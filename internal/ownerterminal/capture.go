package ownerterminal

import (
	"bytes"
	"context"
	"io"
	"sync"
)

type Capture struct {
	mu       sync.Mutex
	data     []byte
	total    int
	overflow bool
	changed  chan struct{}
	done     chan struct{}
}

func CaptureOutput(output io.Reader) *Capture {
	capture := &Capture{changed: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(capture.done)
		buffer := make([]byte, 4096)
		defer clear(buffer)
		for {
			n, err := output.Read(buffer)
			capture.mu.Lock()
			capture.total += n
			if len(capture.data)+n <= 64<<10 && !capture.overflow {
				capture.data = append(capture.data, buffer[:n]...)
			} else {
				capture.overflow = true
			}
			capture.mu.Unlock()
			select {
			case capture.changed <- struct{}{}:
			default:
			}
			if err != nil {
				return
			}
		}
	}()
	return capture
}

func (c *Capture) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}

// Inspect calls inspect with c.mu held, passing the retained data, the total
// bytes read (including bytes not retained), and whether capture overflowed.
// inspect must not mutate or retain the data or re-enter Capture.
func (c *Capture) Inspect(inspect func(data []byte, total int, overflow bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	inspect(c.data, c.total, c.overflow)
}

func (c *Capture) Wait(ctx context.Context, text string) error {
	return c.WaitFor(ctx, func(data []byte) bool {
		return bytes.Contains(data, []byte(text))
	})
}

// WaitFor calls match with c.mu held and only when capture has not overflowed.
// match must not mutate or retain the data or re-enter Capture.
func (c *Capture) WaitFor(ctx context.Context, match func([]byte) bool) error {
	check := func() (found, overflow bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.overflow {
			return false, true
		}
		return match(c.data), false
	}
	for {
		found, overflow := check()
		if overflow {
			return ErrTerminal
		}
		if found {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			found, _ := check()
			if found {
				return nil
			}
			return ErrTerminal
		case <-c.changed:
		}
	}
}

func (c *Capture) Join(ctx context.Context) error {
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.overflow {
			return ErrTerminal
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Capture) Contains(value []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.data, value)
}

func (c *Capture) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.data)
}
