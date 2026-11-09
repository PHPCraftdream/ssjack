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

func (c *Capture) Wait(ctx context.Context, text string) error {
	for {
		c.mu.Lock()
		found, overflow := bytes.Contains(c.data, []byte(text)), c.overflow
		c.mu.Unlock()
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
			c.mu.Lock()
			found, overflow := bytes.Contains(c.data, []byte(text)), c.overflow
			c.mu.Unlock()
			if found && !overflow {
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
