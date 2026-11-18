package testfixture

import (
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/timer"
)

// ManualStallClock is a virtual watchdog StallClock: time moves only in
// Advance, which runs every due timer on the calling goroutine. No test sleeps
// or waits on a real timer.
type ManualStallClock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*manualStallTimer
	fires  int
}

type manualStallTimer struct {
	c      *ManualStallClock
	at     time.Duration
	f      func()
	active bool
}

func (c *ManualStallClock) AfterFunc(d time.Duration, f func()) timer.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &manualStallTimer{c: c, at: c.now + d, f: f, active: true}
	c.timers = append(c.timers, t)
	return t
}

func (t *manualStallTimer) Reset(d time.Duration) bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.active, t.at = true, t.c.now+d
	return was
}

func (t *manualStallTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.active = false
	return was
}

// Advance moves time forward by d, firing due timers in deadline order. A
// callback sees the clock at its own deadline and runs without the clock lock.
func (c *ManualStallClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now + d
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *manualStallTimer
		for _, t := range c.timers {
			if t.active && t.at <= target && (next == nil || t.at < next.at) {
				next = t
			}
		}
		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		next.active = false
		if next.at > c.now {
			c.now = next.at
		}
		c.fires++
		f := next.f
		c.mu.Unlock()
		f()
	}
}

// Armed counts the timers that are still scheduled.
func (c *ManualStallClock) Armed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.active {
			n++
		}
	}
	return n
}

// Fired counts how many timer callbacks have run.
func (c *ManualStallClock) Fired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fires
}
