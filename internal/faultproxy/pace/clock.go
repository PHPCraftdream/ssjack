package pace

import (
	"context"
	"sync"
	"time"
)

// Timer is a scheduled callback that can be cancelled.
type Timer interface {
	// Stop prevents the callback from running and reports whether it did.
	Stop() bool
}

// Clock is the time source of duration drops and throttling.
type Clock interface {
	Now() time.Time
	// AfterFunc runs f once, after d has elapsed on this clock, in its own
	// goroutine (RealClock) or inside Advance (ManualClock). f must not block.
	AfterFunc(d time.Duration, f func()) Timer
}

// RealClock is the wall clock (monotonic). It is the default.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time { return time.Now() }

// AfterFunc wraps time.AfterFunc.
func (RealClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// ManualClock is a Clock that only moves when Advance is called, so duration
// and throttle behaviour can be tested exactly and without sleeping.
type ManualClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*manualTimer
	changed chan struct{}
}

type manualTimer struct {
	clock *ManualClock
	at    time.Time
	f     func()
}

// NewManualClock returns a clock standing at start (a fixed epoch when zero).
func NewManualClock(start time.Time) *ManualClock {
	if start.IsZero() {
		start = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	}
	return &ManualClock{now: start, changed: make(chan struct{})}
}

// Now returns the manual time.
func (m *ManualClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

// AfterFunc schedules f at Now()+d. A timer that is already due (d <= 0)
// fires on the next Advance call, including Advance(0).
func (m *ManualClock) AfterFunc(d time.Duration, f func()) Timer {
	m.mu.Lock()
	defer m.mu.Unlock()
	timer := &manualTimer{clock: m, at: m.now.Add(d), f: f}
	m.timers = append(m.timers, timer)
	m.broadcastLocked()
	return timer
}

func (m *ManualClock) broadcastLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

// Stop cancels the timer.
func (t *manualTimer) Stop() bool {
	m := t.clock
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, pending := range m.timers {
		if pending == t {
			m.timers = append(m.timers[:i], m.timers[i+1:]...)
			m.broadcastLocked()
			return true
		}
	}
	return false
}

// Advance moves time forward by d, running every timer that becomes due in
// deadline order. Each callback sees the clock standing at its own deadline;
// callbacks run on the calling goroutine.
func (m *ManualClock) Advance(d time.Duration) {
	m.mu.Lock()
	target := m.now.Add(d)
	m.mu.Unlock()
	for {
		m.mu.Lock()
		next := -1
		for i, timer := range m.timers {
			if timer.at.After(target) {
				continue
			}
			if next < 0 || timer.at.Before(m.timers[next].at) {
				next = i
			}
		}
		if next < 0 {
			if target.After(m.now) {
				m.now = target
			}
			m.mu.Unlock()
			return
		}
		timer := m.timers[next]
		m.timers = append(m.timers[:next], m.timers[next+1:]...)
		if timer.at.After(m.now) {
			m.now = timer.at
		}
		m.broadcastLocked()
		m.mu.Unlock()
		timer.f()
	}
}

// Pending returns the number of scheduled, not yet fired timers.
func (m *ManualClock) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.timers)
}

// WaitPending blocks until at least n timers are scheduled. A proxy that is
// waiting for the clock (a drop timer, or a throttle waiting for tokens) has
// a timer pending, so this is how a test knows the proxy reached that state.
func (m *ManualClock) WaitPending(ctx context.Context, n int) error {
	for {
		m.mu.Lock()
		ready := len(m.timers) >= n
		changed := m.changed
		m.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
