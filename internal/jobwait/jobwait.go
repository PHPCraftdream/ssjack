// Package jobwait holds what the polling tools share when they may block in
// the keeper instead of returning at once (wait_seconds on transfer_status,
// remote_read and app_read): the longest wait, the number of waits that may run
// at the same time, the validation of a requested wait and an injectable expiry
// timer.
package jobwait

import (
	"errors"
	"sync/atomic"
	"time"
)

const (
	// MaxSeconds is the longest wait one call may ask for; a larger request is
	// treated as MaxSeconds. It stays below every deadline on the path (the
	// keeper IPC deadline of a waiting call is MaxSeconds plus a margin).
	MaxSeconds = 25
	// MaxSlots is the number of waits one manager serves at the same time; a
	// call that finds every slot taken is answered at once, as if it asked for
	// no wait.
	MaxSlots = 4
)

// ErrWaitRange is the fixed refusal of a negative wait.
var ErrWaitRange = errors.New("wait_seconds must be between 0 and 25")

// Clamp validates a requested wait in seconds: a negative value is refused,
// a value above MaxSeconds becomes MaxSeconds.
func Clamp(seconds int) (int, error) {
	if seconds < 0 {
		return 0, ErrWaitRange
	}
	return min(seconds, MaxSeconds), nil
}

// Duration is Clamp as a time.Duration.
func Duration(seconds int) (time.Duration, error) {
	clamped, err := Clamp(seconds)
	if err != nil {
		return 0, err
	}
	return time.Duration(clamped) * time.Second, nil
}

// Timer arms one expiry: the channel fires once after d, stop releases it.
// Managers keep one so that tests can fire an expiry without sleeping.
type Timer func(d time.Duration) (<-chan time.Time, func())

// SystemTimer is the Timer backed by the real clock.
func SystemTimer(d time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}

// Gate bounds the waits running at the same time. The zero value is ready.
type Gate struct {
	active atomic.Int32
}

// Acquire takes a slot without blocking and reports whether one was free; a
// true result must be paired with Release.
func (g *Gate) Acquire() bool {
	for {
		n := g.active.Load()
		if n >= MaxSlots {
			return false
		}
		if g.active.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// Release returns a slot taken by Acquire.
func (g *Gate) Release() {
	g.active.Add(-1)
}
