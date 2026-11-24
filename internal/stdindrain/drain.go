package stdindrain

import (
	"errors"
	"time"
)

const (
	IdleWindow  = 40 * time.Millisecond
	MaxBytes    = 64 * 1024
	MaxDuration = 2 * time.Second
)

var ErrDrain = errors.New("stdin tail could not be drained")

type PollFunc func(time.Duration) (bool, error)
type ReadFunc func([]byte) (int, error)

// Drain consumes available input synchronously until an idle window passes or
// the overall deadline is reached. Errors or limit exhaustion stop the caller
// from resuming, but do not guarantee that queued input was discarded.
func Drain(idle time.Duration, max int, poll PollFunc, read ReadFunc) error {
	if idle <= 0 || max <= 0 || poll == nil || read == nil {
		return ErrDrain
	}
	buf := make([]byte, 256)
	defer clear(buf)
	deadline := time.Now().Add(MaxDuration)
	consumed := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ErrDrain
		}
		wait := min(idle, remaining)
		ready, err := poll(wait)
		if err != nil {
			return ErrDrain
		}
		if !ready {
			if time.Until(deadline) <= 0 {
				return ErrDrain
			}
			return nil
		}
		if time.Until(deadline) <= 0 {
			return ErrDrain
		}
		n, err := read(buf[:min(len(buf), max-consumed)])
		if err != nil || n <= 0 || n > max-consumed {
			return ErrDrain
		}
		consumed += n
		if consumed == max {
			remaining = time.Until(deadline)
			if remaining <= 0 {
				return ErrDrain
			}
			ready, err = poll(min(idle, remaining))
			if err != nil || ready || time.Until(deadline) <= 0 {
				return ErrDrain
			}
			return nil
		}
	}
}
