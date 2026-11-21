package flakediag

import (
	"fmt"
	"testing"
	"time"
)

// Probe reports a description of the current state and whether the waited-for
// condition has been met. desc may be empty; it is only rendered as evidence.
type Probe func() (desc string, done bool)

// WaitFor polls probe every 5ms (the interval of the helpers it replaced) until
// done or timeout. It never fails the test on timeout; the caller decides.
// Failure-only evidence (what, timeout, elapsed, attempts, last description,
// goroutine dump) is registered via t.Cleanup and printed only if the test
// subsequently fails.
func WaitFor(t *testing.T, what string, timeout time.Duration, probe Probe) (lastDesc string) {
	done, lastDesc, _ := waitForAll(t, what, timeout, func() (string, bool, error) {
		desc, ok := probe()
		return desc, ok, nil
	})
	_ = done
	return lastDesc
}

// WaitForDesc is like WaitFor but the probe may also return an error, which is
// included in the evidence. It returns whether the probe reported done, the
// last description, and the last error seen.
func WaitForDesc(t *testing.T, what string, timeout time.Duration, probe func() (desc string, done bool, err error)) (done bool, lastDesc string, lastErr error) {
	return waitForAll(t, what, timeout, probe)
}

// waitForAll implements both variants; probe returns (desc, done, err).
func waitForAll(t *testing.T, what string, timeout time.Duration, probe func() (string, bool, error)) (bool, string, error) {
	deadline := time.Now().Add(timeout)
	attempts := 0
	var lastDesc string
	var lastErr error
	start := time.Now()
	for {
		attempts++
		desc, done, err := probe()
		if desc != "" {
			lastDesc = desc
		}
		if err != nil {
			lastErr = err
		}
		if done {
			return true, lastDesc, lastErr
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	elapsed := time.Since(start)
	render := func() string {
		return fmt.Sprintf(
			"waited for: %s\ntimeout: %s\nelapsed: %s\nattempts: %d\nlast description: %s\nlast error: %v\ngoroutine dump:\n%s",
			what, timeout, elapsed, attempts, lastDesc, lastErr, GoroutineDump(64*1024),
		)
	}
	onFailureSince(t, start, render)
	return false, lastDesc, lastErr
}
