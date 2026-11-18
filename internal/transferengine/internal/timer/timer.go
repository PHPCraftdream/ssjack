// Package timer holds the minimal timer handle the stall watchdog and its test
// clock share, so the watchdog and its fixtures can agree on the type without
// importing each other.
package timer

import "time"

// Timer is the timer handle the watchdog drives. *time.Timer satisfies it.
type Timer interface {
	// Reset re-arms the timer to fire d from now.
	Reset(d time.Duration) bool
	// Stop disarms the timer.
	Stop() bool
}
