package pace

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// testBudget bounds every wait in these tests; it is a hang detector.
const testBudget = 30 * time.Second

func TestManualClockRunsDueTimersInDeadlineOrder(t *testing.T) {
	start := time.Date(2030, time.March, 1, 12, 0, 0, 0, time.UTC)
	clock := NewManualClock(start)
	var order []string
	var seenAt []time.Duration
	note := func(name string) func() {
		return func() {
			order = append(order, name)
			seenAt = append(seenAt, clock.Now().Sub(start))
		}
	}
	clock.AfterFunc(2*time.Second, note("two"))
	clock.AfterFunc(time.Second, func() {
		note("one")()
		// A timer set from a callback is relative to the callback's time.
		clock.AfterFunc(time.Second, note("one+1"))
	})
	cancelled := clock.AfterFunc(1500*time.Millisecond, note("cancelled"))
	late := clock.AfterFunc(time.Hour, note("late"))
	if clock.Pending() != 4 {
		t.Fatalf("pending = %d, want 4", clock.Pending())
	}
	if !cancelled.Stop() || cancelled.Stop() {
		t.Fatal("Stop must report true once, then false")
	}
	clock.Advance(3 * time.Second)
	// Timers due at the same instant fire in the order they were scheduled.
	if want := []string{"one", "two", "one+1"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("fire order = %v, want %v", order, want)
	}
	// The clock stood at each deadline while its callback ran.
	if want := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second}; !reflect.DeepEqual(seenAt, want) {
		t.Fatalf("callbacks saw the clock at %v, want %v", seenAt, want)
	}
	if got := clock.Now().Sub(start); got != 3*time.Second {
		t.Fatalf("now = start+%s, want start+3s", got)
	}
	if clock.Pending() != 1 || !late.Stop() || clock.Pending() != 0 {
		t.Fatal("the hour timer should still have been pending")
	}
	var fired bool
	clock.AfterFunc(0, func() { fired = true })
	if fired {
		t.Fatal("an already-due timer must wait for Advance")
	}
	clock.Advance(0)
	if !fired {
		t.Fatal("Advance(0) did not run the already-due timer")
	}
}

func TestManualClockWaitPending(t *testing.T) {
	clock := NewManualClock(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), testBudget)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- clock.WaitPending(ctx, 2) }()
	clock.AfterFunc(time.Hour, func() {})
	clock.AfterFunc(time.Hour, func() {})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := clock.WaitPending(cancelled, 3); err == nil {
		t.Fatal("WaitPending ignored its context")
	}
}

func TestRealClockMovesForward(t *testing.T) {
	var clock Clock = RealClock{}
	before := clock.Now()
	fired := make(chan struct{})
	timer := clock.AfterFunc(time.Millisecond, func() { close(fired) })
	select {
	case <-fired:
	case <-time.After(testBudget):
		t.Fatal("real timer never fired")
	}
	if timer.Stop() {
		t.Fatal("Stop reported success on a fired timer")
	}
	if !clock.Now().After(before) {
		t.Fatal("clock did not advance")
	}
}
