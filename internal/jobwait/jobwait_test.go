package jobwait

import (
	"math"
	"testing"
	"time"
)

func TestClampRefusesNegativeAndCapsLarge(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int
		bad  bool
	}{
		{in: 0, want: 0},
		{in: 1, want: 1},
		{in: MaxSeconds, want: MaxSeconds},
		{in: MaxSeconds + 1, want: MaxSeconds},
		{in: 3600, want: MaxSeconds},
		{in: math.MaxInt32, want: MaxSeconds},
		{in: -1, bad: true},
		{in: math.MinInt32, bad: true},
	} {
		got, err := Clamp(tc.in)
		if tc.bad {
			if err != ErrWaitRange {
				t.Fatalf("Clamp(%d) error = %v, want ErrWaitRange", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("Clamp(%d) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
}

func TestDurationMatchesClamp(t *testing.T) {
	d, err := Duration(7)
	if err != nil || d != 7*time.Second {
		t.Fatalf("Duration(7) = %v, %v", d, err)
	}
	d, err = Duration(1000)
	if err != nil || d != MaxSeconds*time.Second {
		t.Fatalf("Duration(1000) = %v, %v", d, err)
	}
	if _, err := Duration(-5); err != ErrWaitRange {
		t.Fatalf("Duration(-5) error = %v", err)
	}
}

func TestGateBoundsSlots(t *testing.T) {
	var g Gate
	for i := 0; i < MaxSlots; i++ {
		if !g.Acquire() {
			t.Fatalf("slot %d was refused", i)
		}
	}
	if g.Acquire() {
		t.Fatal("slot beyond MaxSlots was granted")
	}
	g.Release()
	if !g.Acquire() {
		t.Fatal("released slot was not reusable")
	}
	if g.Acquire() {
		t.Fatal("slot beyond MaxSlots was granted after reuse")
	}
}

func TestSystemTimerFiresAndStops(t *testing.T) {
	c, stop := SystemTimer(time.Millisecond)
	defer stop()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("system timer did not fire")
	}
	_, stopLong := SystemTimer(time.Hour)
	stopLong()
}
