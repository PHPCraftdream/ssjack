package watchdog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
)

func requireDone(t *testing.T, ctx context.Context, want bool) {
	t.Helper()
	if got := ctx.Err() != nil; got != want {
		t.Fatalf("context done = %v, want %v", got, want)
	}
}

func TestWatchdogFiresAtTheLimitAndCancelsTheSession(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, err := NewConfig(clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wd, ctx := cfg.Start(context.Background())
	clock.Advance(time.Minute - time.Nanosecond)
	requireDone(t, ctx, false)
	clock.Advance(time.Nanosecond)
	requireDone(t, ctx, true)
	if !wd.Stop() {
		t.Fatal("stop did not report the stall")
	}
	if !wd.Stop() {
		t.Fatal("a second stop changed the verdict")
	}
	if clock.Armed() != 0 {
		t.Fatalf("%d timers left armed", clock.Armed())
	}
}

func TestWatchdogKickRestartsTheLimit(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, ctx := cfg.Start(context.Background())
	for i := 0; i < 50; i++ {
		clock.Advance(time.Minute - time.Nanosecond)
		wd.kick()
	}
	requireDone(t, ctx, false)
	clock.Advance(time.Minute)
	requireDone(t, ctx, true)
	if !wd.Stop() {
		t.Fatal("stop did not report the stall")
	}
	if clock.Fired() != 1 {
		t.Fatalf("timer fired %d times", clock.Fired())
	}
}

func TestWatchdogStopDisarmsAndLateEventsAreIgnored(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, ctx := cfg.Start(context.Background())
	clock.Advance(30 * time.Second)
	if wd.Stop() {
		t.Fatal("stop before the limit reported a stall")
	}
	// The session context is released by stop; a late kick or an elapsed limit
	// changes nothing.
	requireDone(t, ctx, true)
	wd.kick()
	clock.Advance(time.Hour)
	if wd.Stop() {
		t.Fatal("a stopped watchdog reported a stall later")
	}
	if clock.Armed() != 0 || clock.Fired() != 0 {
		t.Fatalf("armed=%d fired=%d after stop", clock.Armed(), clock.Fired())
	}
}

func TestWatchdogParentCancelIsNotAStall(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	parent, cancel := context.WithCancel(context.Background())
	wd, ctx := cfg.Start(parent)
	cancel()
	requireDone(t, ctx, true)
	if wd.Stop() {
		t.Fatal("a cancel of the parent was reported as a stall")
	}
}

func TestWatchdogFireWinsOverALaterParentCancel(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	parent, cancel := context.WithCancel(context.Background())
	wd, _ := cfg.Start(parent)
	clock.Advance(time.Minute)
	cancel()
	if !wd.Stop() {
		t.Fatal("the stall that came first was lost")
	}
}

func TestStallReaderCountsAskingAndBytes(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, ctx := cfg.Start(context.Background())
	r := wd.Reader(bytes.NewReader(make([]byte, 1000)))
	buf := make([]byte, 100)
	// A slow but moving link: every buffer takes just under the limit.
	for i := 0; i < 10; i++ {
		clock.Advance(time.Minute - time.Nanosecond)
		if n, err := r.Read(buf); n != len(buf) || err != nil {
			t.Fatalf("read %d = %d, %v", i, n, err)
		}
	}
	requireDone(t, ctx, false)
	// The next write never completes: no further read is asked for.
	clock.Advance(time.Minute)
	requireDone(t, ctx, true)
	if !wd.Stop() {
		t.Fatal("a stuck write was not reported as a stall")
	}
}

func TestStallReaderPassesDataAndErrorsThrough(t *testing.T) {
	clock := &testfixture.ManualStallClock{}
	cfg, _ := NewConfig(clock, time.Minute)
	wd, _ := cfg.Start(context.Background())
	defer wd.Stop()
	want := []byte("payload")
	got, err := io.ReadAll(wd.Reader(bytes.NewReader(want)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	boom := errors.New("boom")
	if _, err := wd.Reader(errReader{boom}).Read(make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the reader's own", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestStallConfigDefaultsAndValidation(t *testing.T) {
	cfg, err := NewConfig(nil, 0)
	if err != nil || cfg.limit != DefaultStallLimit {
		t.Fatalf("defaults = %+v, %v", cfg, err)
	}
	if DefaultStallLimit != 60*time.Second {
		t.Fatalf("DefaultStallLimit = %s, the spec says 60 s", DefaultStallLimit)
	}
	if _, ok := cfg.clock.(wallStallClock); !ok {
		t.Fatalf("default clock is %T, want the wall clock", cfg.clock)
	}
	if custom, err := NewConfig(nil, 5*time.Second); err != nil || custom.limit != 5*time.Second {
		t.Fatalf("custom limit = %+v, %v", custom, err)
	}
	if _, err := NewConfig(nil, -time.Second); err == nil {
		t.Fatal("a negative stall limit was accepted")
	}
}

func TestWatchdogOnTheWallClockStopsItsTimer(t *testing.T) {
	// A one-hour limit never elapses here: the test only checks that start and
	// stop leave no armed timer and release the context, with no waiting.
	cfg, err := NewConfig(nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wd, ctx := cfg.Start(context.Background())
	wd.kick()
	if wd.Stop() {
		t.Fatal("a fresh watchdog reported a stall")
	}
	requireDone(t, ctx, true)
	if wd.timer.Stop() {
		t.Fatal("the wall timer was still armed after stop")
	}
}
