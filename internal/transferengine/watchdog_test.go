package transferengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// manualStallClock is a virtual StallClock: time moves only in Advance, which
// runs every due timer on the calling goroutine. No test sleeps or waits on a
// real timer.
type manualStallClock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*manualStallTimer
	fires  int
}

type manualStallTimer struct {
	c      *manualStallClock
	at     time.Duration
	f      func()
	active bool
}

func (c *manualStallClock) AfterFunc(d time.Duration, f func()) StallTimer {
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
func (c *manualStallClock) Advance(d time.Duration) {
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

// armed counts the timers that are still scheduled.
func (c *manualStallClock) armed() int {
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

func (c *manualStallClock) fired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fires
}

func requireDone(t *testing.T, ctx context.Context, want bool) {
	t.Helper()
	if got := ctx.Err() != nil; got != want {
		t.Fatalf("context done = %v, want %v", got, want)
	}
}

func TestWatchdogFiresAtTheLimitAndCancelsTheSession(t *testing.T) {
	clock := &manualStallClock{}
	cfg, err := newStallConfig(clock, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wd, ctx := cfg.start(context.Background())
	clock.Advance(time.Minute - time.Nanosecond)
	requireDone(t, ctx, false)
	clock.Advance(time.Nanosecond)
	requireDone(t, ctx, true)
	if !wd.stop() {
		t.Fatal("stop did not report the stall")
	}
	if !wd.stop() {
		t.Fatal("a second stop changed the verdict")
	}
	if clock.armed() != 0 {
		t.Fatalf("%d timers left armed", clock.armed())
	}
}

func TestWatchdogKickRestartsTheLimit(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, ctx := cfg.start(context.Background())
	for i := 0; i < 50; i++ {
		clock.Advance(time.Minute - time.Nanosecond)
		wd.kick()
	}
	requireDone(t, ctx, false)
	clock.Advance(time.Minute)
	requireDone(t, ctx, true)
	if !wd.stop() {
		t.Fatal("stop did not report the stall")
	}
	if clock.fired() != 1 {
		t.Fatalf("timer fired %d times", clock.fired())
	}
}

func TestWatchdogStopDisarmsAndLateEventsAreIgnored(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, ctx := cfg.start(context.Background())
	clock.Advance(30 * time.Second)
	if wd.stop() {
		t.Fatal("stop before the limit reported a stall")
	}
	// The session context is released by stop; a late kick or an elapsed limit
	// changes nothing.
	requireDone(t, ctx, true)
	wd.kick()
	clock.Advance(time.Hour)
	if wd.stop() {
		t.Fatal("a stopped watchdog reported a stall later")
	}
	if clock.armed() != 0 || clock.fired() != 0 {
		t.Fatalf("armed=%d fired=%d after stop", clock.armed(), clock.fired())
	}
}

func TestWatchdogParentCancelIsNotAStall(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	parent, cancel := context.WithCancel(context.Background())
	wd, ctx := cfg.start(parent)
	cancel()
	requireDone(t, ctx, true)
	if wd.stop() {
		t.Fatal("a cancel of the parent was reported as a stall")
	}
}

func TestWatchdogFireWinsOverALaterParentCancel(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	parent, cancel := context.WithCancel(context.Background())
	wd, _ := cfg.start(parent)
	clock.Advance(time.Minute)
	cancel()
	if !wd.stop() {
		t.Fatal("the stall that came first was lost")
	}
}

func TestStallReaderCountsAskingAndBytes(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, ctx := cfg.start(context.Background())
	r := &stallReader{r: bytes.NewReader(make([]byte, 1000)), w: wd}
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
	if !wd.stop() {
		t.Fatal("a stuck write was not reported as a stall")
	}
}

func TestStallReaderPassesDataAndErrorsThrough(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, _ := cfg.start(context.Background())
	defer wd.stop()
	want := []byte("payload")
	got, err := io.ReadAll(&stallReader{r: bytes.NewReader(want), w: wd})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	boom := errors.New("boom")
	if _, err := (&stallReader{r: errReader{boom}, w: wd}).Read(make([]byte, 4)); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the reader's own", err)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestStallConfigDefaultsAndValidation(t *testing.T) {
	cfg, err := newStallConfig(nil, 0)
	if err != nil || cfg.limit != DefaultStallLimit {
		t.Fatalf("defaults = %+v, %v", cfg, err)
	}
	if DefaultStallLimit != 60*time.Second {
		t.Fatalf("DefaultStallLimit = %s, the spec says 60 s", DefaultStallLimit)
	}
	if _, ok := cfg.clock.(wallStallClock); !ok {
		t.Fatalf("default clock is %T, want the wall clock", cfg.clock)
	}
	if custom, err := newStallConfig(nil, 5*time.Second); err != nil || custom.limit != 5*time.Second {
		t.Fatalf("custom limit = %+v, %v", custom, err)
	}
	if _, err := newStallConfig(nil, -time.Second); err == nil {
		t.Fatal("a negative stall limit was accepted")
	}
	if _, err := NewWithOptions(newFakeChunkRemote(newVClock()), transfercore.DefaultLimits(), Options{StallLimit: -1}); err == nil {
		t.Fatal("NewWithOptions accepted a negative stall limit")
	}
}

func TestWatchdogOnTheWallClockStopsItsTimer(t *testing.T) {
	// A one-hour limit never elapses here: the test only checks that start and
	// stop leave no armed timer and release the context, with no waiting.
	cfg, err := newStallConfig(nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wd, ctx := cfg.start(context.Background())
	wd.kick()
	if wd.stop() {
		t.Fatal("a fresh watchdog reported a stall")
	}
	requireDone(t, ctx, true)
	if wd.timer.Stop() {
		t.Fatal("the wall timer was still armed after stop")
	}
}

func TestStallErrorClassification(t *testing.T) {
	live := &uploadJob{ctx: context.Background()}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	dead := &uploadJob{ctx: gone}
	remoteExit := &transfercore.Error{Class: transfercore.ClassRemoteFailed, Message: "remote operation failed", ExitCode: 24}

	if err := live.stallError(nil, true); err != nil {
		t.Fatalf("nil error became %v", err)
	}
	if err := live.stallError(cancelledError(), true); !transferremote.IsLinkFailure(err) {
		t.Fatalf("stalled cancellation = %v, want a link failure", err)
	}
	if err := live.stallError(context.Canceled, true); !transferremote.IsLinkFailure(err) {
		t.Fatalf("stalled raw cancellation = %v, want a link failure", err)
	}
	if err := live.stallError(cancelledError(), false); transfercore.ClassOf(err) != transfercore.ClassCancelled {
		t.Fatalf("unstalled cancellation = %v, want cancelled", err)
	}
	if err := dead.stallError(cancelledError(), true); transfercore.ClassOf(err) != transfercore.ClassCancelled || transferremote.IsLinkFailure(err) {
		t.Fatalf("manager cancel with a stall = %v, want cancelled", err)
	}
	if err := live.stallError(remoteExit, true); err != remoteExit {
		t.Fatalf("a remote exit status was rewritten to %v", err)
	}
}
