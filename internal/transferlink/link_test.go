package transferlink

import (
	"math"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manual clock; it is only read under the profile lock.
type fakeClock struct{ t time.Time }

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestProfile(c *fakeClock) *Profile {
	return NewProfile(Config{Now: c.Now, Window: time.Minute})
}

func approx(a, b, eps float64) bool { return math.Abs(a-b) <= eps }

const (
	mb = int64(1_000_000)
	// bps1M is the speed 1 MB in 1 s feeds into the EWMA.
	bps1M = mb
)

// speedProfile returns a profile whose speed EWMA is exactly bytesPerSec.
func speedProfile(c *fakeClock, bytesPerSec int64) *Profile {
	p := newTestProfile(c)
	p.StreamProgress(bytesPerSec, time.Second)
	return p
}

func TestUseChunks(t *testing.T) {
	tests := []struct {
		name  string
		speed int64 // 0 = unknown
		drops []time.Duration
		size  int64
		want  bool
	}{
		{"no drop known", bps1M, nil, 1 << 40, false},
		{"drop but speed unknown", 0, []time.Duration{10 * time.Second}, 1 << 40, false},
		{"fits in survival time", bps1M, []time.Duration{10 * time.Second}, 5 * mb, false},
		{"exactly survival time", bps1M, []time.Duration{10 * time.Second}, 10 * mb, false},
		{"just above survival time", bps1M, []time.Duration{10 * time.Second}, 10*mb + 1, true},
		{"min over drops decides", bps1M, []time.Duration{30 * time.Second, 5 * time.Second, 20 * time.Second}, 6 * mb, true},
		{"min over drops fits", bps1M, []time.Duration{30 * time.Second, 5 * time.Second, 20 * time.Second}, 4 * mb, false},
		{"zero size", bps1M, []time.Duration{time.Second}, 0, false},
		{"negative size", bps1M, []time.Duration{time.Second}, -5, false},
		{"zero lifetime drop", bps1M, []time.Duration{0}, 1, true},
		{"negative lifetime treated as zero", bps1M, []time.Duration{-time.Second}, 1, true},
		{"huge size slow link", 1, []time.Duration{time.Hour}, math.MaxInt64, true},
		{"huge size fast link", int64(maxSpeed), []time.Duration{time.Hour}, math.MaxInt64, true},
		{"tiny size huge survival", bps1M, []time.Duration{24 * time.Hour}, 1000, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newClock()
			p := newTestProfile(c)
			if tc.speed > 0 {
				p.StreamProgress(tc.speed, time.Second)
			}
			for _, life := range tc.drops {
				p.Dropped(0, life, FailLink)
			}
			if got := p.UseChunks(tc.size); got != tc.want {
				t.Fatalf("UseChunks(%d) = %v, want %v", tc.size, got, tc.want)
			}
		})
	}
}

func TestNextChunkFormula(t *testing.T) {
	tests := []struct {
		name      string
		speed     int64 // 0 = unknown
		drops     []time.Duration
		setup     time.Duration
		stored    int64 // 0 = not seeded
		remaining int64
		want      int64
	}{
		{"half of speed times survival", bps1M, []time.Duration{10 * time.Second}, 0, 0, math.MaxInt64, 5 * mb},
		{"clamped to remaining", bps1M, []time.Duration{10 * time.Second}, 0, 0, mb, mb},
		{"remaining below floor", bps1M, []time.Duration{10 * time.Second}, 0, 0, 100, 100},
		{"remaining one", bps1M, []time.Duration{10 * time.Second}, 0, 0, 1, 1},
		{"remaining zero", bps1M, []time.Duration{10 * time.Second}, 0, 0, 0, 0},
		{"remaining negative", bps1M, []time.Duration{10 * time.Second}, 0, 0, -7, 0},
		{"floor wins over tiny bound", 1000, []time.Duration{10 * time.Second}, 0, 0, math.MaxInt64, MinChunk},
		{"cap at MaxChunk", 1_000_000_000, []time.Duration{100 * time.Second}, 0, 0, math.MaxInt64, MaxChunk},
		{"survivability beats overhead floor", bps1M, []time.Duration{10 * time.Second}, time.Second, 0, math.MaxInt64, 5 * mb},
		{"overhead floor lifts small stored", bps1M, []time.Duration{100 * time.Second}, 250 * time.Millisecond, MinChunk, math.MaxInt64, 5 * mb},
		{"stored above overhead floor kept", bps1M, []time.Duration{100 * time.Second}, 250 * time.Millisecond, 8 * mb, math.MaxInt64, 8 * mb},
		{"stored above bound is cut", bps1M, []time.Duration{100 * time.Second}, 0, 60 * mb, math.MaxInt64, 50 * mb},
		{"min lifetime of several drops", bps1M, []time.Duration{30 * time.Second, 10 * time.Second, 20 * time.Second}, 0, 0, math.MaxInt64, 5 * mb},
		{"speed unknown but drop known", 0, []time.Duration{10 * time.Second}, 0, 0, math.MaxInt64, MinChunk},
		{"nothing known", 0, nil, 0, 0, math.MaxInt64, MaxChunk},
		{"no drop known keeps stored", bps1M, nil, 0, 3 * mb, math.MaxInt64, 3 * mb},
		{"no drop known nothing stored", bps1M, nil, 0, 0, math.MaxInt64, MaxChunk},
		{"zero lifetime drop", bps1M, []time.Duration{0}, 0, 0, math.MaxInt64, MinChunk},
		{"remaining near int64 max", bps1M, []time.Duration{10 * time.Second}, 0, 0, math.MaxInt64 - 1, 5 * mb},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newClock()
			p := newTestProfile(c)
			if tc.speed > 0 {
				p.StreamProgress(tc.speed, time.Second)
			}
			for _, life := range tc.drops {
				p.Dropped(0, life, FailLink)
			}
			if tc.setup > 0 {
				p.ConnectionSetup(tc.setup)
			}
			p.chunk = tc.stored
			if got := p.NextChunk(tc.remaining); got != tc.want {
				t.Fatalf("NextChunk(%d) = %d, want %d", tc.remaining, got, tc.want)
			}
		})
	}
}

func TestNextChunkExtremeInputsStayInRange(t *testing.T) {
	c := newClock()
	p := newTestProfile(c)
	p.StreamProgress(math.MaxInt64, time.Nanosecond)
	p.ConnectionSetup(time.Duration(math.MaxInt64))
	p.Dropped(math.MaxInt64, time.Duration(math.MaxInt64), FailLink)
	for _, rem := range []int64{1, MinChunk - 1, MinChunk, MaxChunk, MaxChunk + 1, math.MaxInt64} {
		got := p.NextChunk(rem)
		if got <= 0 || got > rem || got > MaxChunk {
			t.Fatalf("NextChunk(%d) = %d out of range", rem, got)
		}
	}
	if got := p.NextChunk(math.MaxInt64); got != MaxChunk {
		t.Fatalf("NextChunk(max) = %d, want %d", got, MaxChunk)
	}
}

func TestThroughputEWMAAndGuards(t *testing.T) {
	c := newClock()
	p := newTestProfile(c)
	p.StreamProgress(0, time.Second)
	p.StreamProgress(10, 0)
	p.StreamProgress(-5, time.Second)
	p.StreamProgress(10, -time.Second)
	if s := p.Snapshot().Speed; s != 0 {
		t.Fatalf("invalid samples changed speed: %v", s)
	}
	p.StreamProgress(1_000_000, time.Second)
	if s := p.Snapshot().Speed; s != 1e6 {
		t.Fatalf("first sample seeds speed, got %v", s)
	}
	p.StreamProgress(2_000_000, time.Second)
	if s := p.Snapshot().Speed; !approx(s, 1.3e6, 1) {
		t.Fatalf("EWMA = %v, want 1.3e6", s)
	}
	p.StreamProgress(math.MaxInt64, time.Nanosecond)
	if s := p.Snapshot().Speed; s > maxSpeed || math.IsInf(s, 0) || math.IsNaN(s) {
		t.Fatalf("speed not bounded: %v", s)
	}
}

func TestSetupEWMA(t *testing.T) {
	c := newClock()
	p := newTestProfile(c)
	p.ConnectionSetup(0)
	p.ConnectionSetup(-time.Second)
	if s := p.Snapshot().Setup; s != 0 {
		t.Fatalf("invalid setup changed profile: %v", s)
	}
	p.ConnectionSetup(time.Second)
	if s := p.Snapshot().Setup; s != time.Second {
		t.Fatalf("first setup = %v", s)
	}
	p.ConnectionSetup(2 * time.Second)
	got := p.Snapshot().Setup.Seconds()
	if !approx(got, 1.3, 1e-6) {
		t.Fatalf("setup EWMA = %v, want 1.3", got)
	}
}

// enterChunked builds a chunked-mode profile: speed 1 MB/s, one drop of 10 s,
// so the survival bound is 5 MB.
func enterChunked(t *testing.T, c *fakeClock) *Profile {
	t.Helper()
	p := speedProfile(c, bps1M)
	p.Dropped(1000, 10*time.Second, FailLink) // stream bytes: counts as progress
	step := p.Decide(100 * mb)
	if step.Mode != ModeChunked || step.Len != 5*mb {
		t.Fatalf("Decide = %+v, want chunked 5 MB", step)
	}
	return p
}

func TestAIMDHalvesOnDropAndStopsAtFloor(t *testing.T) {
	c := newClock()
	p := enterChunked(t, c)
	p.Dropped(0, 8*time.Second, FailLink) // stored 5 MB -> 2.5 MB; bound 4 MB
	if got := p.NextChunk(math.MaxInt64); got != 2_500_000 {
		t.Fatalf("after first drop NextChunk = %d, want 2500000", got)
	}
	p.Dropped(0, 8*time.Second, FailLink)
	if got := p.NextChunk(math.MaxInt64); got != 1_250_000 {
		t.Fatalf("after second drop NextChunk = %d, want 1250000", got)
	}
	for i := 0; i < 40; i++ {
		p.Dropped(0, 8*time.Second, FailLink)
		if got := p.NextChunk(math.MaxInt64); got < MinChunk {
			t.Fatalf("chunk collapsed below floor: %d", got)
		}
	}
	if got := p.NextChunk(math.MaxInt64); got != MinChunk {
		t.Fatalf("chunk = %d, want floor %d", got, MinChunk)
	}
	if s := p.Snapshot().Stored; s != MinChunk {
		t.Fatalf("stored = %d, want %d", s, MinChunk)
	}
}

func TestAIMDGrowsAfterFourSuccessesCappedByBound(t *testing.T) {
	c := newClock()
	p := enterChunked(t, c)
	p.Dropped(0, 8*time.Second, FailLink) // stored 2.5 MB, bound 4 MB
	for i := 0; i < GrowAfter-1; i++ {
		p.ChunkDone(2_500_000, 2500*time.Millisecond)
	}
	if got := p.NextChunk(math.MaxInt64); got != 2_500_000 {
		t.Fatalf("grew before %d successes: %d", GrowAfter, got)
	}
	p.ChunkDone(2_500_000, 2500*time.Millisecond)
	if got := p.NextChunk(math.MaxInt64); got != 3_750_000 {
		t.Fatalf("after %d successes NextChunk = %d, want 3750000", GrowAfter, got)
	}
	for i := 0; i < GrowAfter; i++ {
		p.ChunkDone(3_750_000, 3750*time.Millisecond)
	}
	if got := p.NextChunk(math.MaxInt64); got != 4*mb {
		t.Fatalf("growth must stop at the survival bound: %d", got)
	}
	if s := p.Snapshot().Stored; s > 6*mb {
		t.Fatalf("stored size ran away from the bound: %d", s)
	}
}

func TestAIMDGrowthCapsAtMaxChunk(t *testing.T) {
	c := newClock()
	p := speedProfile(c, 1_000_000_000)
	p.Dropped(0, 100*time.Second, FailLink)
	step := p.Decide(1 << 40)
	if step.Mode != ModeChunked || step.Len != MaxChunk {
		t.Fatalf("Decide = %+v", step)
	}
	p.chunk = MaxChunk - 1
	for i := 0; i < 4*GrowAfter; i++ {
		p.ChunkDone(MaxChunk, 67*time.Millisecond)
		if s := p.Snapshot().Stored; s > MaxChunk {
			t.Fatalf("stored %d above MaxChunk", s)
		}
	}
	if got := p.NextChunk(math.MaxInt64); got != MaxChunk {
		t.Fatalf("NextChunk = %d", got)
	}
}

func TestDropBreaksSuccessStreak(t *testing.T) {
	c := newClock()
	p := enterChunked(t, c)
	for i := 0; i < GrowAfter-1; i++ {
		p.ChunkDone(5*mb, 5*time.Second)
	}
	p.Dropped(0, 10*time.Second, FailLink) // stored 5 MB -> 2.5 MB, streak reset
	for i := 0; i < GrowAfter-1; i++ {
		p.ChunkDone(2_500_000, 2500*time.Millisecond)
	}
	if got := p.NextChunk(math.MaxInt64); got != 2_500_000 {
		t.Fatalf("streak survived a drop: NextChunk = %d", got)
	}
}

func TestDecideModes(t *testing.T) {
	t.Run("fresh profile streams", func(t *testing.T) {
		p := newTestProfile(newClock())
		if st := p.Decide(100); st.Mode != ModeStream || st.Len != 100 {
			t.Fatalf("Decide = %+v", st)
		}
	})
	t.Run("nothing remaining", func(t *testing.T) {
		p := enterChunked(t, newClock())
		if st := p.Decide(0); st.Len != 0 {
			t.Fatalf("Decide(0) = %+v", st)
		}
		if st := p.Decide(-1); st.Len != 0 {
			t.Fatalf("Decide(-1) = %+v", st)
		}
	})
	t.Run("drop but transfer fits survival", func(t *testing.T) {
		p := speedProfile(newClock(), bps1M)
		p.Dropped(0, 10*time.Second, FailLink)
		if st := p.Decide(5 * mb); st.Mode != ModeStream || st.Len != 5*mb {
			t.Fatalf("Decide = %+v", st)
		}
	})
	t.Run("tiny file stays stream even after a drop", func(t *testing.T) {
		p := speedProfile(newClock(), 10)
		p.Dropped(0, time.Second, FailLink)
		if st := p.Decide(MinChunk - 1); st.Mode != ModeStream {
			t.Fatalf("Decide = %+v", st)
		}
		if p.Mode() != ModeStream {
			t.Fatal("mode switched for a file below the chunk floor")
		}
	})
	t.Run("rule 4a: chunk reaches remaining", func(t *testing.T) {
		p := enterChunked(t, newClock())
		if st := p.Decide(5*mb + 1); st.Mode != ModeChunked || st.Len != 5*mb {
			t.Fatalf("Decide(5MB+1) = %+v", st)
		}
		if st := p.Decide(5 * mb); st.Mode != ModeStream || st.Len != 5*mb {
			t.Fatalf("Decide(5MB) = %+v", st)
		}
		if p.Mode() != ModeStream {
			t.Fatal("mode not stored as stream")
		}
	})
	t.Run("rule 4b: speed doubled and no drop in window", func(t *testing.T) {
		c := newClock()
		p := enterChunked(t, c)
		p.ChunkDone(5*mb, time.Second) // EWMA 1e6 -> 2.2e6
		if st := p.Decide(100 * mb); st.Mode != ModeChunked {
			t.Fatalf("returned to stream with a drop in the window: %+v", st)
		}
		c.Advance(time.Minute + time.Second)
		st := p.Decide(100 * mb)
		if st.Mode != ModeStream || st.Len != 100*mb {
			t.Fatalf("Decide after window = %+v, want stream", st)
		}
	})
	t.Run("rule 4b: not doubled stays chunked", func(t *testing.T) {
		c := newClock()
		p := enterChunked(t, c)
		p.ChunkDone(3*mb, time.Second) // EWMA 1e6 -> 1.6e6
		c.Advance(time.Minute + time.Second)
		st := p.Decide(100 * mb)
		if st.Mode != ModeChunked || st.Len != 5*mb {
			t.Fatalf("Decide = %+v, want chunked with the stored size", st)
		}
	})
	t.Run("rule 4b: drop in window blocks return", func(t *testing.T) {
		c := newClock()
		p := enterChunked(t, c)
		p.ChunkDone(50*mb, time.Second)
		c.Advance(40 * time.Second)
		if st := p.Decide(100 * mb); st.Mode != ModeChunked {
			t.Fatalf("Decide = %+v", st)
		}
	})
	t.Run("new transfer after Succeeded decides afresh", func(t *testing.T) {
		c := newClock()
		p := enterChunked(t, c)
		p.Succeeded()
		if p.Mode() != ModeStream {
			t.Fatal("Succeeded must reset the mode")
		}
		if st := p.Decide(2 * mb); st.Mode != ModeStream {
			t.Fatalf("small transfer: %+v", st)
		}
		if st := p.Decide(100 * mb); st.Mode != ModeChunked || st.Len != 5*mb {
			t.Fatalf("big transfer on a known-bad link: %+v", st)
		}
	})
	t.Run("drops forgotten after window: new transfer streams", func(t *testing.T) {
		c := newClock()
		p := enterChunked(t, c)
		p.Succeeded()
		c.Advance(2 * time.Minute)
		if st := p.Decide(100 * mb); st.Mode != ModeStream {
			t.Fatalf("Decide = %+v", st)
		}
	})
}

func TestDropWindowDecay(t *testing.T) {
	c := newClock()
	p := newTestProfile(c) // window 1 min
	p.Dropped(0, 10*time.Second, FailLink)
	c.Advance(30 * time.Second)
	p.Dropped(0, 40*time.Second, FailLink)
	if s := p.Snapshot(); !s.SurviveKnown || s.Survive != 10*time.Second || s.Drops != 2 {
		t.Fatalf("snapshot = %+v", s)
	}
	c.Advance(40 * time.Second) // first drop is 70 s old, second 40 s
	if s := p.Snapshot(); s.Survive != 40*time.Second || s.Drops != 1 {
		t.Fatalf("old drop not forgotten: %+v", s)
	}
	c.Advance(100 * time.Second)
	s := p.Snapshot()
	if s.SurviveKnown || s.Drops != 0 {
		t.Fatalf("all drops must be forgotten: %+v", s)
	}
	p.StreamProgress(mb, time.Second)
	if p.UseChunks(1 << 40) {
		t.Fatal("UseChunks true without a known drop")
	}
}

func TestDropWindowBoundaryIsInclusive(t *testing.T) {
	c := newClock()
	p := newTestProfile(c)
	p.Dropped(0, time.Second, FailLink)
	c.Advance(time.Minute)
	if s := p.Snapshot(); s.Drops != 1 {
		t.Fatalf("drop exactly window old must stay: %+v", s)
	}
	c.Advance(time.Nanosecond)
	if s := p.Snapshot(); s.Drops != 0 {
		t.Fatalf("drop older than window must go: %+v", s)
	}
}

func TestDropHistoryIsBounded(t *testing.T) {
	c := newClock()
	p := NewProfile(Config{Now: c.Now, Window: time.Hour})
	p.Dropped(0, time.Second, FailLink) // smallest, oldest
	for i := 0; i < maxDrops; i++ {
		p.Dropped(0, 100*time.Second, FailLink)
	}
	s := p.Snapshot()
	if s.Drops != maxDrops {
		t.Fatalf("drops = %d, want %d", s.Drops, maxDrops)
	}
	if s.Survive != 100*time.Second {
		t.Fatalf("evicted drop still counts: %v", s.Survive)
	}
}

func TestOnlyLinkFailuresAffectProfile(t *testing.T) {
	c := newClock()
	p := enterChunked(t, c)
	before := p.Snapshot()
	for _, k := range []FailureKind{FailUnknown, FailCancelled, FailRefused, FailIntegrity, FailLimit, FailureKind(99), FailureKind(-1)} {
		for i := 0; i < 20; i++ {
			p.Dropped(123, 5*time.Second, k)
		}
		if after := p.Snapshot(); after != before {
			t.Fatalf("kind %d changed the profile:\nbefore %+v\nafter  %+v", k, before, after)
		}
		if p.GiveUp() {
			t.Fatalf("kind %d fed GiveUp", k)
		}
	}
	p.Dropped(123, 5*time.Second, FailLink)
	if after := p.Snapshot(); after == before {
		t.Fatal("FailLink did not change the profile")
	}
}

func TestSetupFailureOnlyCountsAttempt(t *testing.T) {
	c := newClock()
	p := enterChunked(t, c)
	before := p.Snapshot()
	p.Dropped(0, 0, FailSetup)
	after := p.Snapshot()
	if after.Stalled != before.Stalled+1 {
		t.Fatalf("stalled = %d", after.Stalled)
	}
	after.Stalled = before.Stalled
	if after != before {
		t.Fatalf("setup failure changed more than the counter:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestGiveUp(t *testing.T) {
	t.Run("setup failures", func(t *testing.T) {
		p := newTestProfile(newClock())
		for i := 1; i < MaxNoProgress; i++ {
			p.Dropped(0, time.Second, FailSetup)
			if p.GiveUp() {
				t.Fatalf("gave up after %d attempts", i)
			}
		}
		p.Dropped(0, time.Second, FailSetup)
		if !p.GiveUp() {
			t.Fatalf("no give up after %d attempts", MaxNoProgress)
		}
	})
	t.Run("chunk drops never progress", func(t *testing.T) {
		p := enterChunked(t, newClock())
		for i := 1; i < MaxNoProgress; i++ {
			p.Dropped(100_000, 2*time.Second, FailLink)
		}
		if p.GiveUp() {
			t.Fatal("gave up too early")
		}
		p.Dropped(100_000, 2*time.Second, FailLink)
		if !p.GiveUp() {
			t.Fatal("must give up after repeated chunk drops")
		}
	})
	t.Run("chunk completion resets", func(t *testing.T) {
		p := enterChunked(t, newClock())
		for i := 1; i < MaxNoProgress; i++ {
			p.Dropped(0, 2*time.Second, FailLink)
		}
		p.ChunkDone(MinChunk, time.Second)
		if s := p.Snapshot(); s.Stalled != 0 {
			t.Fatalf("stalled = %d", s.Stalled)
		}
		for i := 1; i < MaxNoProgress; i++ {
			p.Dropped(0, 2*time.Second, FailLink)
		}
		if p.GiveUp() {
			t.Fatal("counter was not reset by ChunkDone")
		}
	})
	t.Run("stream drops need new bytes", func(t *testing.T) {
		p := newTestProfile(newClock())
		p.Dropped(100, time.Second, FailLink) // new high-water mark
		if s := p.Snapshot(); s.Stalled != 0 {
			t.Fatalf("first stream bytes are progress, stalled = %d", s.Stalled)
		}
		for i := 1; i < MaxNoProgress; i++ {
			p.Dropped(100, time.Second, FailLink)
		}
		if p.GiveUp() {
			t.Fatal("gave up too early")
		}
		p.Dropped(100, time.Second, FailLink)
		if !p.GiveUp() {
			t.Fatal("same bytes again and again must give up")
		}
	})
	t.Run("stream drop with more bytes resets", func(t *testing.T) {
		p := newTestProfile(newClock())
		for i := 0; i < MaxNoProgress-1; i++ {
			p.Dropped(0, time.Second, FailLink)
		}
		p.Dropped(5, time.Second, FailLink)
		if p.GiveUp() || p.Snapshot().Stalled != 0 {
			t.Fatalf("new bytes must reset: %+v", p.Snapshot())
		}
	})
	t.Run("Succeeded and BeginTransfer reset", func(t *testing.T) {
		p := newTestProfile(newClock())
		for i := 0; i < MaxNoProgress; i++ {
			p.Dropped(0, time.Second, FailSetup)
		}
		if !p.GiveUp() {
			t.Fatal("setup")
		}
		p.BeginTransfer()
		if p.GiveUp() {
			t.Fatal("BeginTransfer must reset")
		}
		for i := 0; i < MaxNoProgress; i++ {
			p.Dropped(0, time.Second, FailSetup)
		}
		p.Succeeded()
		if p.GiveUp() {
			t.Fatal("Succeeded must reset")
		}
	})
}

func TestDropSpeedFallsBackToAttemptSpeed(t *testing.T) {
	p := newTestProfile(newClock())
	p.Dropped(1000, 2*time.Second, FailLink)
	if s := p.Snapshot().DropSpeed; !approx(s, 500, 1e-9) {
		t.Fatalf("DropSpeed = %v, want 500", s)
	}
	p2 := newTestProfile(newClock())
	p2.StreamProgress(4000, time.Second)
	p2.Dropped(1000, 2*time.Second, FailLink)
	if s := p2.Snapshot().DropSpeed; s != 4000 {
		t.Fatalf("DropSpeed = %v, want the EWMA 4000", s)
	}
}

func TestNilClockAndDefaults(t *testing.T) {
	p := NewProfile(Config{})
	p.Dropped(0, time.Second, FailLink)
	if s := p.Snapshot(); s.Drops != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
	if p.window != DefaultWindow {
		t.Fatalf("window = %v", p.window)
	}
}

func TestConcurrentUse(t *testing.T) {
	c := newClock() // never advanced: only read under the profile lock
	p := NewProfile(Config{Now: c.Now, Window: time.Hour})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p.StreamProgress(int64(100_000+g*i), 100*time.Millisecond)
				p.ConnectionSetup(time.Duration(100+g) * time.Millisecond)
				if i%7 == 0 {
					p.Dropped(int64(i), time.Duration(5+g)*time.Second, FailLink)
				}
				step := p.Decide(int64(1+i) * mb)
				if step.Len <= 0 || step.Len > int64(1+i)*mb {
					t.Errorf("bad step %+v", step)
					return
				}
				if n := p.NextChunk(int64(1+i) * mb); n <= 0 || n > MaxChunk {
					t.Errorf("bad chunk %d", n)
					return
				}
				if step.Mode == ModeChunked {
					p.ChunkDone(step.Len, time.Second)
				}
				_ = p.UseChunks(int64(i) * mb)
				_ = p.GiveUp()
				_ = p.Snapshot()
			}
		}(g)
	}
	wg.Wait()
}
