package transferlink

import (
	"math"
	"reflect"
	"testing"
	"time"
)

// The simulation drives a whole upload loop against a virtual link on a
// virtual clock: no sleeps, no timers, no wall clock, no real I/O.

var simEpoch = time.Unix(1_700_000_000, 0)

// phase describes the link for connections that start before Until (the last
// phase has Until == 0 and lasts forever).
type phase struct {
	Until time.Duration
	Rate  int64         // payload bytes per second
	Life  time.Duration // connection lifetime, setup included; 0 = never drops
	Bytes int64         // connection drops after this many payload bytes; 0 = never
}

type simLink struct {
	Phases []phase
	Setup  time.Duration
	Jitter float64 // lifetime is scaled by a factor in [1-Jitter, 1+Jitter)
	Seed   uint64
}

func (l simLink) phaseAt(at time.Duration) phase {
	for _, ph := range l.Phases {
		if ph.Until == 0 || at < ph.Until {
			return ph
		}
	}
	return l.Phases[len(l.Phases)-1]
}

// xorshift is a tiny deterministic generator independent of math/rand.
type xorshift struct{ s uint64 }

func newXorshift(seed uint64) *xorshift {
	r := &xorshift{s: seed*0x9E3779B97F4A7C15 ^ 0xD1B54A32D192ED03}
	if r.s == 0 {
		r.s = 1
	}
	for i := 0; i < 8; i++ {
		r.float()
	}
	return r
}

func (r *xorshift) float() float64 {
	r.s ^= r.s << 13
	r.s ^= r.s >> 7
	r.s ^= r.s << 17
	return float64(r.s>>11) / float64(uint64(1)<<53)
}

type attempt struct {
	At      time.Duration
	Mode    Mode
	Len     int64
	Sent    int64
	Dropped bool
	Setup   bool // the connection died before it was usable
}

type simResult struct {
	Attempts  []attempt
	Done      bool
	GaveUp    bool
	Exhausted bool
	Elapsed   time.Duration
	Sent      int64 // all payload bytes put on the wire
	Wasted    int64 // payload bytes of attempts that were cut off
	Delivered int64
	Drops     int
	Final     Snapshot
}

const simMaxAttempts = 200_000

func durationFor(n, rate int64) time.Duration {
	return time.Duration(float64(n) / float64(rate) * float64(time.Second))
}

func bytesIn(d time.Duration, rate int64) int64 {
	return int64(float64(d) / float64(time.Second) * float64(rate))
}

// runSim uploads size bytes over link, driving a Profile exactly like the
// engine will: Decide, NextRange, connect, send, report.
func runSim(t *testing.T, link simLink, size int64, window time.Duration) simResult {
	t.Helper()
	clk := &fakeClock{t: simEpoch}
	p := NewProfile(Config{Now: clk.Now, Window: window})
	rng := newXorshift(link.Seed)
	var covered []Range
	remaining := size
	var res simResult

	for len(res.Attempts) < simMaxAttempts {
		if remaining == 0 {
			res.Done = true
			break
		}
		if p.GiveUp() {
			res.GaveUp = true
			break
		}
		step := p.Decide(remaining)
		chunk := step.Len
		if step.Mode == ModeStream {
			chunk = 0
		}
		rg, ok, err := NextRange(size, covered, chunk)
		if err != nil || !ok {
			t.Fatalf("NextRange(%d, %v, %d) = %v, %v, %v", size, covered, chunk, rg, ok, err)
		}
		if rg.Len != step.Len {
			t.Fatalf("planner %+v disagrees with the gap %v", step, rg)
		}

		at := clk.t.Sub(simEpoch)
		ph := link.phaseAt(at)
		life := ph.Life
		if life > 0 && link.Jitter > 0 {
			life = time.Duration(float64(life) * (1 - link.Jitter + 2*link.Jitter*rng.float()))
		}
		a := attempt{At: at, Mode: step.Mode, Len: rg.Len}

		if life > 0 && life <= link.Setup {
			clk.Advance(life)
			p.Dropped(0, life, FailSetup)
			a.Setup, a.Dropped = true, true
			res.Attempts = append(res.Attempts, a)
			continue
		}
		clk.Advance(link.Setup)
		p.ConnectionSetup(link.Setup)

		dataLimit := time.Duration(math.MaxInt64)
		if life > 0 {
			dataLimit = life - link.Setup
		}
		byBytes := rg.Len
		if ph.Bytes > 0 && ph.Bytes < byBytes {
			byBytes = ph.Bytes
		}
		need := durationFor(byBytes, ph.Rate)
		var sent int64
		var spent time.Duration
		dropped := false
		switch {
		case need > dataLimit:
			spent = dataLimit
			sent = bytesIn(dataLimit, ph.Rate)
			if sent > byBytes {
				sent = byBytes
			}
			dropped = true
		case byBytes < rg.Len:
			spent, sent, dropped = need, byBytes, true
		default:
			spent, sent = need, rg.Len
		}
		clk.Advance(spent)
		res.Sent += sent
		a.Sent = sent

		if dropped {
			if sent > 0 && spent > 0 {
				p.StreamProgress(sent, spent)
			}
			p.Dropped(sent, link.Setup+spent, FailLink)
			res.Wasted += sent
			res.Drops++
			a.Dropped = true
		} else {
			if step.Mode == ModeChunked {
				p.ChunkDone(rg.Len, spent)
			} else {
				p.StreamProgress(sent, spent)
			}
			covered = append(covered, rg)
			remaining -= rg.Len
			res.Delivered += rg.Len
			if remaining == 0 {
				p.Succeeded()
			}
		}
		res.Attempts = append(res.Attempts, a)
	}
	res.Exhausted = !res.Done && !res.GaveUp
	res.Elapsed = clk.t.Sub(simEpoch)
	res.Final = p.Snapshot()
	if res.Done {
		if err := ValidateTiling(size, covered); err != nil {
			t.Fatalf("delivered parts do not tile the file: %v", err)
		}
	}
	return res
}

// checkInvariants holds for every scenario.
func checkInvariants(t *testing.T, size int64, res simResult) {
	t.Helper()
	if res.Exhausted {
		t.Fatalf("simulation did not terminate (%d attempts)", len(res.Attempts))
	}
	if res.Wasted > res.Sent {
		t.Fatalf("wasted %d > sent %d", res.Wasted, res.Sent)
	}
	for i, a := range res.Attempts {
		if a.Len <= 0 || a.Len > size {
			t.Fatalf("attempt %d: bad length %d", i, a.Len)
		}
		if a.Mode == ModeChunked && (a.Len < MinChunk || a.Len > MaxChunk) {
			t.Fatalf("attempt %d: chunk %d outside [%d,%d]", i, a.Len, MinChunk, MaxChunk)
		}
	}
	if res.Done {
		if res.Delivered != size {
			t.Fatalf("delivered %d of %d", res.Delivered, size)
		}
		if last := res.Attempts[len(res.Attempts)-1]; last.Mode != ModeStream || last.Dropped {
			t.Fatalf("a finished transfer ends with a completed stream, got %+v", last)
		}
	}
}

func countMode(res simResult, m Mode) int {
	n := 0
	for _, a := range res.Attempts {
		if a.Mode == m {
			n++
		}
	}
	return n
}

func TestSimGoodLinkIsOneStream(t *testing.T) {
	size := int64(50_000_000)
	res := runSim(t, simLink{Phases: []phase{{Rate: 10_000_000}}, Setup: 200 * time.Millisecond}, size, time.Hour)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp {
		t.Fatalf("result %+v", res)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Mode != ModeStream || res.Wasted != 0 || res.Drops != 0 {
		t.Fatalf("a link without drops must take exactly one stream: %+v", res.Attempts)
	}
}

func TestSimSlowLinkWithoutDropsStaysStream(t *testing.T) {
	size := int64(1_000_000)
	res := runSim(t, simLink{Phases: []phase{{Rate: 10_000}}, Setup: time.Second}, size, time.Hour)
	checkInvariants(t, size, res)
	if !res.Done || len(res.Attempts) != 1 || res.Elapsed != 101*time.Second {
		t.Fatalf("result %+v", res)
	}
}

func TestSimSteadyFlakyLinkConvergesToFixedChunk(t *testing.T) {
	// 200 KB/s, connections die after 30 s, setup 1 s: bound = 0.5*B*T = 3 MB.
	size := int64(30_000_000)
	link := simLink{Phases: []phase{{Rate: 200_000, Life: 30 * time.Second}}, Setup: time.Second}
	res := runSim(t, link, size, time.Hour)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp {
		t.Fatalf("result %+v", res)
	}
	if res.Drops != 1 {
		t.Fatalf("only the first stream may be cut off, drops = %d", res.Drops)
	}
	if res.Wasted > 200_000*30 {
		t.Fatalf("wasted %d exceeds one connection", res.Wasted)
	}
	if countMode(res, ModeChunked) == 0 {
		t.Fatal("never switched to chunks")
	}
	for i, a := range res.Attempts {
		if a.Mode == ModeChunked && a.Len != 3_000_000 {
			t.Fatalf("attempt %d: chunk %d, want the converged 3000000", i, a.Len)
		}
	}
}

func TestSimDegradingLinkHalvesAndRecovers(t *testing.T) {
	// The link gets worse at 150 s: connections then live only 10 s.
	size := int64(30_000_000)
	link := simLink{
		Phases: []phase{
			{Until: 150 * time.Second, Rate: 100_000, Life: 60 * time.Second},
			{Rate: 100_000, Life: 10 * time.Second},
		},
		Setup: time.Second,
	}
	res := runSim(t, link, size, time.Hour)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp {
		t.Fatalf("result %+v", res)
	}
	if res.Drops < 2 || res.Drops > 3 {
		t.Fatalf("drops = %d, want the stream drop plus the degradation drop", res.Drops)
	}
	if res.Wasted*2 > size {
		t.Fatalf("wasted %d is more than half of the file", res.Wasted)
	}
	lastDrop := -1
	for i, a := range res.Attempts {
		if a.Dropped {
			lastDrop = i
		}
	}
	for i, a := range res.Attempts[lastDrop+1:] {
		if a.Mode == ModeChunked && a.Len != 500_000 {
			t.Fatalf("attempt %d after the last drop: chunk %d, want the converged 500000", lastDrop+1+i, a.Len)
		}
	}
}

func TestSimByteBudgetDrops(t *testing.T) {
	// A proxy cuts every connection after 4 MB.
	size := int64(50_000_000)
	link := simLink{Phases: []phase{{Rate: 1_000_000, Bytes: 4_000_000}}, Setup: 500 * time.Millisecond}
	res := runSim(t, link, size, time.Hour)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp || res.Drops != 1 {
		t.Fatalf("result %+v", res)
	}
	for i, a := range res.Attempts {
		if a.Mode == ModeChunked && a.Len != 2_250_000 {
			t.Fatalf("attempt %d: chunk %d, want 2250000", i, a.Len)
		}
	}
}

func TestSimImprovingLinkReturnsToStream(t *testing.T) {
	// 50 KB/s with 20 s connections, then at 200 s a fast stable link. The
	// file is far larger than one chunk can be, so only the speed rule (not
	// "remainder fits one chunk") can bring the transfer back to a stream.
	const improveAt = 200 * time.Second
	size := int64(1 << 30)
	link := simLink{
		Phases: []phase{
			{Until: improveAt, Rate: 50_000, Life: 20 * time.Second},
			{Rate: 5_000_000},
		},
		Setup: 500 * time.Millisecond,
	}
	res := runSim(t, link, size, time.Minute)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp {
		t.Fatalf("result %+v", res)
	}
	chunkedBefore, streamAfter := false, false
	for _, a := range res.Attempts {
		if a.At < improveAt && a.Mode == ModeChunked {
			chunkedBefore = true
		}
		if a.At >= improveAt && a.Mode == ModeStream && a.Len > MaxChunk {
			streamAfter = true
		}
	}
	if !chunkedBefore {
		t.Fatal("never chunked on the slow link")
	}
	if !streamAfter {
		t.Fatal("did not return to a single stream after the link improved")
	}
	// the improved phase must not be spent on one tiny chunk after another
	if n := countMode(res, ModeChunked); n > 200 {
		t.Fatalf("too many chunks: %d", n)
	}
}

func TestSimHugeFileKeepsMaxChunk(t *testing.T) {
	// ~137 GB over a fast link that drops once: chunks settle at MaxChunk.
	size := int64(1) << 37
	link := simLink{Phases: []phase{{Rate: 1_000_000_000, Life: 100 * time.Second}}, Setup: 100 * time.Millisecond}
	res := runSim(t, link, size, time.Hour)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp || res.Drops != 1 {
		t.Fatalf("result done=%v gaveUp=%v drops=%d", res.Done, res.GaveUp, res.Drops)
	}
	for i, a := range res.Attempts {
		if a.Mode == ModeChunked && a.Len != MaxChunk {
			t.Fatalf("attempt %d: chunk %d, want %d", i, a.Len, MaxChunk)
		}
	}
}

func TestSimJitteryLinkFinishesWithFewDrops(t *testing.T) {
	// Lifetimes are in [10 s, 30 s): after the first chunk drop the bound
	// 0.5*B*T always fits, so at most two drops occur for every seed.
	size := int64(5_000_000)
	for seed := uint64(1); seed <= 25; seed++ {
		link := simLink{
			Phases: []phase{{Rate: 100_000, Life: 20 * time.Second}},
			Setup:  time.Second,
			Jitter: 0.5,
			Seed:   seed,
		}
		res := runSim(t, link, size, time.Hour)
		checkInvariants(t, size, res)
		if !res.Done || res.GaveUp {
			t.Fatalf("seed %d: result %+v", seed, res)
		}
		if res.Drops > 3 {
			t.Fatalf("seed %d: %d drops", seed, res.Drops)
		}
		if res.Wasted > 3*100_000*30 {
			t.Fatalf("seed %d: wasted %d", seed, res.Wasted)
		}
	}
}

func TestSimGiveUpOnlyWithoutProgress(t *testing.T) {
	t.Run("dead link: connections die during setup", func(t *testing.T) {
		size := int64(10_000_000)
		link := simLink{Phases: []phase{{Rate: 100_000, Life: time.Second}}, Setup: 2 * time.Second}
		res := runSim(t, link, size, time.Hour)
		checkInvariants(t, size, res)
		if !res.GaveUp || res.Done {
			t.Fatalf("result %+v", res)
		}
		if len(res.Attempts) != MaxNoProgress {
			t.Fatalf("attempts = %d, want exactly %d", len(res.Attempts), MaxNoProgress)
		}
	})
	t.Run("link too short for even the smallest chunk", func(t *testing.T) {
		// 1 s of data per connection at 100 KB/s cannot deliver 256 KiB.
		size := int64(10_000_000)
		link := simLink{Phases: []phase{{Rate: 100_000, Life: 3 * time.Second}}, Setup: 2 * time.Second}
		res := runSim(t, link, size, time.Hour)
		checkInvariants(t, size, res)
		if !res.GaveUp || res.Done {
			t.Fatalf("result %+v", res)
		}
		if n := len(res.Attempts); n < MaxNoProgress || n > MaxNoProgress+2 {
			t.Fatalf("attempts = %d", n)
		}
		if res.Delivered != 0 {
			t.Fatalf("delivered %d", res.Delivered)
		}
		if res.Final.Stored < MinChunk || res.Final.Chunk < MinChunk {
			t.Fatalf("chunk collapsed: %+v", res.Final)
		}
	})
	t.Run("a flaky link that still progresses never gives up", func(t *testing.T) {
		size := int64(5_000_000)
		link := simLink{Phases: []phase{{Rate: 100_000, Life: 20 * time.Second}}, Setup: time.Second, Jitter: 0.5, Seed: 99}
		res := runSim(t, link, size, time.Hour)
		checkInvariants(t, size, res)
		if res.GaveUp || !res.Done {
			t.Fatalf("result %+v", res)
		}
	})
}

func TestSimIsDeterministic(t *testing.T) {
	size := int64(5_000_000)
	link := simLink{
		Phases: []phase{
			{Until: 40 * time.Second, Rate: 100_000, Life: 20 * time.Second},
			{Rate: 400_000, Life: 15 * time.Second},
		},
		Setup:  time.Second,
		Jitter: 0.4,
		Seed:   7,
	}
	first := runSim(t, link, size, 90*time.Second)
	checkInvariants(t, size, first)
	if len(first.Attempts) < 3 {
		t.Fatalf("scenario too trivial to prove determinism: %+v", first.Attempts)
	}
	for i := 0; i < 3; i++ {
		again := runSim(t, link, size, 90*time.Second)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\nfirst %+v\nagain %+v", i, first, again)
		}
	}
	other := link
	other.Seed = 8
	if reflect.DeepEqual(first, runSim(t, other, size, 90*time.Second)) {
		t.Fatal("different jitter seeds produced identical traces; the seed is not used")
	}
}

func TestSimShortWindowForgetsAndProbes(t *testing.T) {
	// With a 60 s window the survival time is forgotten while the transfer
	// runs; the planner then probes with a bigger chunk and relearns on the
	// next drop. Each probe costs at most one connection of data, the
	// transfer still finishes and never gives up (every cycle progresses).
	size := int64(40_000_000)
	link := simLink{Phases: []phase{{Rate: 100_000, Life: 30 * time.Second}}, Setup: time.Second}
	res := runSim(t, link, size, 60*time.Second)
	checkInvariants(t, size, res)
	if !res.Done || res.GaveUp {
		t.Fatalf("result %+v", res)
	}
	if res.Wasted > int64(res.Drops)*100_000*30 {
		t.Fatalf("wasted %d exceeds %d drops of one connection", res.Wasted, res.Drops)
	}
	if res.Wasted > size {
		t.Fatalf("wasted %d of %d", res.Wasted, size)
	}
}
