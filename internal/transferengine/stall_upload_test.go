package transferengine

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// stallPlan scripts one stream or part session of stallRemote.
//
// A plan with stuck false only makes the link slow: every read of the source
// is preceded by step of virtual stall-clock time and the session then runs
// normally. A stuck session reads cut bytes the same way, then goes silent: it
// runs during (if set), lets hold of time pass on both clocks (the engine's
// measuring clock and the watchdog's) and waits for its context, like a session
// whose socket is alive and delivers nothing.
type stallPlan struct {
	stuck  bool
	cut    int64
	step   time.Duration
	hold   time.Duration
	during func()
}

// stallRemote wraps the in-memory chunk remote and plays stallPlans in the
// byte-moving sessions. Everything else is the plain fake.
type stallRemote struct {
	*fakeChunkRemote
	sc *manualStallClock

	mu      sync.Mutex
	writes  int
	parts   []transferlink.Range
	onWrite func(n int) *stallPlan
	onPart  func(n int, rg transferlink.Range) *stallPlan
}

// advancingReader lets step of virtual time pass before every read.
type advancingReader struct {
	r     io.Reader
	clock *manualStallClock
	step  time.Duration
}

func (a *advancingReader) Read(p []byte) (int, error) {
	if a.step > 0 {
		a.clock.Advance(a.step)
	}
	return a.r.Read(p)
}

// stick plays a stuck session: deliver, go silent, wait for the context.
func (s *stallRemote) stick(ctx context.Context, p *stallPlan, src io.Reader) {
	sent, _ := io.CopyN(io.Discard, &advancingReader{r: src, clock: s.sc, step: p.step}, p.cut)
	s.fakeChunkRemote.transit(sent)
	if p.during != nil {
		p.during()
	}
	if p.hold > 0 {
		s.fakeChunkRemote.clock.Advance(p.hold)
		s.sc.Advance(p.hold)
	}
	<-ctx.Done()
}

func (s *stallRemote) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	s.mu.Lock()
	s.writes++
	n, script := s.writes, s.onWrite
	s.mu.Unlock()
	var plan *stallPlan
	if script != nil {
		plan = script(n)
	}
	if plan == nil {
		return s.fakeChunkRemote.WriteFile(ctx, path, src, executable)
	}
	if !plan.stuck {
		return s.fakeChunkRemote.WriteFile(ctx, path, &advancingReader{r: src, clock: s.sc, step: plan.step}, executable)
	}
	s.stick(ctx, plan, src)
	return plan.cut, cancelledError()
}

func (s *stallRemote) UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (transferremote.PartResult, error) {
	s.mu.Lock()
	s.parts = append(s.parts, part)
	n, script := len(s.parts), s.onPart
	s.mu.Unlock()
	var plan *stallPlan
	if script != nil {
		plan = script(n, part)
	}
	if plan == nil {
		return s.fakeChunkRemote.UploadPart(ctx, parent, key, part, src)
	}
	if !plan.stuck {
		return s.fakeChunkRemote.UploadPart(ctx, parent, key, part, &advancingReader{r: src, clock: s.sc, step: plan.step})
	}
	s.stick(ctx, plan, src)
	return transferremote.PartResult{}, cancelledError()
}

func (s *stallRemote) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func (s *stallRemote) partRanges() []transferlink.Range {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]transferlink.Range(nil), s.parts...)
}

// stallRig is a chunk rig whose engine runs over a stallRemote with the
// default 60 s limit on a virtual watchdog clock.
type stallRig struct {
	*chunkRig
	sc      *manualStallClock
	remote  *stallRemote
	profile *transferlink.Profile
	stalled *Engine
}

func newStallRig(t *testing.T) *stallRig {
	t.Helper()
	base := newChunkRig(t)
	sc := &manualStallClock{}
	remote := &stallRemote{fakeChunkRemote: base.fake, sc: sc}
	profile := transferlink.NewProfile(transferlink.Config{Now: base.clock.Now})
	engine, err := NewWithOptions(remote, transfercore.DefaultLimits(), Options{
		Target: "t1", Profile: profile, Now: base.clock.Now,
		StallLimit: DefaultStallLimit, StallClock: sc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &stallRig{chunkRig: base, sc: sc, remote: remote, profile: profile, stalled: engine}
}

// stuckAt returns a plan for a session that delivers cut bytes and then goes
// silent for a full limit.
func stuckAt(cut int64) *stallPlan {
	return &stallPlan{stuck: true, cut: cut, hold: DefaultStallLimit}
}

// requireTimers checks what a session must leave behind: the watchdog fired the
// expected number of times in all and no timer stayed armed.
func (r *stallRig) requireTimers(fired int) {
	r.t.Helper()
	if got := r.sc.fired(); got != fired {
		r.t.Fatalf("watchdog fired %d times, want %d", got, fired)
	}
	if n := r.sc.armed(); n != 0 {
		r.t.Fatalf("%d watchdog timers left armed", n)
	}
}

func TestStallDuringTheStreamIsADropAndTheJobContinuesChunked(t *testing.T) {
	rig := newStallRig(t)
	content := chunkContent(3*chunkMiB, 11)
	rig.write("big.bin", content)
	rig.remote.onWrite = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkMiB)
		}
		return nil
	}

	res, err, log := rig.upload(rig.stalled, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	rig.requireTimers(1)
	stored := rig.fake.storedParts()
	assertTiles(t, int64(len(content)), stored)
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) || res.SHA256 != sumHex(content) {
		t.Fatalf("result = %+v", res)
	}
	if n := rig.remote.writeCount(); n != 1 {
		t.Fatalf("%d streams ran, want only the stalled one", n)
	}
	if res.Attempts != 1+len(stored)+1 {
		t.Fatalf("attempts = %d, want the stalled stream, %d parts and one assembly", res.Attempts, len(stored))
	}
	// The stall feeds the planner like any drop.
	if snap := rig.profile.Snapshot(); snap.Drops != 1 {
		t.Fatalf("profile drops = %d, want the one stall", snap.Drops)
	}
	assertMonotone(t, log.items)
}

func TestStallDuringAPartIsADropAndTheGapIsSentAgain(t *testing.T) {
	rig := newStallRig(t)
	content := chunkContent(3*chunkMiB, 12)
	rig.write("big.bin", content)
	rig.fake.streamFault = dropFirstStream(chunkMiB)
	rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan {
		if n == 2 {
			return stuckAt(100 << 10)
		}
		return nil
	}

	res, err, _ := rig.upload(rig.stalled, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	assertCleanRemote(t, rig.fake)
	rig.requireTimers(1)
	attempts := rig.remote.partRanges()
	if len(attempts) < 3 || attempts[1].Off != attempts[0].End() || attempts[2].Off != attempts[1].Off {
		t.Fatalf("part sessions = %v, want the stalled part sent again from its own offset", attempts)
	}
	stored := rig.fake.storedParts()
	assertTiles(t, int64(len(content)), stored)
	if res.ChunksDone != len(stored) || res.ChunksDone != len(attempts)-1 {
		t.Fatalf("%d parts done after %d part sessions, want exactly the stalled one lost", res.ChunksDone, len(attempts))
	}
}

func TestEveryPartStallingEndsAsLinkUnstableWithTheStagingKept(t *testing.T) {
	rig := newStallRig(t)
	content := chunkContent(3*chunkMiB, 13)
	rig.write("big.bin", content)
	key := rig.key("big.bin", chunkDest)
	rig.remote.onWrite = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkMiB)
		}
		return nil
	}
	rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan { return stuckAt(50 << 10) }

	res, err, _ := rig.upload(rig.stalled, "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassLinkUnstable)
	assertNotPublished(t, rig.fake, chunkDest)
	if n := len(rig.remote.partRanges()); n != transferlink.MaxNoProgress {
		t.Fatalf("%d part sessions, want %d attempts without progress", n, transferlink.MaxNoProgress)
	}
	rig.requireTimers(1 + transferlink.MaxNoProgress)
	if !rig.fake.hasStage(key) {
		t.Fatal("a link_unstable job removed its staging; it must stay for the next call")
	}
	if res.Mode != ModeChunked || res.Bytes != 0 {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestSteadySlowProgressNeverTripsTheWatchdog(t *testing.T) {
	slow := DefaultStallLimit - time.Second
	t.Run("stream", func(t *testing.T) {
		rig := newStallRig(t)
		content := chunkContent(3*chunkMiB, 14)
		rig.write("big.bin", content)
		rig.remote.onWrite = func(n int) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.upload(rig.stalled, "big.bin", chunkDest, false)
		if err != nil {
			t.Fatalf("Upload: %v", err)
		}
		want := Result{Kind: KindFile, Files: 1, Bytes: int64(len(content)), SHA256: sumHex(content)}
		if res != want {
			t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
		}
		assertPublished(t, rig.fake, chunkDest, content)
		rig.requireTimers(0)
	})
	t.Run("parts", func(t *testing.T) {
		rig := newStallRig(t)
		content := chunkContent(3*chunkMiB, 15)
		rig.write("big.bin", content)
		rig.fake.streamFault = dropFirstStream(chunkMiB)
		rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.upload(rig.stalled, "big.bin", chunkDest, false)
		if err != nil {
			t.Fatalf("Upload: %v", err)
		}
		assertPublished(t, rig.fake, chunkDest, content)
		assertCleanRemote(t, rig.fake)
		rig.requireTimers(0)
		if res.Mode != ModeChunked || res.ChunksDone != len(rig.fake.storedParts()) {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestSlowProgressThenASilentSessionTrips(t *testing.T) {
	rig := newStallRig(t)
	content := chunkContent(3*chunkMiB, 16)
	rig.write("big.bin", content)
	rig.remote.onWrite = func(n int) *stallPlan {
		if n == 1 {
			// Seven buffers, each just under the limit apart, then silence.
			return &stallPlan{stuck: true, cut: 200 << 10, step: DefaultStallLimit - time.Second, hold: DefaultStallLimit}
		}
		return nil
	}

	res, err, _ := rig.upload(rig.stalled, "big.bin", chunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	assertPublished(t, rig.fake, chunkDest, content)
	rig.requireTimers(1)
	if res.Mode != ModeChunked {
		t.Fatalf("result = %+v, want the stall to have switched to chunked mode", res)
	}
}

func TestManagerCancelIsNeverALinkFailure(t *testing.T) {
	cases := []struct {
		name  string
		part  bool
		hold  time.Duration
		fired int
	}{
		{"stream cancelled before the limit", false, 0, 0},
		{"stream cancelled together with the stall", false, DefaultStallLimit, 1},
		{"part cancelled before the limit", true, 0, 0},
		{"part cancelled together with the stall", true, DefaultStallLimit, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newStallRig(t)
			content := chunkContent(3*chunkMiB, 17)
			rig.write("big.bin", content)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := &stallPlan{stuck: true, cut: 100 << 10, hold: tc.hold, during: cancel}
			if tc.part {
				rig.fake.streamFault = dropFirstStream(chunkMiB)
				rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan {
					if n == 1 {
						return plan
					}
					return nil
				}
			} else {
				rig.remote.onWrite = func(n int) *stallPlan { return plan }
			}

			_, err := rig.stalled.Upload(ctx, rig.root, "big.bin", chunkDest, false, nil)
			expectClass(t, err, transfercore.ClassCancelled)
			if transferremote.IsLinkFailure(err) {
				t.Fatalf("a cancel was reported as a link failure: %v", err)
			}
			assertNotPublished(t, rig.fake, chunkDest)
			assertCleanRemote(t, rig.fake)
			rig.requireTimers(tc.fired)
			if snap := rig.profile.Snapshot(); tc.part && snap.Drops != 1 || !tc.part && snap.Drops != 0 {
				t.Fatalf("profile drops = %d: the cancel was fed to the planner as a drop", snap.Drops)
			}
		})
	}
}

func TestStallOnATargetWithoutChunkedModeIsARemoteFailure(t *testing.T) {
	rig := newStallRig(t)
	content := chunkContent(3*chunkMiB, 18)
	rig.write("big.bin", content)
	rig.fake.setCaps(transferremote.ChunkCaps{})
	rig.remote.onWrite = func(n int) *stallPlan { return stuckAt(chunkMiB) }

	_, err, _ := rig.upload(rig.stalled, "big.bin", chunkDest, false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	if !transferremote.IsLinkFailure(err) {
		t.Fatalf("error = %v, want the plain link failure", err)
	}
	assertNotPublished(t, rig.fake, chunkDest)
	assertCleanRemote(t, rig.fake)
	rig.requireTimers(1)
	if n := rig.remote.writeCount(); n != 1 {
		t.Fatalf("%d streams ran, want no retry without chunked mode", n)
	}
}
