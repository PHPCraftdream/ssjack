package stalltest

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/chunkfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
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
	*testfixture.FakeChunkRemote
	sc *testfixture.ManualStallClock

	mu      sync.Mutex
	writes  int
	parts   []transferlink.Range
	onWrite func(n int) *stallPlan
	onPart  func(n int, rg transferlink.Range) *stallPlan
}

// advancingReader lets step of virtual time pass before every read.
type advancingReader struct {
	r     io.Reader
	clock *testfixture.ManualStallClock
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
	s.FakeChunkRemote.Transit(sent)
	if p.during != nil {
		p.during()
	}
	if p.hold > 0 {
		s.FakeChunkRemote.Clock.Advance(p.hold)
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
		return s.FakeChunkRemote.WriteFile(ctx, path, src, executable)
	}
	if !plan.stuck {
		return s.FakeChunkRemote.WriteFile(ctx, path, &advancingReader{r: src, clock: s.sc, step: plan.step}, executable)
	}
	s.stick(ctx, plan, src)
	return plan.cut, testfixture.CancelledError()
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
		return s.FakeChunkRemote.UploadPart(ctx, parent, key, part, src)
	}
	if !plan.stuck {
		return s.FakeChunkRemote.UploadPart(ctx, parent, key, part, &advancingReader{r: src, clock: s.sc, step: plan.step})
	}
	s.stick(ctx, plan, src)
	return transferremote.PartResult{}, testfixture.CancelledError()
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
	*chunkfixture.ChunkRig
	t       *testing.T
	sc      *testfixture.ManualStallClock
	remote  *stallRemote
	profile *transferlink.Profile
	stalled *transferengine.Engine
}

func newStallRig(t *testing.T) *stallRig {
	t.Helper()
	base := chunkfixture.NewChunkRig(t)
	sc := &testfixture.ManualStallClock{}
	remote := &stallRemote{FakeChunkRemote: base.Fake, sc: sc}
	profile := transferlink.NewProfile(transferlink.Config{Now: base.Clock.Now})
	engine, err := transferengine.NewWithOptions(remote, transfercore.DefaultLimits(), transferengine.Options{
		Target: "t1", Profile: profile, Now: base.Clock.Now,
		StallLimit: transferengine.DefaultStallLimit, StallClock: sc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &stallRig{ChunkRig: base, t: t, sc: sc, remote: remote, profile: profile, stalled: engine}
}

// stuckAt returns a plan for a session that delivers cut bytes and then goes
// silent for a full limit.
func stuckAt(cut int64) *stallPlan {
	return &stallPlan{stuck: true, cut: cut, hold: transferengine.DefaultStallLimit}
}

// requireTimers checks what a session must leave behind: the watchdog fired the
// expected number of times in all and no timer stayed armed.
func (r *stallRig) requireTimers(fired int) {
	r.t.Helper()
	if got := r.sc.Fired(); got != fired {
		r.t.Fatalf("watchdog fired %d times, want %d", got, fired)
	}
	if n := r.sc.Armed(); n != 0 {
		r.t.Fatalf("%d watchdog timers left armed", n)
	}
}

func TestStallDuringTheStreamIsADropAndTheJobContinuesChunked(t *testing.T) {
	rig := newStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 11)
	rig.Write("big.bin", content)
	rig.remote.onWrite = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkfixture.ChunkMiB)
		}
		return nil
	}

	res, err, log := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	rig.requireTimers(1)
	stored := rig.Fake.StoredParts()
	chunkfixture.AssertTiles(t, int64(len(content)), stored)
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) || res.SHA256 != chunkfixture.SumHex(content) {
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
	chunkfixture.AssertMonotone(t, log.Items)
}

func TestStallDuringAPartIsADropAndTheGapIsSentAgain(t *testing.T) {
	rig := newStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 12)
	rig.Write("big.bin", content)
	rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
	rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan {
		if n == 2 {
			return stuckAt(100 << 10)
		}
		return nil
	}

	res, err, _ := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	rig.requireTimers(1)
	attempts := rig.remote.partRanges()
	if len(attempts) < 3 || attempts[1].Off != attempts[0].End() || attempts[2].Off != attempts[1].Off {
		t.Fatalf("part sessions = %v, want the stalled part sent again from its own offset", attempts)
	}
	stored := rig.Fake.StoredParts()
	chunkfixture.AssertTiles(t, int64(len(content)), stored)
	if res.ChunksDone != len(stored) || res.ChunksDone != len(attempts)-1 {
		t.Fatalf("%d parts done after %d part sessions, want exactly the stalled one lost", res.ChunksDone, len(attempts))
	}
}

func TestEveryPartStallingEndsAsLinkUnstableWithTheStagingKept(t *testing.T) {
	rig := newStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 13)
	rig.Write("big.bin", content)
	key := rig.Key("big.bin", chunkfixture.ChunkDest)
	rig.remote.onWrite = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkfixture.ChunkMiB)
		}
		return nil
	}
	rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan { return stuckAt(50 << 10) }

	res, err, _ := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassLinkUnstable)
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	if n := len(rig.remote.partRanges()); n != transferlink.MaxNoProgress {
		t.Fatalf("%d part sessions, want %d attempts without progress", n, transferlink.MaxNoProgress)
	}
	rig.requireTimers(1 + transferlink.MaxNoProgress)
	if !rig.Fake.HasStage(key) {
		t.Fatal("a link_unstable job removed its staging; it must stay for the next call")
	}
	if res.Mode != transferengine.ModeChunked || res.Bytes != 0 {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestSteadySlowProgressNeverTripsTheWatchdog(t *testing.T) {
	slow := transferengine.DefaultStallLimit - time.Second
	t.Run("stream", func(t *testing.T) {
		rig := newStallRig(t)
		content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 14)
		rig.Write("big.bin", content)
		rig.remote.onWrite = func(n int) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
		if err != nil {
			t.Fatalf("Upload: %v", err)
		}
		want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: int64(len(content)), SHA256: chunkfixture.SumHex(content)}
		if res != want {
			t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
		}
		chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
		rig.requireTimers(0)
	})
	t.Run("parts", func(t *testing.T) {
		rig := newStallRig(t)
		content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 15)
		rig.Write("big.bin", content)
		rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
		rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
		if err != nil {
			t.Fatalf("Upload: %v", err)
		}
		chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
		chunkfixture.AssertCleanRemote(t, rig.Fake)
		rig.requireTimers(0)
		if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(rig.Fake.StoredParts()) {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestSlowProgressThenASilentSessionTrips(t *testing.T) {
	rig := newStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 16)
	rig.Write("big.bin", content)
	rig.remote.onWrite = func(n int) *stallPlan {
		if n == 1 {
			// Seven buffers, each just under the limit apart, then silence.
			return &stallPlan{stuck: true, cut: 200 << 10, step: transferengine.DefaultStallLimit - time.Second, hold: transferengine.DefaultStallLimit}
		}
		return nil
	}

	res, err, _ := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	chunkfixture.AssertPublished(t, rig.Fake, chunkfixture.ChunkDest, content)
	rig.requireTimers(1)
	if res.Mode != transferengine.ModeChunked {
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
		{"stream cancelled together with the stall", false, transferengine.DefaultStallLimit, 1},
		{"part cancelled before the limit", true, 0, 0},
		{"part cancelled together with the stall", true, transferengine.DefaultStallLimit, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newStallRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 17)
			rig.Write("big.bin", content)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := &stallPlan{stuck: true, cut: 100 << 10, hold: tc.hold, during: cancel}
			if tc.part {
				rig.Fake.SetStreamFault(chunkfixture.DropFirstStream(chunkfixture.ChunkMiB))
				rig.remote.onPart = func(n int, rg transferlink.Range) *stallPlan {
					if n == 1 {
						return plan
					}
					return nil
				}
			} else {
				rig.remote.onWrite = func(n int) *stallPlan { return plan }
			}

			_, err := rig.stalled.Upload(ctx, rig.Root, "big.bin", chunkfixture.ChunkDest, false, nil)
			testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
			if transferremote.IsLinkFailure(err) {
				t.Fatalf("a cancel was reported as a link failure: %v", err)
			}
			chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
			chunkfixture.AssertCleanRemote(t, rig.Fake)
			rig.requireTimers(tc.fired)
			if snap := rig.profile.Snapshot(); tc.part && snap.Drops != 1 || !tc.part && snap.Drops != 0 {
				t.Fatalf("profile drops = %d: the cancel was fed to the planner as a drop", snap.Drops)
			}
		})
	}
}

func TestStallOnATargetWithoutChunkedModeIsARemoteFailure(t *testing.T) {
	rig := newStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 18)
	rig.Write("big.bin", content)
	rig.Fake.SetCaps(transferremote.ChunkCaps{})
	rig.remote.onWrite = func(n int) *stallPlan { return stuckAt(chunkfixture.ChunkMiB) }

	_, err, _ := rig.Upload(rig.stalled, "big.bin", chunkfixture.ChunkDest, false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	if !transferremote.IsLinkFailure(err) {
		t.Fatalf("error = %v, want the plain link failure", err)
	}
	chunkfixture.AssertNotPublished(t, rig.Fake, chunkfixture.ChunkDest)
	chunkfixture.AssertCleanRemote(t, rig.Fake)
	rig.requireTimers(1)
	if n := rig.remote.writeCount(); n != 1 {
		t.Fatalf("%d streams ran, want no retry without chunked mode", n)
	}
}
