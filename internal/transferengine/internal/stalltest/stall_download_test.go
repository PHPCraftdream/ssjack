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
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/enginetest"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// advancingWriter lets step of virtual time pass before every write, the
// download counterpart of advancingReader: the write that follows is the one
// that carries the next bytes of a slow link.
type advancingWriter struct {
	w     io.Writer
	clock *testfixture.ManualStallClock
	step  time.Duration
}

func (a *advancingWriter) Write(p []byte) (int, error) {
	if a.step > 0 {
		a.clock.Advance(a.step)
	}
	return a.w.Write(p)
}

// dlStallRemote wraps the in-memory download remote and plays stallPlans in the
// byte-moving sessions (the whole stream and each range read). A plan with
// stuck false only makes the link slow: every write into the local sink is
// preceded by step of virtual stall-clock time. A stuck session delivers cut
// bytes the same way, then goes silent: it runs during (if set), lets hold of
// time pass on both clocks (the engine's measuring clock and the watchdog's) and
// waits for its context, like a session whose socket is alive and delivers
// nothing. Everything else is the plain fake.
type dlStallRemote struct {
	*testfixture.FakeDownloadRemote
	sc *testfixture.ManualStallClock

	smu       sync.Mutex
	streams   int
	attempted []transferlink.Range
	readPlan  func(n int) *stallPlan
	rangePlan func(n int, rg transferlink.Range) *stallPlan
}

// stick plays a stuck session: deliver, go silent, wait for the context.
func (s *dlStallRemote) stick(ctx context.Context, p *stallPlan, data []byte, dst io.Writer) int64 {
	if int64(len(data)) > p.cut {
		data = data[:p.cut]
	}
	sent, _ := testfixture.WriteInChunks(&advancingWriter{w: dst, clock: s.sc, step: p.step}, data)
	s.FakeChunkRemote.Transit(sent)
	if p.during != nil {
		p.during()
	}
	if p.hold > 0 {
		s.FakeChunkRemote.Clock.Advance(p.hold)
		s.sc.Advance(p.hold)
	}
	<-ctx.Done()
	return sent
}

func (s *dlStallRemote) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	s.smu.Lock()
	s.streams++
	n, script := s.streams, s.readPlan
	s.smu.Unlock()
	var plan *stallPlan
	if script != nil {
		plan = script(n)
	}
	if plan == nil {
		return s.FakeDownloadRemote.ReadFile(ctx, path, dst)
	}
	if !plan.stuck {
		return s.FakeDownloadRemote.ReadFile(ctx, path, &advancingWriter{w: dst, clock: s.sc, step: plan.step})
	}
	data, ok := s.Get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	sent := s.stick(ctx, plan, data, dst)
	return sent, testfixture.CancelledError()
}

func (s *dlStallRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	s.smu.Lock()
	s.attempted = append(s.attempted, part)
	n, script := len(s.attempted), s.rangePlan
	s.smu.Unlock()
	var plan *stallPlan
	if script != nil {
		plan = script(n, part)
	}
	if plan == nil {
		return s.FakeDownloadRemote.ReadRange(ctx, path, part, grid, fileSize, dst)
	}
	if !plan.stuck {
		return s.FakeDownloadRemote.ReadRange(ctx, path, part, grid, fileSize, &advancingWriter{w: dst, clock: s.sc, step: plan.step})
	}
	data, ok := s.Get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	var avail []byte
	if part.Off < int64(len(data)) {
		avail = data[part.Off:min(part.End(), int64(len(data)))]
	}
	sent := s.stick(ctx, plan, avail, dst)
	return sent, testfixture.CancelledError()
}

func (s *dlStallRemote) streamCount() int {
	s.smu.Lock()
	defer s.smu.Unlock()
	return s.streams
}

// rangeAttempts lists every range read, the stalled ones included.
func (s *dlStallRemote) rangeAttempts() []transferlink.Range {
	s.smu.Lock()
	defer s.smu.Unlock()
	return append([]transferlink.Range(nil), s.attempted...)
}

// dlStallRig is a download rig whose engine runs over a dlStallRemote with the
// default 60 s limit on a virtual watchdog clock.
type dlStallRig struct {
	*chunkfixture.DlRig
	t       *testing.T
	sc      *testfixture.ManualStallClock
	remote  *dlStallRemote
	profile *transferlink.Profile
	stalled *transferengine.Engine
}

func newDLStallRig(t *testing.T) *dlStallRig {
	t.Helper()
	base := chunkfixture.NewDLRig(t)
	sc := &testfixture.ManualStallClock{}
	remote := &dlStallRemote{FakeDownloadRemote: base.Fake, sc: sc}
	profile := transferlink.NewProfile(transferlink.Config{Now: base.Clock.Now})
	engine, err := transferengine.NewWithOptions(remote, transfercore.DefaultLimits(), transferengine.Options{
		Target: "t1", Profile: profile, Now: base.Clock.Now,
		StallLimit: transferengine.DefaultStallLimit, StallClock: sc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &dlStallRig{DlRig: base, t: t, sc: sc, remote: remote, profile: profile, stalled: engine}
}

// requireTimers checks what a session must leave behind: the watchdog fired the
// expected number of times in all and no timer stayed armed.
func (r *dlStallRig) requireTimers(fired int) {
	r.t.Helper()
	if got := r.sc.Fired(); got != fired {
		r.t.Fatalf("watchdog fired %d times, want %d", got, fired)
	}
	if n := r.sc.Armed(); n != 0 {
		r.t.Fatalf("%d watchdog timers left armed", n)
	}
}

func TestDownloadStallDuringTheStreamIsADropAndTheJobContinuesChunked(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 51)
	rig.Put(content)
	rig.remote.readPlan = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkfixture.ChunkMiB)
		}
		return nil
	}

	res, err, log := rig.Download(rig.stalled, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	rig.requireTimers(1)
	ranges := rig.Fake.Ranges()
	chunkfixture.AssertTiles(t, int64(len(content)), ranges)
	if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(content)) || res.SHA256 != chunkfixture.SumHex(content) {
		t.Fatalf("result = %+v", res)
	}
	if n := rig.remote.streamCount(); n != 1 {
		t.Fatalf("%d streams ran, want only the stalled one", n)
	}
	if res.Attempts != 1+len(ranges)+1 {
		t.Fatalf("attempts = %d, want the stalled stream, %d parts and one assembly", res.Attempts, len(ranges))
	}
	// The stall feeds the planner like any drop.
	if snap := rig.profile.Snapshot(); snap.Drops != 1 {
		t.Fatalf("profile drops = %d, want the one stall", snap.Drops)
	}
	chunkfixture.AssertMonotone(t, log.Items)
}

func TestDownloadStallDuringARangeReadIsADropAndTheGapIsReadAgain(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 52)
	rig.Put(content)
	rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
	rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan {
		if n == 2 {
			return stuckAt(100 << 10)
		}
		return nil
	}

	res, err, _ := rig.Download(rig.stalled, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	rig.requireTimers(1)
	attempts := rig.remote.rangeAttempts()
	if len(attempts) < 3 || attempts[1].Off != attempts[0].End() || attempts[2].Off != attempts[1].Off {
		t.Fatalf("range reads = %v, want the stalled part read again from its own offset", attempts)
	}
	stored := rig.Fake.Ranges()
	chunkfixture.AssertTiles(t, int64(len(content)), stored)
	if res.ChunksDone != len(stored) || res.ChunksDone != len(attempts)-1 {
		t.Fatalf("%d parts done after %d range reads, want exactly the stalled one lost", res.ChunksDone, len(attempts))
	}
	// The dropped stream and the stalled part are two drops.
	if snap := rig.profile.Snapshot(); snap.Drops != 2 {
		t.Fatalf("profile drops = %d, want the stream and the stalled part", snap.Drops)
	}
}

func TestDownloadEveryRangeReadStallingEndsAsLinkUnstableWithTheStagingKept(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 53)
	rig.Put(content)
	rig.remote.readPlan = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkfixture.ChunkMiB)
		}
		return nil
	}
	rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan { return stuckAt(50 << 10) }

	res, err, _ := rig.Download(rig.stalled, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassLinkUnstable)
	rig.AssertAbsent("big.bin")
	if n := len(rig.remote.rangeAttempts()); n != transferlink.MaxNoProgress {
		t.Fatalf("%d range reads, want %d attempts without progress", n, transferlink.MaxNoProgress)
	}
	rig.requireTimers(1 + transferlink.MaxNoProgress)
	// The staging of the transfer stays for the next call, with no stray part
	// of the stalled reads in it.
	if kept := rig.Kept("big.bin", content); len(kept) != 0 {
		t.Fatalf("staging holds %v, want no part", kept)
	}
	if res.Mode != transferengine.ModeChunked || res.Bytes != 0 {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestDownloadSteadySlowProgressNeverTripsTheWatchdog(t *testing.T) {
	slow := transferengine.DefaultStallLimit - time.Second
	t.Run("stream", func(t *testing.T) {
		rig := newDLStallRig(t)
		content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 54)
		rig.Put(content)
		rig.remote.readPlan = func(n int) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.Download(rig.stalled, "big.bin", false)
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		want := transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: int64(len(content)), SHA256: chunkfixture.SumHex(content)}
		if res != want {
			t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
		}
		rig.AssertDownloaded("big.bin", content)
		rig.requireTimers(0)
	})
	t.Run("parts", func(t *testing.T) {
		rig := newDLStallRig(t)
		content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 55)
		rig.Put(content)
		rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
		rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.Download(rig.stalled, "big.bin", false)
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		rig.AssertDownloaded("big.bin", content)
		rig.requireTimers(0)
		if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(rig.Fake.Ranges()) {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestDownloadSlowProgressThenASilentSessionTrips(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 56)
	rig.Put(content)
	rig.remote.readPlan = func(n int) *stallPlan {
		if n == 1 {
			// Fifty buffers, each just under the limit apart, then silence.
			return &stallPlan{stuck: true, cut: 200 << 10, step: transferengine.DefaultStallLimit - time.Second, hold: transferengine.DefaultStallLimit}
		}
		return nil
	}

	res, err, _ := rig.Download(rig.stalled, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.AssertDownloaded("big.bin", content)
	rig.requireTimers(1)
	if res.Mode != transferengine.ModeChunked {
		t.Fatalf("result = %+v, want the stall to have switched to chunked mode", res)
	}
}

func TestDownloadCancelIsNeverALinkFailure(t *testing.T) {
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
			rig := newDLStallRig(t)
			content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 57)
			rig.Put(content)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := &stallPlan{stuck: true, cut: 100 << 10, hold: tc.hold, during: cancel}
			if tc.part {
				rig.Fake.SetReadFault(chunkfixture.DlDropFirstStream(chunkfixture.ChunkMiB))
				rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan {
					if n == 1 {
						return plan
					}
					return nil
				}
			} else {
				rig.remote.readPlan = func(n int) *stallPlan { return plan }
			}

			_, err := rig.stalled.Download(ctx, rig.Root, chunkfixture.DlRemote, "big.bin", false, nil)
			testfixture.ExpectClass(t, err, transfercore.ClassCancelled)
			if transferremote.IsLinkFailure(err) {
				t.Fatalf("a cancel was reported as a link failure: %v", err)
			}
			rig.AssertAbsent("big.bin")
			testfixture.NoStagingLeft(t, rig.Root.Dir())
			rig.requireTimers(tc.fired)
			if snap := rig.profile.Snapshot(); tc.part && snap.Drops != 1 || !tc.part && snap.Drops != 0 {
				t.Fatalf("profile drops = %d: the cancel was fed to the planner as a drop", snap.Drops)
			}
		})
	}
}

func TestDownloadStallOnATargetWithoutChunkedModeIsARemoteFailure(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkfixture.ChunkContent(3*chunkfixture.ChunkMiB, 58)
	rig.Put(content)
	rig.Fake.SetCaps(transferremote.ChunkCaps{})
	rig.remote.readPlan = func(n int) *stallPlan { return stuckAt(chunkfixture.ChunkMiB) }

	res, err, _ := rig.Download(rig.stalled, "big.bin", false)
	testfixture.ExpectClass(t, err, transfercore.ClassRemoteFailed)
	if !transferremote.IsLinkFailure(err) {
		t.Fatalf("error = %v, want the plain link failure", err)
	}
	enginetest.ExpectNoResult(t, res)
	rig.AssertAbsent("big.bin")
	testfixture.NoStagingLeft(t, rig.Root.Dir())
	rig.requireTimers(1)
	if n := rig.remote.streamCount(); n != 1 {
		t.Fatalf("%d streams ran, want no retry without chunked mode", n)
	}
}
