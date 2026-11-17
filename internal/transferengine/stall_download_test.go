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
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// advancingWriter lets step of virtual time pass before every write, the
// download counterpart of advancingReader: the write that follows is the one
// that carries the next bytes of a slow link.
type advancingWriter struct {
	w     io.Writer
	clock *manualStallClock
	step  time.Duration
}

func (a *advancingWriter) Write(p []byte) (int, error) {
	if a.step > 0 {
		a.clock.Advance(a.step)
	}
	return a.w.Write(p)
}

// errWriter is a sink that refuses every write.
type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

// dlStallRemote wraps the in-memory download remote and plays stallPlans in the
// byte-moving sessions (the whole stream and each range read). A plan with
// stuck false only makes the link slow: every write into the local sink is
// preceded by step of virtual stall-clock time. A stuck session delivers cut
// bytes the same way, then goes silent: it runs during (if set), lets hold of
// time pass on both clocks (the engine's measuring clock and the watchdog's) and
// waits for its context, like a session whose socket is alive and delivers
// nothing. Everything else is the plain fake.
type dlStallRemote struct {
	*fakeDownloadRemote
	sc *manualStallClock

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
	sent, _ := writeInChunks(&advancingWriter{w: dst, clock: s.sc, step: p.step}, data)
	s.fakeChunkRemote.transit(sent)
	if p.during != nil {
		p.during()
	}
	if p.hold > 0 {
		s.fakeChunkRemote.clock.Advance(p.hold)
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
		return s.fakeDownloadRemote.ReadFile(ctx, path, dst)
	}
	if !plan.stuck {
		return s.fakeDownloadRemote.ReadFile(ctx, path, &advancingWriter{w: dst, clock: s.sc, step: plan.step})
	}
	data, ok := s.get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	sent := s.stick(ctx, plan, data, dst)
	return sent, cancelledError()
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
		return s.fakeDownloadRemote.ReadRange(ctx, path, part, grid, fileSize, dst)
	}
	if !plan.stuck {
		return s.fakeDownloadRemote.ReadRange(ctx, path, part, grid, fileSize, &advancingWriter{w: dst, clock: s.sc, step: plan.step})
	}
	data, ok := s.get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	var avail []byte
	if part.Off < int64(len(data)) {
		avail = data[part.Off:min(part.End(), int64(len(data)))]
	}
	sent := s.stick(ctx, plan, avail, dst)
	return sent, cancelledError()
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
	*dlRig
	sc      *manualStallClock
	remote  *dlStallRemote
	profile *transferlink.Profile
	stalled *Engine
}

func newDLStallRig(t *testing.T) *dlStallRig {
	t.Helper()
	base := newDLRig(t)
	sc := &manualStallClock{}
	remote := &dlStallRemote{fakeDownloadRemote: base.fake, sc: sc}
	profile := transferlink.NewProfile(transferlink.Config{Now: base.clock.Now})
	engine, err := NewWithOptions(remote, transfercore.DefaultLimits(), Options{
		Target: "t1", Profile: profile, Now: base.clock.Now,
		StallLimit: DefaultStallLimit, StallClock: sc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &dlStallRig{dlRig: base, sc: sc, remote: remote, profile: profile, stalled: engine}
}

// requireTimers checks what a session must leave behind: the watchdog fired the
// expected number of times in all and no timer stayed armed.
func (r *dlStallRig) requireTimers(fired int) {
	r.t.Helper()
	if got := r.sc.fired(); got != fired {
		r.t.Fatalf("watchdog fired %d times, want %d", got, fired)
	}
	if n := r.sc.armed(); n != 0 {
		r.t.Fatalf("%d watchdog timers left armed", n)
	}
}

func TestStallWriterCountsAcceptedBytes(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, ctx := cfg.start(context.Background())
	var sink bytes.Buffer
	w := &stallWriter{w: &sink, wd: wd}
	// A slow but moving link: every buffer arrives just under the limit apart.
	for i := 0; i < 10; i++ {
		clock.Advance(time.Minute - time.Nanosecond)
		if n, err := w.Write(make([]byte, 100)); n != 100 || err != nil {
			t.Fatalf("write %d = %d, %v", i, n, err)
		}
	}
	requireDone(t, ctx, false)
	if sink.Len() != 1000 {
		t.Fatalf("the sink got %d bytes, want 1000", sink.Len())
	}
	// Nothing more arrives.
	clock.Advance(time.Minute)
	requireDone(t, ctx, true)
	if !wd.stop() {
		t.Fatal("a silent link was not reported as a stall")
	}
}

func TestStallWriterIgnoresARefusedWrite(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, ctx := cfg.start(context.Background())
	boom := errors.New("boom")
	w := &stallWriter{w: errWriter{boom}, wd: wd}
	clock.Advance(time.Minute - time.Nanosecond)
	if n, err := w.Write(make([]byte, 100)); n != 0 || !errors.Is(err, boom) {
		t.Fatalf("write = %d, %v, want the sink's own error", n, err)
	}
	// The refused write did not re-arm the timer.
	requireDone(t, ctx, false)
	clock.Advance(time.Nanosecond)
	requireDone(t, ctx, true)
	if !wd.stop() {
		t.Fatal("the stall was lost")
	}
}

func TestStallWriterPassesDataThrough(t *testing.T) {
	clock := &manualStallClock{}
	cfg, _ := newStallConfig(clock, time.Minute)
	wd, _ := cfg.start(context.Background())
	defer wd.stop()
	var sink bytes.Buffer
	want := []byte("payload")
	if n, err := (&stallWriter{w: &sink, wd: wd}).Write(want); n != len(want) || err != nil || !bytes.Equal(sink.Bytes(), want) {
		t.Fatalf("write = %d, %v, sink %q", n, err, sink.Bytes())
	}
}

func TestDownloadStallErrorClassification(t *testing.T) {
	live := &downloadJob{ctx: context.Background()}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	dead := &downloadJob{ctx: gone}
	remoteExit := &transfercore.Error{Class: transfercore.ClassRemoteFailed, Message: "remote operation failed", ExitCode: 24}

	if err := live.stallError(nil, true); err != nil {
		t.Fatalf("nil error became %v", err)
	}
	if err := live.stallError(cancelledError(), true); !transferremote.IsLinkFailure(err) {
		t.Fatalf("stalled cancellation = %v, want a link failure", err)
	}
	if err := live.stallError(cancelledError(), false); transfercore.ClassOf(err) != transfercore.ClassCancelled {
		t.Fatalf("unstalled cancellation = %v, want cancelled", err)
	}
	if err := dead.stallError(cancelledError(), true); transfercore.ClassOf(err) != transfercore.ClassCancelled || transferremote.IsLinkFailure(err) {
		t.Fatalf("job cancel with a stall = %v, want cancelled", err)
	}
	if err := live.stallError(remoteExit, true); err != remoteExit {
		t.Fatalf("a remote exit status was rewritten to %v", err)
	}
}

func TestDownloadStallDuringTheStreamIsADropAndTheJobContinuesChunked(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkContent(3*chunkMiB, 51)
	rig.put(content)
	rig.remote.readPlan = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkMiB)
		}
		return nil
	}

	res, err, log := rig.download(rig.stalled, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	rig.requireTimers(1)
	ranges := rig.fake.ranges()
	assertTiles(t, int64(len(content)), ranges)
	if res.Mode != ModeChunked || res.Bytes != int64(len(content)) || res.SHA256 != sumHex(content) {
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
	assertMonotone(t, log.items)
}

func TestDownloadStallDuringARangeReadIsADropAndTheGapIsReadAgain(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkContent(3*chunkMiB, 52)
	rig.put(content)
	rig.fake.readFault = dlDropFirstStream(chunkMiB)
	rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan {
		if n == 2 {
			return stuckAt(100 << 10)
		}
		return nil
	}

	res, err, _ := rig.download(rig.stalled, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	rig.requireTimers(1)
	attempts := rig.remote.rangeAttempts()
	if len(attempts) < 3 || attempts[1].Off != attempts[0].End() || attempts[2].Off != attempts[1].Off {
		t.Fatalf("range reads = %v, want the stalled part read again from its own offset", attempts)
	}
	stored := rig.fake.ranges()
	assertTiles(t, int64(len(content)), stored)
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
	content := chunkContent(3*chunkMiB, 53)
	rig.put(content)
	rig.remote.readPlan = func(n int) *stallPlan {
		if n == 1 {
			return stuckAt(chunkMiB)
		}
		return nil
	}
	rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan { return stuckAt(50 << 10) }

	res, err, _ := rig.download(rig.stalled, "big.bin", false)
	expectClass(t, err, transfercore.ClassLinkUnstable)
	rig.assertAbsent("big.bin")
	if n := len(rig.remote.rangeAttempts()); n != transferlink.MaxNoProgress {
		t.Fatalf("%d range reads, want %d attempts without progress", n, transferlink.MaxNoProgress)
	}
	rig.requireTimers(1 + transferlink.MaxNoProgress)
	// The staging of the transfer stays for the next call, with no stray part
	// of the stalled reads in it.
	if kept := rig.kept("big.bin", content); len(kept) != 0 {
		t.Fatalf("staging holds %v, want no part", kept)
	}
	if res.Mode != ModeChunked || res.Bytes != 0 {
		t.Fatalf("failed result = %+v", res)
	}
}

func TestDownloadSteadySlowProgressNeverTripsTheWatchdog(t *testing.T) {
	slow := DefaultStallLimit - time.Second
	t.Run("stream", func(t *testing.T) {
		rig := newDLStallRig(t)
		content := chunkContent(3*chunkMiB, 54)
		rig.put(content)
		rig.remote.readPlan = func(n int) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.download(rig.stalled, "big.bin", false)
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		want := Result{Kind: KindFile, Files: 1, Bytes: int64(len(content)), SHA256: sumHex(content)}
		if res != want {
			t.Fatalf("result = %+v, want the plain stream result %+v", res, want)
		}
		rig.assertDownloaded("big.bin", content)
		rig.requireTimers(0)
	})
	t.Run("parts", func(t *testing.T) {
		rig := newDLStallRig(t)
		content := chunkContent(3*chunkMiB, 55)
		rig.put(content)
		rig.fake.readFault = dlDropFirstStream(chunkMiB)
		rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan { return &stallPlan{step: slow} }

		res, err, _ := rig.download(rig.stalled, "big.bin", false)
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		rig.assertDownloaded("big.bin", content)
		rig.requireTimers(0)
		if res.Mode != ModeChunked || res.ChunksDone != len(rig.fake.ranges()) {
			t.Fatalf("result = %+v", res)
		}
	})
}

func TestDownloadSlowProgressThenASilentSessionTrips(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkContent(3*chunkMiB, 56)
	rig.put(content)
	rig.remote.readPlan = func(n int) *stallPlan {
		if n == 1 {
			// Fifty buffers, each just under the limit apart, then silence.
			return &stallPlan{stuck: true, cut: 200 << 10, step: DefaultStallLimit - time.Second, hold: DefaultStallLimit}
		}
		return nil
	}

	res, err, _ := rig.download(rig.stalled, "big.bin", false)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	rig.assertDownloaded("big.bin", content)
	rig.requireTimers(1)
	if res.Mode != ModeChunked {
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
		{"stream cancelled together with the stall", false, DefaultStallLimit, 1},
		{"part cancelled before the limit", true, 0, 0},
		{"part cancelled together with the stall", true, DefaultStallLimit, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newDLStallRig(t)
			content := chunkContent(3*chunkMiB, 57)
			rig.put(content)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			plan := &stallPlan{stuck: true, cut: 100 << 10, hold: tc.hold, during: cancel}
			if tc.part {
				rig.fake.readFault = dlDropFirstStream(chunkMiB)
				rig.remote.rangePlan = func(n int, rg transferlink.Range) *stallPlan {
					if n == 1 {
						return plan
					}
					return nil
				}
			} else {
				rig.remote.readPlan = func(n int) *stallPlan { return plan }
			}

			_, err := rig.stalled.Download(ctx, rig.root, dlRemote, "big.bin", false, nil)
			expectClass(t, err, transfercore.ClassCancelled)
			if transferremote.IsLinkFailure(err) {
				t.Fatalf("a cancel was reported as a link failure: %v", err)
			}
			rig.assertAbsent("big.bin")
			noStagingLeft(t, rig.root.Dir())
			rig.requireTimers(tc.fired)
			if snap := rig.profile.Snapshot(); tc.part && snap.Drops != 1 || !tc.part && snap.Drops != 0 {
				t.Fatalf("profile drops = %d: the cancel was fed to the planner as a drop", snap.Drops)
			}
		})
	}
}

func TestDownloadStallOnATargetWithoutChunkedModeIsARemoteFailure(t *testing.T) {
	rig := newDLStallRig(t)
	content := chunkContent(3*chunkMiB, 58)
	rig.put(content)
	rig.fake.setCaps(transferremote.ChunkCaps{})
	rig.remote.readPlan = func(n int) *stallPlan { return stuckAt(chunkMiB) }

	res, err, _ := rig.download(rig.stalled, "big.bin", false)
	expectClass(t, err, transfercore.ClassRemoteFailed)
	if !transferremote.IsLinkFailure(err) {
		t.Fatalf("error = %v, want the plain link failure", err)
	}
	expectNoResult(t, res)
	rig.assertAbsent("big.bin")
	noStagingLeft(t, rig.root.Dir())
	rig.requireTimers(1)
	if n := rig.remote.streamCount(); n != 1 {
		t.Fatalf("%d streams ran, want no retry without chunked mode", n)
	}
}
