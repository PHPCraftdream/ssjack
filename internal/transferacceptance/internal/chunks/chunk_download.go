//go:build linux || darwin

package chunks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/faultproxy"
	fixture "github.com/PHPCraftdream/ssjack/internal/transferacceptance/internal/fixture"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// The chunked download scenarios mirror the upload ones: the Engine runs over
// the real exec fixture (GNU, BusyBox applets or stock macOS tools) with the
// SSH client dialing a fault-injecting proxy, here cutting the SERVER to CLIENT
// direction at an exact byte count. A thin wrapper around the real chunk layer
// arms the cut on the very next connection just before a chosen session
// starts, so every fault lands on a known session with no sleeping and no
// timing assumption. The remote source is a file in the sandbox; the local
// destination is a directory under the transfer root.

const (
	downloadPayload  = 8 << 20
	streamCutDown    = 768 << 10 // exact server-to-client bytes of the cut stream
	partCutDown      = 128 << 10 // inside the payload of any part (the smallest is 256 KiB)
	strandedCutDown  = 64 << 10  // below every part, above every control session
	handshakeCutDown = 200       // inside the SSH handshake: the session never starts
)

// dlHookRemote wraps the real chunk layer and runs hooks before the whole
// stream, each remote look at the source and each range read.
type dlHookRemote struct {
	transferremote.ChunkRemote

	diag     *fixture.RigDiagnostics
	mu       sync.Mutex
	streams  int
	stats    int
	calls    []dlCall
	done     int64 // bytes of the ranges that were read successfully
	onStream func(n int)
	onStat   func(n int)
	onRange  func(n int, part transferlink.Range)
}

type dlCall struct {
	part     transferlink.Range
	grid     int64
	fileSize int64
}

func (h *dlHookRemote) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	h.mu.Lock()
	h.streams++
	n, hook := h.streams, h.onStream
	h.mu.Unlock()
	call := h.diag.Enter(fixture.RigCall{Action: fixture.RigRead, Attempt: n})
	if hook != nil {
		hook(n)
	}
	got, err := h.ChunkRemote.ReadFile(ctx, path, dst)
	h.diag.Complete(call, got, false, err)
	return got, err
}

func (h *dlHookRemote) StatSource(ctx context.Context, path string) (transferremote.SourceStat, error) {
	h.mu.Lock()
	h.stats++
	n, hook := h.stats, h.onStat
	h.mu.Unlock()
	call := h.diag.Enter(fixture.RigCall{Action: fixture.RigStat, Attempt: n})
	if hook != nil {
		hook(n)
	}
	got, err := h.ChunkRemote.StatSource(ctx, path)
	h.diag.Complete(call, got.Size, false, err)
	return got, err
}

func (h *dlHookRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	h.mu.Lock()
	h.calls = append(h.calls, dlCall{part: part, grid: grid, fileSize: fileSize})
	n, hook := len(h.calls), h.onRange
	h.mu.Unlock()
	call := h.diag.Enter(fixture.RigCall{Action: fixture.RigRange, Attempt: n, Offset: part.Off, Length: part.Len, Grid: grid, Size: fileSize})
	if hook != nil {
		hook(n, part)
	}
	got, err := h.ChunkRemote.ReadRange(ctx, path, part, grid, fileSize, dst)
	if err == nil {
		h.mu.Lock()
		h.done += part.Len
		h.mu.Unlock()
	}
	h.diag.Complete(call, got, false, err)
	return got, err
}

func (h *dlHookRemote) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streams, h.stats, h.calls, h.done = 0, 0, nil, 0
	h.onStream, h.onStat, h.onRange = nil, nil, nil
}

func (h *dlHookRemote) counts() (streams, stats, ranges int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.streams, h.stats, len(h.calls)
}

func (h *dlHookRemote) rangeCalls() []dlCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]dlCall(nil), h.calls...)
}

func (h *dlHookRemote) doneBytes() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.done
}

// usesDD mirrors the range-read primitive choice of the remote layer on a
// target whose probe selected dd: a whole block on the grid, or the tail of the
// file starting on the grid, is read with dd; every other range with
// tail and head.
func (c dlCall) usesDD() bool {
	g := c.grid
	return g > 0 && g <= 64<<20 && c.part.Off%g == 0 && (c.part.Len == g || (c.part.Len < g && c.part.End() == c.fileSize))
}

// downloadRig is the upload rig (root, sandbox, exec fixture, fault proxy)
// with the download hooks in front of its chunk layer.
type downloadRig struct {
	*uploadRig
	hook *dlHookRemote
}

func newDownloadRig(t *testing.T) *downloadRig {
	t.Helper()
	up := newUploadRig(t)
	return &downloadRig{uploadRig: up, hook: &dlHookRemote{ChunkRemote: up.remote, diag: up.remote.diag}}
}

// engine returns an engine with an empty link profile: a new keeper process.
func (r *downloadRig) engine() *transferengine.Engine {
	r.t.Helper()
	engine, err := transferengine.NewWithOptions(r.hook, r.limits, transferengine.Options{Target: targetName})
	if err != nil {
		r.t.Fatal(err)
	}
	return engine
}

// source writes the remote source file into the sandbox and returns its path.
func (r *downloadRig) source(name string, payload []byte) string {
	r.t.Helper()
	path := filepath.Join(r.dir("src"), name)
	writeFile(r.t, path, payload)
	return path
}

// localDir creates a directory under the root and returns its path.
func (r *downloadRig) localDir(name string) string {
	r.t.Helper()
	path := filepath.Join(r.rootDir, name)
	mkdirAll(r.t, path)
	return path
}

func (r *downloadRig) download(engine *transferengine.Engine, remotePath, local string) (transferengine.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), uploadDeadline)
	defer cancel()
	r.hook.diag.Start(fixture.RigDownload)
	res, err := engine.Download(ctx, r.root, remotePath, local, false, nil)
	r.hook.diag.Drain(r.t, r.server, res, err)
	return res, err
}

// cutNextDown cuts the next connection after exactly n server-to-client bytes.
func (r *downloadRig) cutNextDown(n int64) {
	r.hook.diag.ArmProxy(r.t, faultproxy.ServerToClient, n, false, false)
}

// cutFromDown cuts every connection from the next one on after n
// server-to-client bytes; control sessions carry less than that and pass,
// payload sessions do not.
func (r *downloadRig) cutFromDown(n int64) {
	r.hook.diag.ArmProxy(r.t, faultproxy.ServerToClient, n, true, false)
}

// assertDownloaded requires the destination to hold exactly payload and the
// result to describe it.
func assertDownloaded(t *testing.T, res transferengine.Result, dest string, payload []byte) {
	t.Helper()
	assertUploaded(t, res, dest, payload)
}

// assertSourceUntouched requires the remote source to be the payload.
func assertSourceUntouched(t *testing.T, src string, payload []byte) {
	t.Helper()
	if !bytes.Equal(readFile(t, src), payload) {
		t.Fatal("the remote source was modified")
	}
}

// strandDownload runs a download that ends as link_unstable with its staging
// kept: the first stream is cut, the first part gets through, then every
// further range session is cut. It returns the local staging directory.
func (r *downloadRig) strandDownload(remotePath, local string) string {
	r.t.Helper()
	r.hook.reset()
	r.hook.onStream = func(n int) {
		if n == 1 {
			r.cutNextDown(streamCutDown)
		}
	}
	r.hook.onRange = func(n int, part transferlink.Range) {
		if n == 2 {
			r.cutFromDown(strandedCutDown)
		}
	}
	res, err := r.download(r.engine(), remotePath, local)
	r.hook.reset()
	r.clearFaults()
	var failure *transfercore.Error
	require(r.t, errors.As(err, &failure), "expected a typed error for the stranded download")
	require(r.t, failure.Class == transfercore.ClassLinkUnstable, "stranded download must report link_unstable")
	require(r.t, failure.Message == transfercore.MsgLinkUnstable, "stranded download must return the standard link_unstable message")
	require(r.t, res.Mode == transferengine.ModeChunked, "stranded download must be in chunked mode")
	require(r.t, res.ChunksDone >= 1, "stranded download must complete at least one chunk")
	require(r.t, res.Attempts >= 1+1+transferlink.MaxNoProgress, "expected stream, successful range, and a full no-progress retry budget")
	dest := filepath.Join(r.rootDir, filepath.FromSlash(local))
	if exists(dest) {
		r.t.Fatal("a stranded download published the destination")
	}
	staging := findStaging(r.t, filepath.Dir(dest))
	info, statErr := os.Stat(staging)
	require(r.t, statErr == nil, "could not stat stranded staging")
	require(r.t, info.Mode().Perm() == 0o700, "stranded staging permissions must be 0700")
	if got := string(readFile(r.t, filepath.Join(staging, "marker"))); !strings.HasPrefix(got, "SSJACK-STAGING 1 ") {
		r.t.Fatal("stranded staging marker lacks the expected prefix")
	}
	parts := stagedParts(r.t, staging)
	require(r.t, len(parts) >= 1, "stranded staging must retain at least one part")
	require(r.t, int64(res.ChunksDone) == int64(len(parts)), "completed chunk count must match retained part count")
	return staging
}

// ScenarioChunkDownloadStreamDrop cuts the stream of a large download at an
// exact server-to-client byte: the job must continue in chunked mode on its
// own and publish the file byte-exact, with nothing else left next to it.
func ScenarioChunkDownloadStreamDrop(t *testing.T) {
	rig := newDownloadRig(t)
	payload := fixture.SeedPayload(downloadPayload, 71)
	src := rig.source("blob.bin", payload)
	parent := rig.localDir("got")
	dest := filepath.Join(parent, "blob.bin")
	rig.hook.onStream = func(n int) {
		if n == 1 {
			rig.cutNextDown(streamCutDown)
		}
	}

	res, err := rig.download(rig.engine(), src, "got/blob.bin")
	if err != nil {
		t.Fatal("download failed after the stream drop")
	}
	assertDownloaded(t, res, dest, payload)
	require(t, res.Mode == transferengine.ModeChunked, "expected chunked mode after the stream drop")
	require(t, res.ChunksDone >= 2, "expected at least two completed chunks")
	require(t, res.ChunksTotal == res.ChunksDone, "total chunk count must equal completed chunks")
	require(t, res.Attempts >= 1+res.ChunksDone+1, "attempt count must cover stream, completed chunks, and assembly")
	require(t, res.BytesPerSecond > 0, "expected positive throughput")
	require(t, res.ChunkBytes > 0, "expected a positive chunk size")
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
	assertSourceUntouched(t, src, payload)
	streams, stats, ranges := rig.hook.counts()
	require(t, streams == 1, "expected exactly one stream session")
	require(t, ranges == res.ChunksDone, "range read count must match completed chunks")
	require(t, stats == ranges+2, "source stat count must cover every range, preflight, and the final look")
	// The first part starts at offset 0 with a whole block: dd.
	calls := rig.hook.rangeCalls()
	require(t, len(calls) > 0, "expected at least one range read after the stream drop")
	require(t, calls[0].part.Off == 0, "first range must start at offset zero")
	require(t, calls[0].usesDD(), "first range must use the dd grid primitive")
	cuts := cutConns(rig.proxy.Stats())
	require(t, len(cuts) == 1, "expected exactly one proxy byte cut")
	require(t, cuts[0].ServerToClient == streamCutDown, "cut must match the server-to-client stream threshold")
}

// ScenarioChunkDownloadDropMidChunk cuts the connection of the second range
// read in the middle of its payload: only that part is lost, the next attempt
// starts at the same gap and the published file is byte-exact.
func ScenarioChunkDownloadDropMidChunk(t *testing.T) {
	rig := newDownloadRig(t)
	payload := fixture.SeedPayload(downloadPayload, 72)
	src := rig.source("blob.bin", payload)
	parent := rig.localDir("got")
	dest := filepath.Join(parent, "blob.bin")
	rig.hook.onStream = func(n int) {
		if n == 1 {
			rig.cutNextDown(streamCutDown)
		}
	}
	rig.hook.onRange = func(n int, part transferlink.Range) {
		if n == 2 {
			rig.cutNextDown(partCutDown)
		}
	}

	res, err := rig.download(rig.engine(), src, "got/blob.bin")
	if err != nil {
		t.Fatal("download failed after the range drop")
	}
	assertDownloaded(t, res, dest, payload)
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
	assertSourceUntouched(t, src, payload)
	calls := rig.hook.rangeCalls()
	require(t, len(calls) >= 3, "expected at least three range reads")
	require(t, calls[1].part.Off == calls[0].part.End(), "second range must begin at the end of the first")
	require(t, calls[2].part.Off == calls[1].part.Off, "third range must retry the second range's offset")
	if res.ChunksDone != len(calls)-1 {
		t.Fatalf("%d parts done after %d range reads, want exactly one lost", res.ChunksDone, len(calls))
	}
	cuts := cutConns(rig.proxy.Stats())
	require(t, len(cuts) == 2, "expected exactly two proxy byte cuts")
	require(t, cuts[0].ServerToClient == streamCutDown, "first cut must match the server-to-client stream threshold")
	require(t, cuts[1].ServerToClient == partCutDown, "second cut must match the server-to-client part threshold")
}

// ScenarioChunkDownloadDropDuringAssembly cuts the transport of the last look
// at the remote source, the one between the last part and the local assembly.
// A single drop is retried inside the job; a link that keeps dropping it ends
// the job as link_unstable with all parts intact, and a second call from a new
// engine reassembles from the parts and publishes once.
func ScenarioChunkDownloadDropDuringAssembly(t *testing.T) {
	// finalLook reports whether the next look at the source is the one after
	// the last part: every byte was read successfully.
	finalLook := func(rig *downloadRig) bool { return rig.hook.doneBytes() == downloadPayload }

	t.Run("one drop", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 73)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.cutNextDown(streamCutDown)
			}
		}
		cutOnce := true
		rig.hook.onStat = func(n int) {
			if finalLook(rig) && cutOnce {
				cutOnce = false
				rig.cutNextDown(handshakeCutDown)
			}
		}

		res, err := rig.download(rig.engine(), src, "got/blob.bin")
		if err != nil {
			t.Fatal("download failed after one assembly drop")
		}
		assertDownloaded(t, res, dest, payload)
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		if cutOnce {
			t.Fatal("the final look at the source was never reached")
		}
		_, stats, ranges := rig.hook.counts()
		if stats != ranges+3 {
			t.Fatalf("%d source looks for %d range reads, want the preflight, one per part, the dropped look and its retry", stats, ranges)
		}
		require(t, res.Mode == transferengine.ModeChunked, "assembly retry must report chunked mode")
		require(t, res.Attempts == 1+ranges+2, "expected one stream attempt, one per range, and two assembly attempts")
	})
	t.Run("every drop then a new engine", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 74)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.cutNextDown(streamCutDown)
			}
		}
		rig.hook.onStat = func(n int) {
			if finalLook(rig) {
				rig.cutNextDown(handshakeCutDown)
			}
		}

		res, err := rig.download(rig.engine(), src, "got/blob.bin")
		rig.clearFaults()
		requireClass(t, err, transfercore.ClassLinkUnstable)
		_, stats, ranges := rig.hook.counts()
		if stats != ranges+1+transferlink.MaxNoProgress {
			t.Fatalf("%d source looks for %d range reads, want the preflight, one per part and %d dropped looks", stats, ranges, transferlink.MaxNoProgress)
		}
		require(t, res.Mode == transferengine.ModeChunked, "stranded assembly must report chunked mode")
		require(t, res.Bytes == int64(len(payload)), "stranded assembly must retain every verified payload byte")
		if exists(dest) {
			t.Fatal("a failed assembly published the destination")
		}
		staging := findStaging(t, parent)
		parts := stagedParts(t, staging)
		if err := transferlink.ValidateTiling(int64(len(payload)), parts); err != nil {
			t.Fatal("retained parts no longer tile the payload")
		}

		rig.hook.reset()
		res, err = rig.download(rig.engine(), src, "got/blob.bin")
		if err != nil {
			t.Fatal("second download failed after the assembly drops")
		}
		assertDownloaded(t, res, dest, payload)
		streams, stats, sent := rig.hook.counts()
		require(t, streams == 0, "assembly retry must not open a stream")
		require(t, sent == 0, "assembly retry must not reread ranges")
		require(t, stats == 2, "assembly retry must stat the source exactly twice")
		if exists(staging) {
			t.Fatal("the second call left the staging behind")
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
	})
}

// ScenarioChunkDownloadResumeByNewEngine strands a download as link_unstable
// and finishes it with a brand-new engine that has no link profile: the new
// call continues from the parts on disk, without a second stream. A second
// case resumes from parts that are off the chunk grid, which only the tail and
// head primitive can read.
func ScenarioChunkDownloadResumeByNewEngine(t *testing.T) {
	t.Run("after link_unstable", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 75)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		staging := rig.strandDownload(src, "got/blob.bin")
		before := stagedParts(t, staging)

		res, err := rig.download(rig.engine(), src, "got/blob.bin")
		if err != nil {
			t.Fatal("download resume by a new engine failed")
		}
		assertDownloaded(t, res, dest, payload)
		streams, _, ranges := rig.hook.counts()
		require(t, streams == 0, "resume must not open a stream")
		require(t, ranges != 0, "resume must read at least one range")
		gaps, err := transferlink.Gaps(int64(len(payload)), before)
		require(t, err == nil, "could not compute gaps in stranded parts")
		require(t, len(gaps) != 0, "stranded parts must have at least one gap")
		if first := rig.hook.rangeCalls()[0]; first.part.Off != gaps[0].Off {
			t.Fatalf("resume started at %d, want the first gap at %d", first.part.Off, gaps[0].Off)
		}
		require(t, res.Mode == transferengine.ModeChunked, "resumed download must report chunked mode")
		require(t, res.ChunksDone >= len(before), "completed chunk count must cover retained parts")
		if exists(staging) {
			t.Fatal("the resumed download left its staging behind")
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
	})
	t.Run("parts off the grid", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 76)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		info, err := os.Stat(src)
		if err != nil {
			t.Fatal(err)
		}
		// Parts as an earlier process left them: the largest is 256 KiB, so the
		// resumed job reads with a 256 KiB grid, and the first gap starts at
		// 356 KiB, off that grid.
		key := transferremote.StagingKey(targetName, src, "got/blob.bin",
			strconv.FormatInt(int64(len(payload)), 10), strconv.FormatInt(info.ModTime().Unix(), 10))
		staging, state, err := rig.root.OpenChunkStaging("got/blob.bin", key, sha256.Sum256(payload), false, true)
		require(t, err == nil, "opening chunk staging failed")
		require(t, state == transferlocal.ChunkCreated, "expected newly created chunk staging")
		for _, p := range []transferlink.Range{{Off: 0, Len: 256 << 10}, {Off: 256 << 10, Len: 100 << 10}} {
			w, err := staging.CreatePart(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(payload[p.Off:p.End()]); err != nil {
				t.Fatal(err)
			}
			if err := w.Commit(); err != nil {
				t.Fatal(err)
			}
		}

		res, err := rig.download(rig.engine(), src, "got/blob.bin")
		if err != nil {
			t.Fatal("download resume from off-grid parts failed")
		}
		assertDownloaded(t, res, dest, payload)
		streams, _, _ := rig.hook.counts()
		calls := rig.hook.rangeCalls()
		require(t, streams == 0, "off-grid resume must not open a stream")
		require(t, len(calls) != 0, "off-grid resume must read at least one range")
		first := calls[0]
		require(t, first.part.Off == 356<<10, "first off-grid range must start at 356 KiB")
		require(t, !first.usesDD(), "first off-grid range must not use dd")
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
	})
}

// ScenarioChunkDownloadSourceChanged covers a remote source that changes
// between attempts (the new call derives another staging and never mixes
// versions) and in the middle of a transfer (integrity, staging removed).
func ScenarioChunkDownloadSourceChanged(t *testing.T) {
	t.Run("between attempts", func(t *testing.T) {
		rig := newDownloadRig(t)
		oldPayload := fixture.SeedPayload(downloadPayload, 77)
		src := rig.source("blob.bin", oldPayload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		staging := rig.strandDownload(src, "got/blob.bin")
		stranded := describe(t, staging)

		newPayload := fixture.SeedPayload(downloadPayload, 78)
		must(t, os.WriteFile(src, newPayload, 0o600))
		later := time.Now().Add(2 * time.Hour)
		must(t, os.Chtimes(src, later, later))
		res, err := rig.download(rig.engine(), src, "got/blob.bin")
		if err != nil {
			t.Fatalf("download of the changed source: %v", err)
		}
		assertDownloaded(t, res, dest, newPayload)
		if bytes.Equal(readFile(t, dest), oldPayload) {
			t.Fatal("the destination holds the old version")
		}
		if got := describe(t, staging); got != stranded {
			t.Fatal("the staging of the old version was reused or modified")
		}
		if names := entryNames(t, parent); len(names) != 2 {
			t.Fatalf("destination directory holds %q, want the file and the stale staging", names)
		}
	})
	t.Run("mid transfer", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 79)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.cutNextDown(streamCutDown)
			}
		}
		rig.hook.onRange = func(n int, part transferlink.Range) {
			if n != 2 {
				return
			}
			file, err := os.OpenFile(src, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Errorf("open source: %v", err)
				return
			}
			if _, err := file.WriteString("appended"); err != nil {
				t.Errorf("append: %v", err)
			}
			must(t, file.Close())
		}

		_, err := rig.download(rig.engine(), src, "got/blob.bin")
		requireClass(t, err, transfercore.ClassIntegrity)
		if exists(dest) {
			t.Fatal("a changed source was published")
		}
		assertOnlyEntries(t, parent)
		rig.assertNoStaging(parent)
		if _, _, ranges := rig.hook.counts(); ranges != 2 {
			t.Fatalf("%d range reads, want 2 (the change is caught before part 3)", ranges)
		}
	})
}

// ScenarioChunkDownloadStaleStagingCollected shows that a later transfer into
// the same local directory collects idle marked staging and touches nothing
// else.
func ScenarioChunkDownloadStaleStagingCollected(t *testing.T) {
	rig := newDownloadRig(t)
	payload := fixture.SeedPayload(48<<10, 80)
	src := rig.source("small.bin", payload)
	parent := rig.localDir("gc parent")
	stale := 72 * time.Hour
	young := 22 * time.Hour
	var sum [32]byte

	// mk creates a keyed staging directory through the real local layer and
	// ages its marker.
	mk := func(label string, age time.Duration) (string, string) {
		t.Helper()
		key := transferremote.StagingKey("download-gc", label)
		staging, state, err := rig.root.OpenChunkStaging("gc parent/small.bin", key, sum, false, true)
		require(t, err == nil, "opening stale-staging test directory failed")
		require(t, state == transferlocal.ChunkCreated, "expected newly created stale-staging test directory")
		_ = staging
		dir := filepath.Join(parent, ".ssjack-transfer-"+key)
		marker := filepath.Join(dir, "marker")
		old := time.Now().Add(-age)
		must(t, os.Chtimes(marker, old, old))
		writeFile(t, filepath.Join(dir, "part-0-1"), []byte("x"))
		return dir, key
	}

	var removed, kept []string
	for _, label := range []string{"stale-a", "stale-b"} {
		dir, _ := mk(label, stale)
		removed = append(removed, dir)
	}
	{
		dir, _ := mk("young", young)
		kept = append(kept, dir)
	}
	{
		// Same name pattern and an old marker, but a foreign mode.
		dir, _ := mk("mode-0755", stale)
		must(t, os.Chmod(dir, 0o755))
		kept = append(kept, dir)
	}
	{
		// A link at a keyed name, pointing at a real staging directory.
		target, _ := mk("link-target", young)
		key := transferremote.StagingKey("download-gc", "link")
		link := filepath.Join(parent, ".ssjack-transfer-"+key)
		must(t, os.Symlink(target, link))
		kept = append(kept, target, link)
	}
	{
		// A keyed name without a marker.
		key := transferremote.StagingKey("download-gc", "unmarked")
		dir := filepath.Join(parent, ".ssjack-transfer-"+key)
		must(t, os.Mkdir(dir, 0o700))
		writeFile(t, filepath.Join(dir, "part-0-1"), []byte("x"))
		old := time.Now().Add(-stale)
		must(t, os.Chtimes(dir, old, old))
		kept = append(kept, dir)
	}
	{
		// A one-shot staging name is never collected.
		dir := filepath.Join(parent, ".ssjack-transfer-0123456789ab")
		must(t, os.Mkdir(dir, 0o700))
		marker := filepath.Join(dir, "marker")
		writeFile(t, marker, []byte("SSJACK-STAGING 1 0123456789ab\n"))
		old := time.Now().Add(-stale)
		must(t, os.Chtimes(marker, old, old))
		kept = append(kept, dir)
	}
	before := map[string]string{}
	for _, d := range kept {
		before[d] = describe(t, d)
	}

	dest := filepath.Join(parent, "small.bin")
	res, err := rig.download(rig.engine(), src, "gc parent/small.bin")
	if err != nil {
		t.Fatalf("download into a directory with stale staging: %v", err)
	}
	assertDownloaded(t, res, dest, payload)
	for _, d := range removed {
		if exists(d) {
			t.Fatalf("idle staging %q survived the later transfer", filepath.Base(d))
		}
	}
	for _, d := range kept {
		if got := describe(t, d); got != before[d] {
			t.Fatal("kept staging changed")
		}
	}
	if want := len(kept) + 1; len(entryNames(t, parent)) != want {
		t.Fatalf("parent holds %q, want the download and %d kept directories", entryNames(t, parent), len(kept))
	}
	streams, _, ranges := rig.hook.counts()
	require(t, streams == 1, "small download must open exactly one stream")
	require(t, ranges == 0, "small download must not read any ranges")
}

// The stall scenario of the chunked download is the mirror of the upload one
// (chunk_upload.go): the same rig and the same short inactivity limit,
// with the freeze on the SERVER to CLIENT direction, which is where the payload
// of a download travels.

// stallEngine returns an engine with an empty link profile and the given stall
// limit, over the hooked chunk layer of the download rig.
func (r *downloadRig) stallEngine(limit time.Duration) *transferengine.Engine {
	r.t.Helper()
	engine, err := transferengine.NewWithOptions(r.hook, r.limits, transferengine.Options{Target: targetName, StallLimit: limit})
	if err != nil {
		r.t.Fatal(err)
	}
	return engine
}

// stallNextDown freezes the next connection after exactly n server-to-client
// bytes: the socket stays open and nothing more crosses it.
func (r *downloadRig) stallNextDown(n int64) {
	r.hook.diag.ArmProxy(r.t, faultproxy.ServerToClient, n, false, true)
}

// ScenarioChunkDownloadStallDetectedAndResumed freezes a connection mid-payload
// without closing it: no byte moves and no reset arrives, so only the stall
// watchdog can notice. With a short inactivity limit the stalled session is
// counted as a drop and the job goes on chunked and publishes byte-exact, for
// the whole-stream attempt and for a range read alike.
func ScenarioChunkDownloadStallDetectedAndResumed(t *testing.T) {
	t.Run("stalled stream", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 81)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.stallNextDown(streamCutDown)
			}
		}

		start := time.Now()
		res, err := rig.download(rig.stallEngine(stallScenarioLimit), src, "got/blob.bin")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal("download failed after the stream stall")
		}
		assertDownloaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("download finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		require(t, res.Mode == transferengine.ModeChunked, "expected chunked mode after the stream stall")
		require(t, res.ChunksDone >= 2, "expected at least two completed chunks")
		require(t, res.ChunksTotal == res.ChunksDone, "total chunk count must equal completed chunks")
		require(t, res.Attempts >= 1+res.ChunksDone+1, "attempt count must cover stream, completed chunks, and assembly")
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
		streams, stats, ranges := rig.hook.counts()
		require(t, streams == 1, "expected exactly one stream session")
		require(t, ranges == res.ChunksDone, "range read count must match completed chunks")
		require(t, stats == ranges+2, "source stat count must cover every range, preflight, and the final look")
		proxyStats := rig.proxy.Stats()
		stalled := stalledConns(proxyStats)
		require(t, len(stalled) == 1, "expected exactly one stalled proxy connection")
		require(t, stalled[0].ServerToClient == streamCutDown, "stall must match the server-to-client stream threshold")
		require(t, proxyStats.Dropped == 0, "expected no proxy drops during the stream stall")
	})
	t.Run("stalled part", func(t *testing.T) {
		rig := newDownloadRig(t)
		payload := fixture.SeedPayload(downloadPayload, 82)
		src := rig.source("blob.bin", payload)
		parent := rig.localDir("got")
		dest := filepath.Join(parent, "blob.bin")
		rig.hook.onStream = func(n int) {
			if n == 1 {
				rig.cutNextDown(streamCutDown)
			}
		}
		rig.hook.onRange = func(n int, part transferlink.Range) {
			if n == 2 {
				rig.stallNextDown(partCutDown)
			}
		}

		start := time.Now()
		res, err := rig.download(rig.stallEngine(stallScenarioLimit), src, "got/blob.bin")
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal("download failed after the range stall")
		}
		assertDownloaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("download finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
		calls := rig.hook.rangeCalls()
		require(t, len(calls) >= 3, "expected at least three range reads")
		require(t, calls[1].part.Off == calls[0].part.End(), "second range must begin at the end of the first")
		require(t, calls[2].part.Off == calls[1].part.Off, "third range must retry the second range's offset")
		require(t, res.Mode == transferengine.ModeChunked, "expected chunked mode after the range stall")
		require(t, res.ChunksDone == len(calls)-1, "completed chunks must exclude exactly one stalled range read")
		proxyStats := rig.proxy.Stats()
		stalled := stalledConns(proxyStats)
		require(t, len(stalled) == 1, "expected exactly one stalled proxy connection")
		require(t, stalled[0].ServerToClient == partCutDown, "stall must match the server-to-client part threshold")
		cuts := cutConns(proxyStats)
		require(t, len(cuts) == 1, "expected exactly one proxy byte cut")
		require(t, cuts[0].ServerToClient == streamCutDown, "cut must match the server-to-client stream threshold")
	})
}
