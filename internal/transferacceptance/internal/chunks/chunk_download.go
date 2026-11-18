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
	if hook != nil {
		hook(n)
	}
	return h.ChunkRemote.ReadFile(ctx, path, dst)
}

func (h *dlHookRemote) StatSource(ctx context.Context, path string) (transferremote.SourceStat, error) {
	h.mu.Lock()
	h.stats++
	n, hook := h.stats, h.onStat
	h.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return h.ChunkRemote.StatSource(ctx, path)
}

func (h *dlHookRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	h.mu.Lock()
	h.calls = append(h.calls, dlCall{part: part, grid: grid, fileSize: fileSize})
	n, hook := len(h.calls), h.onRange
	h.mu.Unlock()
	if hook != nil {
		hook(n, part)
	}
	got, err := h.ChunkRemote.ReadRange(ctx, path, part, grid, fileSize, dst)
	if err == nil {
		h.mu.Lock()
		h.done += part.Len
		h.mu.Unlock()
	}
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
	return &downloadRig{uploadRig: up, hook: &dlHookRemote{ChunkRemote: up.remote}}
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
	res, err := engine.Download(ctx, r.root, remotePath, local, false, nil)
	// A remote command of a cut connection may still be finishing; wait for it
	// before anyone looks at the sandbox.
	r.server.WaitIdle(r.t)
	return res, err
}

// cutNextDown cuts the next connection after exactly n server-to-client bytes.
func (r *downloadRig) cutNextDown(n int64) {
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.Conns(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.DropAfterBytes(faultproxy.ServerToClient, n)},
	})
}

// cutFromDown cuts every connection from the next one on after n
// server-to-client bytes; control sessions carry less than that and pass,
// payload sessions do not.
func (r *downloadRig) cutFromDown(n int64) {
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.FromConn(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.DropAfterBytes(faultproxy.ServerToClient, n)},
	})
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
	if !errors.As(err, &failure) || failure.Class != transfercore.ClassLinkUnstable || failure.Message != transfercore.MsgLinkUnstable {
		r.t.Fatalf("stranded download = %+v, %v; want link_unstable", res, err)
	}
	if res.Mode != transferengine.ModeChunked || res.ChunksDone < 1 || res.Attempts < 1+1+transferlink.MaxNoProgress {
		r.t.Fatalf("stranded result = %+v", res)
	}
	dest := filepath.Join(r.rootDir, filepath.FromSlash(local))
	if exists(dest) {
		r.t.Fatal("a stranded download published the destination")
	}
	staging := findStaging(r.t, filepath.Dir(dest))
	if info, err := os.Stat(staging); err != nil || info.Mode().Perm() != 0o700 {
		r.t.Fatalf("stranded staging is not a private directory: %v %v", info, err)
	}
	if got := string(readFile(r.t, filepath.Join(staging, "marker"))); !strings.HasPrefix(got, "SSJACK-STAGING 1 ") {
		r.t.Fatalf("stranded staging has no marker: %q", got)
	}
	parts := stagedParts(r.t, staging)
	if len(parts) < 1 || int64(res.ChunksDone) != int64(len(parts)) {
		r.t.Fatalf("stranded staging holds %v, result says %d parts", parts, res.ChunksDone)
	}
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
		t.Fatalf("download after a dropped stream: %v", err)
	}
	assertDownloaded(t, res, dest, payload)
	if res.Mode != transferengine.ModeChunked || res.ChunksDone < 2 || res.ChunksTotal != res.ChunksDone || res.Attempts < 1+res.ChunksDone+1 {
		t.Fatalf("chunked telemetry = %+v", res)
	}
	if res.BytesPerSecond <= 0 || res.ChunkBytes <= 0 {
		t.Fatalf("telemetry has no speed or chunk size: %+v", res)
	}
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
	assertSourceUntouched(t, src, payload)
	streams, stats, ranges := rig.hook.counts()
	if streams != 1 || ranges != res.ChunksDone || stats != ranges+2 {
		t.Fatalf("sessions: %d streams, %d source looks, %d range reads; result %+v", streams, stats, ranges, res)
	}
	// The first part starts at offset 0 with a whole block: dd.
	calls := rig.hook.rangeCalls()
	if calls[0].part.Off != 0 || !calls[0].usesDD() {
		t.Fatalf("first range read = %+v, want a whole block at offset 0", calls[0])
	}
	cuts := cutConns(rig.proxy.Stats())
	if len(cuts) != 1 || cuts[0].ServerToClient != streamCutDown {
		t.Fatalf("cut connections = %+v, want exactly one cut at %d bytes server to client", cuts, streamCutDown)
	}
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
		t.Fatalf("download with a part cut in the middle: %v", err)
	}
	assertDownloaded(t, res, dest, payload)
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
	assertSourceUntouched(t, src, payload)
	calls := rig.hook.rangeCalls()
	if len(calls) < 3 || calls[1].part.Off != calls[0].part.End() || calls[2].part.Off != calls[1].part.Off {
		t.Fatalf("range reads = %v, want the cut part read again from its own offset", calls)
	}
	if res.ChunksDone != len(calls)-1 {
		t.Fatalf("%d parts done after %d range reads, want exactly one lost", res.ChunksDone, len(calls))
	}
	cuts := cutConns(rig.proxy.Stats())
	if len(cuts) != 2 || cuts[0].ServerToClient != streamCutDown || cuts[1].ServerToClient != partCutDown {
		t.Fatalf("cut connections = %+v, want the stream at %d and a part at %d", cuts, streamCutDown, partCutDown)
	}
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
			t.Fatalf("download with one assembly drop: %v", err)
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
		if res.Mode != transferengine.ModeChunked || res.Attempts != 1+ranges+2 {
			t.Fatalf("result = %+v, want the stream, %d parts and two assembly attempts", res, ranges)
		}
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
		if res.Mode != transferengine.ModeChunked || res.Bytes != int64(len(payload)) {
			t.Fatalf("stranded result = %+v, want every byte verified in parts", res)
		}
		if exists(dest) {
			t.Fatal("a failed assembly published the destination")
		}
		staging := findStaging(t, parent)
		parts := stagedParts(t, staging)
		if err := transferlink.ValidateTiling(int64(len(payload)), parts); err != nil {
			t.Fatalf("the parts did not stay intact: %v", err)
		}

		rig.hook.reset()
		res, err = rig.download(rig.engine(), src, "got/blob.bin")
		if err != nil {
			t.Fatalf("second call after the assembly drops: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		streams, stats, sent := rig.hook.counts()
		if streams != 0 || sent != 0 || stats != 2 {
			t.Fatalf("second call ran %d streams, %d range reads, %d source looks; want only the preflight and the final look", streams, sent, stats)
		}
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
			t.Fatalf("resume by a new engine: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		streams, _, ranges := rig.hook.counts()
		if streams != 0 || ranges == 0 {
			t.Fatalf("resume ran %d streams, %d range reads", streams, ranges)
		}
		gaps, err := transferlink.Gaps(int64(len(payload)), before)
		if err != nil || len(gaps) == 0 {
			t.Fatalf("gaps of the stranded parts: %v, %v", gaps, err)
		}
		if first := rig.hook.rangeCalls()[0]; first.part.Off != gaps[0].Off {
			t.Fatalf("resume started at %d, want the first gap at %d", first.part.Off, gaps[0].Off)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone < len(before) {
			t.Fatalf("resumed result = %+v", res)
		}
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
		if err != nil || state != transferlocal.ChunkCreated {
			t.Fatalf("OpenChunkStaging = %v, %v", state, err)
		}
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
			t.Fatalf("resume from parts off the grid: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		streams, _, _ := rig.hook.counts()
		calls := rig.hook.rangeCalls()
		if streams != 0 || len(calls) == 0 {
			t.Fatalf("resume ran %d streams and %d range reads", streams, len(calls))
		}
		if first := calls[0]; first.part.Off != 356<<10 || first.usesDD() {
			t.Fatalf("first range read = %+v, want one off the grid, read with tail and head", first)
		}
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
		if err != nil || state != transferlocal.ChunkCreated {
			t.Fatalf("OpenChunkStaging(%s) = %v, %v", label, state, err)
		}
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
			t.Fatalf("%q was modified or removed:\nbefore: %s\nafter: %s", filepath.Base(d), before[d], got)
		}
	}
	if want := len(kept) + 1; len(entryNames(t, parent)) != want {
		t.Fatalf("parent holds %q, want the download and %d kept directories", entryNames(t, parent), len(kept))
	}
	if streams, _, ranges := rig.hook.counts(); streams != 1 || ranges != 0 {
		t.Fatalf("a small download ran %d streams and %d range reads, want one whole stream", streams, ranges)
	}
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
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.Conns(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.StallAfterBytes(faultproxy.ServerToClient, n)},
	})
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
			t.Fatalf("download after a stalled stream: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("download finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone < 2 || res.ChunksTotal != res.ChunksDone || res.Attempts < 1+res.ChunksDone+1 {
			t.Fatalf("chunked telemetry = %+v", res)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
		streams, stats, ranges := rig.hook.counts()
		if streams != 1 || ranges != res.ChunksDone || stats != ranges+2 {
			t.Fatalf("sessions: %d streams, %d source looks, %d range reads; result %+v", streams, stats, ranges, res)
		}
		proxyStats := rig.proxy.Stats()
		stalled := stalledConns(proxyStats)
		if len(stalled) != 1 || stalled[0].ServerToClient != streamCutDown || proxyStats.Dropped != 0 {
			t.Fatalf("proxy stats = %+v, want exactly one connection frozen at %d bytes and none cut", proxyStats, streamCutDown)
		}
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
			t.Fatalf("download with a stalled part: %v", err)
		}
		assertDownloaded(t, res, dest, payload)
		if elapsed < stallScenarioLimit {
			t.Fatalf("download finished in %s, before the %s inactivity limit could have fired", elapsed, stallScenarioLimit)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		assertSourceUntouched(t, src, payload)
		calls := rig.hook.rangeCalls()
		if len(calls) < 3 || calls[1].part.Off != calls[0].part.End() || calls[2].part.Off != calls[1].part.Off {
			t.Fatalf("range reads = %v, want the stalled part read again from its own offset", calls)
		}
		if res.Mode != transferengine.ModeChunked || res.ChunksDone != len(calls)-1 {
			t.Fatalf("%d parts done after %d range reads, want exactly the stalled one lost (%+v)", res.ChunksDone, len(calls), res)
		}
		proxyStats := rig.proxy.Stats()
		stalled := stalledConns(proxyStats)
		if len(stalled) != 1 || stalled[0].ServerToClient != partCutDown {
			t.Fatalf("proxy stats = %+v, want exactly one part connection frozen at %d bytes", proxyStats, partCutDown)
		}
		cuts := cutConns(proxyStats)
		if len(cuts) != 1 || cuts[0].ServerToClient != streamCutDown {
			t.Fatalf("cut connections = %+v, want only the stream, cut at %d bytes", cuts, streamCutDown)
		}
	})
}
