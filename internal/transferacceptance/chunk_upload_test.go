//go:build linux || darwin

package transferacceptance

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/faultproxy"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// The chunked upload scenarios drive the Engine directly over the real
// exec fixture (GNU, BusyBox applets or stock macOS tools), with the SSH
// client dialing a fault-injecting proxy. A thin wrapper around the real
// chunk layer arms an exact byte-count cut on the very next connection just
// before a chosen session starts, so every fault lands on a known session
// with no sleeping and no timing assumption. Payloads are large enough that
// the SSH window and socket buffers cannot hold the rest of the file when a
// stream is cut, which is what makes the first drop select chunked mode.

const (
	uploadPayload  = 8 << 20
	streamCut      = 768 << 10 // exact client-to-server bytes of the cut stream
	partCut        = 192 << 10 // inside the payload of a part
	strandedCut    = 64 << 10  // below every part, above every control session
	uploadDeadline = 5 * time.Minute
)

// hookRemote wraps the real chunk layer and runs hooks before the stream,
// each part and each assembly session.
type hookRemote struct {
	transferremote.ChunkRemote

	mu         sync.Mutex
	streams    int
	partCalls  []transferlink.Range
	assembles  int
	onStream   func(n int)
	onPart     func(n int, part transferlink.Range)
	onAssemble func(n int)
}

func (h *hookRemote) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	h.mu.Lock()
	h.streams++
	n, hook := h.streams, h.onStream
	h.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return h.ChunkRemote.WriteFile(ctx, path, src, executable)
}

func (h *hookRemote) UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (transferremote.PartResult, error) {
	h.mu.Lock()
	h.partCalls = append(h.partCalls, part)
	n, hook := len(h.partCalls), h.onPart
	h.mu.Unlock()
	if hook != nil {
		hook(n, part)
	}
	return h.ChunkRemote.UploadPart(ctx, parent, key, part, src)
}

func (h *hookRemote) AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (transferremote.Assembled, error) {
	h.mu.Lock()
	h.assembles++
	n, hook := h.assembles, h.onAssemble
	h.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return h.ChunkRemote.AssembleStaging(ctx, parent, key, parts, size, executable)
}

// reset zeroes the counters and removes the hooks, between phases.
func (h *hookRemote) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streams, h.assembles, h.partCalls = 0, 0, nil
	h.onStream, h.onPart, h.onAssemble = nil, nil, nil
}

func (h *hookRemote) counts() (streams, parts, assembles int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.streams, len(h.partCalls), h.assembles
}

func (h *hookRemote) ranges() []transferlink.Range {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]transferlink.Range(nil), h.partCalls...)
}

// uploadRig is a root, a sandbox behind an exec fixture, a fault proxy in
// front of it and the hooked chunk layer.
type uploadRig struct {
	t       *testing.T
	rootDir string
	sandbox string
	server  *ExecServer
	proxy   *faultproxy.Proxy
	remote  *hookRemote
	root    *transferlocal.Root
	limits  transfercore.Limits
}

func newUploadRig(t *testing.T) *uploadRig {
	t.Helper()
	limits := transfercore.DefaultLimits()
	rootDir, sandbox := evalDir(t), evalDir(t)
	server := StartExecServer(t, sandbox, sandboxEnv(t, nil))
	proxy := faultproxy.Start(t, server.Address())
	config := &ssh.ClientConfig{
		User:            "acceptance",
		Auth:            []ssh.AuthMethod{sshauth.PublicKey(server.ClientSigner())},
		HostKeyCallback: ssh.FixedHostKey(server.HostKey()),
		Timeout:         5 * time.Second,
	}
	runner, err := remote.NewCredentialStreamRunner(targetName, proxy.Addr(), config)
	if err != nil {
		t.Fatal(err)
	}
	root, err := transferlocal.ParseRoot(rootDir, "")
	if err != nil {
		t.Fatal(err)
	}
	return &uploadRig{
		t: t, rootDir: rootDir, sandbox: sandbox, server: server, proxy: proxy, root: root, limits: limits,
		remote: &hookRemote{ChunkRemote: transferremote.NewChunk(runner, targetName, limits)},
	}
}

// engine returns an engine with an empty link profile: a new keeper process.
func (r *uploadRig) engine() *transferengine.Engine {
	r.t.Helper()
	engine, err := transferengine.NewWithOptions(r.remote, r.limits, transferengine.Options{Target: targetName})
	if err != nil {
		r.t.Fatal(err)
	}
	return engine
}

func (r *uploadRig) dir(name string) string {
	path := filepath.Join(r.sandbox, name)
	mkdirAll(r.t, path)
	return path
}

// seed writes the source file under the root and returns its absolute path.
func (r *uploadRig) seed(rel string, payload []byte) string {
	WriteTree(r.t, r.rootDir, map[string][]byte{rel: payload}, []string{filepath.ToSlash(filepath.Dir(rel))})
	return filepath.Join(r.rootDir, filepath.FromSlash(rel))
}

func (r *uploadRig) upload(engine *transferengine.Engine, local, dest string) (transferengine.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), uploadDeadline)
	defer cancel()
	res, err := engine.Upload(ctx, r.root, local, dest, false, nil)
	// A remote command of a cut connection may still be finishing; wait for
	// it before anyone looks at the sandbox.
	r.server.WaitIdle(r.t)
	return res, err
}

// nextConn is the 1-based index the next accepted connection gets.
func (r *uploadRig) nextConn() int { return r.proxy.Stats().Accepted + 1 }

// cutNext cuts the next connection after exactly n client-to-server bytes.
func (r *uploadRig) cutNext(n int64) {
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.Conns(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.DropAfterBytes(faultproxy.ClientToServer, n)},
	})
}

// cutFrom cuts every connection from the next one on after n bytes; control
// sessions carry less than that and pass, payload sessions do not.
func (r *uploadRig) cutFrom(n int64) {
	r.proxy.MustSetRules(r.t, faultproxy.Rule{
		Conns:  faultproxy.FromConn(r.nextConn()),
		Faults: []faultproxy.Fault{faultproxy.DropAfterBytes(faultproxy.ClientToServer, n)},
	})
}

func (r *uploadRig) clearFaults() { r.proxy.MustSetRules(r.t) }

// disarmKill makes the fixture's kill rule match nothing.
func (r *uploadRig) disarmKill() { r.server.ArmKill("\x00no-such-command", 1) }

func cutConns(stats faultproxy.Stats) []faultproxy.ConnStats {
	var cuts []faultproxy.ConnStats
	for _, conn := range stats.Conns {
		if conn.Reason == faultproxy.ReasonBytes {
			cuts = append(cuts, conn)
		}
	}
	return cuts
}

func requireClass(t *testing.T, err error, class transfercore.Class) {
	t.Helper()
	var failure *transfercore.Error
	if !errors.As(err, &failure) || failure.Class != class {
		t.Fatalf("error = %v, want class %s", err, class)
	}
}

// assertOnlyEntries requires dir to hold exactly the named entries.
func assertOnlyEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := entryNames(t, dir)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s holds %q, want exactly %q", filepath.Base(dir), got, want)
	}
}

// assertUploaded requires the destination to hold exactly payload and the
// result to describe it.
func assertUploaded(t *testing.T, res transferengine.Result, dest string, payload []byte) {
	t.Helper()
	if !bytes.Equal(readFile(t, dest), payload) {
		t.Fatal("the published file is not byte-exact")
	}
	assertSHA(t, payload, res.SHA256)
	if res.Kind != transferengine.KindFile || res.Files != 1 || res.Bytes != int64(len(payload)) {
		t.Fatalf("result = %+v", res)
	}
}

func (r *uploadRig) assertNoStaging(parent string) {
	r.t.Helper()
	AssertNoStaging(r.t, parent)
	AssertNoStaging(r.t, r.sandbox)
	AssertNoStaging(r.t, r.rootDir)
}

// findStaging returns the single chunk staging directory of parent.
func findStaging(t *testing.T, parent string) string {
	t.Helper()
	var found []string
	for _, name := range entryNames(t, parent) {
		if strings.HasPrefix(name, ".ssjack-transfer-") {
			found = append(found, filepath.Join(parent, name))
		}
	}
	if len(found) != 1 {
		t.Fatalf("staging directories = %v, want exactly one", found)
	}
	return found[0]
}

// stagedParts reads the parts a staging directory holds, requiring every
// part to be as long as its name says.
func stagedParts(t *testing.T, dir string) []transferlink.Range {
	t.Helper()
	var parts []transferlink.Range
	for _, name := range entryNames(t, dir) {
		if !strings.HasPrefix(name, "part-") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		rng, err := transferlink.ParsePartName(name)
		if err != nil {
			t.Fatalf("staging holds the odd entry %q", name)
		}
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() != rng.Len {
			t.Fatalf("part %q has the wrong size", name)
		}
		parts = append(parts, rng)
	}
	return parts
}

// strandUpload runs an upload that ends as link_unstable with its staging
// kept: the first stream is cut, the first part gets through, then every further
// part session is cut. It returns the staging directory.
func (r *uploadRig) strandUpload(local, dest string) string {
	r.t.Helper()
	r.remote.reset()
	r.remote.onStream = func(n int) {
		if n == 1 {
			r.cutNext(streamCut)
		}
	}
	r.remote.onPart = func(n int, part transferlink.Range) {
		if n == 2 {
			r.cutFrom(strandedCut)
		}
	}
	res, err := r.upload(r.engine(), local, dest)
	r.remote.reset()
	r.clearFaults()
	var failure *transfercore.Error
	if !errors.As(err, &failure) || failure.Class != transfercore.ClassLinkUnstable || failure.Message != transfercore.MsgLinkUnstable {
		r.t.Fatalf("stranded upload = %+v, %v; want link_unstable", res, err)
	}
	if res.Mode != transferengine.ModeChunked || res.ChunksDone < 1 || res.Attempts < 1+1+transferlink.MaxNoProgress {
		r.t.Fatalf("stranded result = %+v", res)
	}
	if exists(dest) {
		r.t.Fatal("a stranded upload published the destination")
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

// scenarioChunkUploadStreamDrop cuts the stream of a large upload at an exact
// byte: the job must continue in chunked mode on its own and publish the
// file byte-exact, with nothing else left in the destination directory.
func scenarioChunkUploadStreamDrop(t *testing.T) {
	rig := newUploadRig(t)
	payload := SeedPayload(uploadPayload, 51)
	rig.seed("big/blob.bin", payload)
	parent := rig.dir("in")
	dest := parent + "/blob.bin"
	rig.remote.onStream = func(n int) {
		if n == 1 {
			rig.cutNext(streamCut)
		}
	}

	res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
	if err != nil {
		t.Fatalf("upload after a dropped stream: %v", err)
	}
	assertUploaded(t, res, dest, payload)
	if res.Mode != transferengine.ModeChunked || res.ChunksDone < 2 || res.ChunksTotal != res.ChunksDone || res.Attempts < 1+res.ChunksDone+1 {
		t.Fatalf("chunked telemetry = %+v", res)
	}
	if res.BytesPerSecond <= 0 || res.ChunkBytes <= 0 {
		t.Fatalf("telemetry has no speed or chunk size: %+v", res)
	}
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
	streams, parts, assembles := rig.remote.counts()
	if streams != 1 || parts != res.ChunksDone || assembles != 1 {
		t.Fatalf("sessions: %d streams, %d parts, %d assemblies; result %+v", streams, parts, assembles, res)
	}
	cuts := cutConns(rig.proxy.Stats())
	if len(cuts) != 1 || cuts[0].ClientToServer != streamCut {
		t.Fatalf("cut connections = %+v, want exactly one cut at %d bytes client to server", cuts, streamCut)
	}
}

// scenarioChunkUploadDropMidChunk cuts the connection of the second part in
// the middle of its payload: only that part is lost, the next attempt starts
// at the same gap and the published file is byte-exact.
func scenarioChunkUploadDropMidChunk(t *testing.T) {
	rig := newUploadRig(t)
	payload := SeedPayload(uploadPayload, 52)
	rig.seed("big/blob.bin", payload)
	parent := rig.dir("in")
	dest := parent + "/blob.bin"
	rig.remote.onStream = func(n int) {
		if n == 1 {
			rig.cutNext(streamCut)
		}
	}
	rig.remote.onPart = func(n int, part transferlink.Range) {
		if n == 2 {
			rig.cutNext(partCut)
		}
	}

	res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
	if err != nil {
		t.Fatalf("upload with a part cut in the middle: %v", err)
	}
	assertUploaded(t, res, dest, payload)
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
	ranges := rig.remote.ranges()
	if len(ranges) < 3 || ranges[1].Off != ranges[0].End() || ranges[2].Off != ranges[1].Off {
		t.Fatalf("part sessions = %v, want the cut part sent again from its own offset", ranges)
	}
	if res.ChunksDone != len(ranges)-1 {
		t.Fatalf("%d parts done after %d part sessions, want exactly one lost", res.ChunksDone, len(ranges))
	}
	cuts := cutConns(rig.proxy.Stats())
	if len(cuts) != 2 || cuts[0].ClientToServer != streamCut || cuts[1].ClientToServer != partCut {
		t.Fatalf("cut connections = %+v, want the stream at %d and a part at %d", cuts, streamCut, partCut)
	}
}

// scenarioChunkUploadDropDuringAssembly kills the transport while the
// assembly session is reading its part list. A single drop is retried inside
// the job; a link that keeps dropping every assembly ends the job as
// link_unstable with all parts intact, and a second call from a new engine
// reassembles into a new temporary name and publishes once.
func scenarioChunkUploadDropDuringAssembly(t *testing.T) {
	t.Run("one drop", func(t *testing.T) {
		rig := newUploadRig(t)
		payload := SeedPayload(uploadPayload, 53)
		rig.seed("big/blob.bin", payload)
		parent := rig.dir("in")
		dest := parent + "/blob.bin"
		rig.remote.onStream = func(n int) {
			if n == 1 {
				rig.cutNext(streamCut)
			}
		}
		rig.remote.onAssemble = func(n int) {
			if n == 1 {
				rig.server.ArmKill("assembled.", 1)
			} else {
				rig.disarmKill()
			}
		}

		res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
		if err != nil {
			t.Fatalf("upload with one assembly drop: %v", err)
		}
		assertUploaded(t, res, dest, payload)
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
		if _, _, assembles := rig.remote.counts(); assembles != 2 {
			t.Fatalf("%d assembly sessions, want the dropped one and its retry", assembles)
		}
	})
	t.Run("every drop then a new engine", func(t *testing.T) {
		rig := newUploadRig(t)
		payload := SeedPayload(uploadPayload, 54)
		rig.seed("big/blob.bin", payload)
		parent := rig.dir("in")
		dest := parent + "/blob.bin"
		rig.remote.onStream = func(n int) {
			if n == 1 {
				rig.cutNext(streamCut)
			}
		}
		rig.remote.onAssemble = func(n int) { rig.server.ArmKill("assembled.", 1) }

		res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
		rig.disarmKill()
		requireClass(t, err, transfercore.ClassLinkUnstable)
		if _, _, assembles := rig.remote.counts(); assembles != transferlink.MaxNoProgress {
			t.Fatalf("%d assembly sessions, want %d", assembles, transferlink.MaxNoProgress)
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

		rig.remote.reset()
		res, err = rig.upload(rig.engine(), "big/blob.bin", dest)
		if err != nil {
			t.Fatalf("second call after the assembly drops: %v", err)
		}
		assertUploaded(t, res, dest, payload)
		streams, sent, assembles := rig.remote.counts()
		if streams != 0 || sent != 0 || assembles != 1 {
			t.Fatalf("second call ran %d streams, %d parts, %d assemblies; want only the assembly", streams, sent, assembles)
		}
		assertOnlyEntries(t, parent, "blob.bin")
		rig.assertNoStaging(parent)
	})
}

// scenarioChunkUploadResumeByNewEngine strands an upload as link_unstable
// and finishes it with a brand-new engine that has no link profile: the new
// call continues from the parts on the remote side, without a second stream.
func scenarioChunkUploadResumeByNewEngine(t *testing.T) {
	rig := newUploadRig(t)
	payload := SeedPayload(uploadPayload, 55)
	rig.seed("big/blob.bin", payload)
	parent := rig.dir("in")
	dest := parent + "/blob.bin"
	staging := rig.strandUpload("big/blob.bin", dest)
	before := stagedParts(t, staging)

	res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
	if err != nil {
		t.Fatalf("resume by a new engine: %v", err)
	}
	assertUploaded(t, res, dest, payload)
	streams, parts, assembles := rig.remote.counts()
	if streams != 0 || parts == 0 || assembles != 1 {
		t.Fatalf("resume ran %d streams, %d parts, %d assemblies", streams, parts, assembles)
	}
	gaps, err := transferlink.Gaps(int64(len(payload)), before)
	if err != nil || len(gaps) == 0 {
		t.Fatalf("gaps of the stranded parts: %v, %v", gaps, err)
	}
	if first := rig.remote.ranges()[0]; first.Off != gaps[0].Off {
		t.Fatalf("resume started at %d, want the first gap at %d", first.Off, gaps[0].Off)
	}
	if res.Mode != transferengine.ModeChunked || res.ChunksDone < len(before) {
		t.Fatalf("resumed result = %+v", res)
	}
	if exists(staging) {
		t.Fatal("the resumed upload left its staging behind")
	}
	assertOnlyEntries(t, parent, "blob.bin")
	rig.assertNoStaging(parent)
}

// scenarioChunkUploadSourceChanged covers a source that changes between
// attempts (the new call derives another staging and never mixes versions)
// and in the middle of a transfer (integrity, staging removed).
func scenarioChunkUploadSourceChanged(t *testing.T) {
	t.Run("between attempts", func(t *testing.T) {
		rig := newUploadRig(t)
		oldPayload := SeedPayload(uploadPayload, 56)
		source := rig.seed("big/blob.bin", oldPayload)
		parent := rig.dir("in")
		dest := parent + "/blob.bin"
		staging := rig.strandUpload("big/blob.bin", dest)
		stranded := describe(t, staging)

		newPayload := SeedPayload(uploadPayload, 57)
		must(t, os.WriteFile(source, newPayload, 0o600))
		later := time.Now().Add(2 * time.Hour)
		must(t, os.Chtimes(source, later, later))
		rig.remote.reset()
		res, err := rig.upload(rig.engine(), "big/blob.bin", dest)
		if err != nil {
			t.Fatalf("upload of the changed source: %v", err)
		}
		assertUploaded(t, res, dest, newPayload)
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
		rig := newUploadRig(t)
		payload := SeedPayload(uploadPayload, 58)
		source := rig.seed("big/blob.bin", payload)
		parent := rig.dir("in")
		dest := parent + "/blob.bin"
		rig.remote.onStream = func(n int) {
			if n == 1 {
				rig.cutNext(streamCut)
			}
		}
		rig.remote.onPart = func(n int, part transferlink.Range) {
			if n != 2 {
				return
			}
			file, err := os.OpenFile(source, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Errorf("open source: %v", err)
				return
			}
			if _, err := file.WriteString("appended"); err != nil {
				t.Errorf("append: %v", err)
			}
			must(t, file.Close())
		}

		_, err := rig.upload(rig.engine(), "big/blob.bin", dest)
		requireClass(t, err, transfercore.ClassIntegrity)
		if exists(dest) {
			t.Fatal("a changed source was published")
		}
		assertOnlyEntries(t, parent)
		rig.assertNoStaging(parent)
		if _, parts, _ := rig.remote.counts(); parts != 2 {
			t.Fatalf("%d part sessions, want 2 (the change is caught before part 3)", parts)
		}
	})
}

// scenarioChunkUploadStaleStagingCollected shows that a later transfer into
// the same parent collects idle marked staging and touches nothing else.
func scenarioChunkUploadStaleStagingCollected(t *testing.T) {
	rig := newUploadRig(t)
	payload := SeedPayload(48<<10, 59)
	rig.seed("small.bin", payload)
	parent := rig.dir("gc parent")
	stale := time.Now().Add(-72 * time.Hour)
	young := time.Now().Add(-22 * time.Hour)

	mk := func(dirName string, perm os.FileMode, marker string, mtime time.Time) {
		t.Helper()
		path := filepath.Join(parent, dirName)
		must(t, os.Mkdir(path, 0o700))
		if marker != "" {
			markerPath := filepath.Join(path, "marker")
			writeFile(t, markerPath, []byte(marker))
			must(t, os.Chtimes(markerPath, mtime, mtime))
		}
		writeFile(t, filepath.Join(path, "part-0-1"), []byte("x"))
		must(t, os.Chmod(path, perm))
	}
	name := func(label string) (dirName, key string) {
		key = transferremote.StagingKey("upload-gc", label)
		return ".ssjack-transfer-" + key, key
	}

	var removed, kept []string
	for _, label := range []string{"stale-a", "stale-b"} {
		d, k := name(label)
		mk(d, 0o700, chunkMarker(k), stale)
		removed = append(removed, d)
	}
	{
		d, k := name("young")
		mk(d, 0o700, chunkMarker(k), young)
		kept = append(kept, d)
	}
	{
		// Same name pattern and an old marker, but a foreign mode.
		d, k := name("mode-0755")
		mk(d, 0o755, chunkMarker(k), stale)
		kept = append(kept, d)
	}
	{
		d, _ := name("unmarked")
		mk(d, 0o700, "", stale)
		kept = append(kept, d)
	}
	{
		// A one-shot staging name is never collected.
		d := ".ssjack-transfer-0123456789abcdef"
		mk(d, 0o700, "SSJACK-STAGING 1 0123456789abcdef\n", stale)
		kept = append(kept, d)
	}
	before := map[string]string{}
	for _, d := range kept {
		before[d] = describe(t, filepath.Join(parent, d))
	}

	dest := parent + "/small.bin"
	res, err := rig.upload(rig.engine(), "small.bin", dest)
	if err != nil {
		t.Fatalf("upload into a parent with stale staging: %v", err)
	}
	assertUploaded(t, res, dest, payload)
	for _, d := range removed {
		if exists(filepath.Join(parent, d)) {
			t.Fatalf("idle staging %q survived the later transfer", d)
		}
	}
	for _, d := range kept {
		if got := describe(t, filepath.Join(parent, d)); got != before[d] {
			t.Fatalf("%q was modified or removed:\nbefore: %s\nafter: %s", d, before[d], got)
		}
	}
	if want := len(kept) + 1; len(entryNames(t, parent)) != want {
		t.Fatalf("parent holds %q, want the upload and %d kept directories", entryNames(t, parent), len(kept))
	}
}
