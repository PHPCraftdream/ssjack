package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// scriptedEngine replays fixed progress reports and returns a fixed outcome.
type scriptedEngine struct {
	mu     sync.Mutex
	steps  []transferengine.Progress
	result transferengine.Result
	err    error
	calls  int
}

func (s *scriptedEngine) Upload(_ context.Context, _ *transferlocal.Root, _, _ string, _ bool, progress func(transferengine.Progress)) (transferengine.Result, error) {
	return s.operate(progress)
}

func (s *scriptedEngine) Download(_ context.Context, _ *transferlocal.Root, _, _ string, _ bool, progress func(transferengine.Progress)) (transferengine.Result, error) {
	return s.operate(progress)
}

func (s *scriptedEngine) operate(progress func(transferengine.Progress)) (transferengine.Result, error) {
	s.mu.Lock()
	s.calls++
	steps, result, err := s.steps, s.result, s.err
	s.mu.Unlock()
	for _, p := range steps {
		progress(p)
	}
	return result, err
}

func (s *scriptedEngine) set(steps []transferengine.Progress, result transferengine.Result, err error) {
	s.mu.Lock()
	s.steps, s.result, s.err = steps, result, err
	s.mu.Unlock()
}

func (s *scriptedEngine) started() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type drivenOutcome struct {
	result transferengine.Result
	err    error
}

// drivenEngine forwards the progress reports a test sends and ends with the
// outcome the test chooses, or with onCancel when its context is cancelled.
type drivenEngine struct {
	feed      chan transferengine.Progress
	ack       chan struct{}
	finish    chan drivenOutcome
	onCancel  drivenOutcome
	cancelled atomic.Bool
}

func newDrivenEngine() *drivenEngine {
	return &drivenEngine{
		feed: make(chan transferengine.Progress), ack: make(chan struct{}), finish: make(chan drivenOutcome),
		onCancel: drivenOutcome{err: transfercore.Fail(transfercore.ClassCancelled, "transfer was cancelled")},
	}
}

func (d *drivenEngine) Upload(ctx context.Context, _ *transferlocal.Root, _, _ string, _ bool, progress func(transferengine.Progress)) (transferengine.Result, error) {
	return d.operate(ctx, progress)
}

func (d *drivenEngine) Download(ctx context.Context, _ *transferlocal.Root, _, _ string, _ bool, progress func(transferengine.Progress)) (transferengine.Result, error) {
	return d.operate(ctx, progress)
}

func (d *drivenEngine) operate(ctx context.Context, progress func(transferengine.Progress)) (transferengine.Result, error) {
	for {
		select {
		case p := <-d.feed:
			progress(p)
			select {
			case d.ack <- struct{}{}:
			case <-ctx.Done():
			}
		case o := <-d.finish:
			return o.result, o.err
		case <-ctx.Done():
			d.cancelled.Store(true)
			return d.onCancel.result, d.onCancel.err
		}
	}
}

// send delivers one progress report and returns once the manager recorded it.
func (d *drivenEngine) send(t *testing.T, p transferengine.Progress) {
	t.Helper()
	select {
	case d.feed <- p:
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not take the progress report within 5s")
	}
	select {
	case <-d.ack:
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not acknowledge the progress report within 5s")
	}
}

func (d *drivenEngine) end(t *testing.T, result transferengine.Result, err error) {
	t.Helper()
	select {
	case d.finish <- drivenOutcome{result: result, err: err}:
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not take the outcome within 5s")
	}
}

// newManagerWithBuild is newTestManager over a caller-supplied build callback.
func newManagerWithBuild(t *testing.T, targets []string, build func(string) (Engine, error)) *Manager {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks failed: %v", err)
	}
	root, err := transferlocal.ParseRoot(dir, "")
	if err != nil {
		t.Fatalf("ParseRoot failed: %v", err)
	}
	m, err := NewManager([]*transferlocal.Root{root}, targets, transfercore.DefaultLimits(), build)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

func startTo(t *testing.T, m *Manager, target string, download bool, local, remote string) StartOutput {
	t.Helper()
	start, err := m.start(StartInput{Target: target, Local: local, Remote: remote}, download)
	if err != nil {
		t.Fatalf("start(%q, %q, %q) failed: %v", target, local, remote, err)
	}
	return start
}

func mustStatus(t *testing.T, m *Manager, id string) StatusOutput {
	t.Helper()
	out, err := m.status(id)
	if err != nil {
		t.Fatalf("status(%s) failed: %v", id, err)
	}
	return out
}

// statusKeys is the set of JSON keys the status record is published with.
func statusKeys(t *testing.T, out StatusOutput) map[string]any {
	t.Helper()
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("status encoding failed: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("status decoding failed: %v", err)
	}
	return keys
}

func requireAbsent(t *testing.T, out StatusOutput, names ...string) {
	t.Helper()
	keys := statusKeys(t, out)
	for _, name := range names {
		if value, present := keys[name]; present {
			t.Fatalf("status carries %q = %v, want it omitted: %+v", name, value, out)
		}
	}
}

var chunkFieldNames = []string{"mode", "chunk_bytes", "chunks_done", "chunks_total", "attempts", "bytes_per_second"}

func requireChunk(t *testing.T, out StatusOutput, mode string, chunkBytes int64, done, total, attempts int, bps int64) {
	t.Helper()
	if out.Mode != mode || out.ChunkBytes != chunkBytes || out.ChunksDone != done || out.ChunksTotal != total || out.Attempts != attempts || out.BytesPerSecond != bps {
		t.Fatalf("chunk fields = {%q %d %d %d %d %d}, want {%q %d %d %d %d %d}: %+v",
			out.Mode, out.ChunkBytes, out.ChunksDone, out.ChunksTotal, out.Attempts, out.BytesPerSecond,
			mode, chunkBytes, done, total, attempts, bps, out)
	}
}

func TestEngineBuiltOncePerTarget(t *testing.T) {
	engines := map[string]*scriptedEngine{"a": {}, "b": {}}
	var mu sync.Mutex
	builds := map[string]int{}
	m := newManagerWithBuild(t, []string{"a", "b"}, func(target string) (Engine, error) {
		mu.Lock()
		defer mu.Unlock()
		builds[target]++
		return engines[target], nil
	})
	for i, target := range []string{"a", "a", "b", "a", "b"} {
		start := startTo(t, m, target, i%2 == 1, "f", "/r")
		waitForState(t, m, start.JobID, string(stateDone))
	}
	mu.Lock()
	defer mu.Unlock()
	if builds["a"] != 1 || builds["b"] != 1 {
		t.Fatalf("builds = %v, want one per target", builds)
	}
	if engines["a"].started() != 3 || engines["b"].started() != 2 {
		t.Fatalf("jobs per engine = a:%d b:%d, want a:3 b:2", engines["a"].started(), engines["b"].started())
	}
}

func TestConcurrentFirstUseBuildsOnce(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	entered := make(chan struct{}, 4)
	var builds atomic.Int32
	engine := &scriptedEngine{}
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) {
		builds.Add(1)
		entered <- struct{}{}
		<-release
		return engine, nil
	})
	t.Cleanup(unblock)
	first := startTo(t, m, "t", false, "a", "/a")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first job did not reach the build within 5s")
	}
	second := startTo(t, m, "t", false, "a", "/b")
	unblock()
	waitForState(t, m, first.JobID, string(stateDone))
	waitForState(t, m, second.JobID, string(stateDone))
	if got := builds.Load(); got != 1 {
		t.Fatalf("builds = %d, want 1", got)
	}
	if got := engine.started(); got != 2 {
		t.Fatalf("jobs on the shared engine = %d, want 2", got)
	}
}

func TestFailedBuildIsNotCached(t *testing.T) {
	var builds atomic.Int32
	engine := &scriptedEngine{}
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) {
		if builds.Add(1) == 1 {
			return nil, errors.New("/private/secret raw build failure")
		}
		return engine, nil
	})
	failed := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, "")
	if failed.State != string(stateFailed) || failed.ErrorClass != "internal" || failed.Message != "transfer failed" {
		t.Fatalf("status after failed build = %+v", failed)
	}
	requireAbsent(t, failed, chunkFieldNames...)
	encoded := mustEncode(t, failed)
	if strings.Contains(encoded, "/private/secret") || strings.Contains(encoded, "raw build failure") {
		t.Fatalf("status leaks build error text: %s", encoded)
	}
	waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateDone))
	waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateDone))
	if got := builds.Load(); got != 2 {
		t.Fatalf("builds = %d, want 2 (the failure retried once, then cached)", got)
	}
}

func TestRetentionEvictionKeepsTheEngine(t *testing.T) {
	var builds atomic.Int32
	engine := &scriptedEngine{}
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) {
		builds.Add(1)
		return engine, nil
	})
	var first string
	for i := 0; i <= maxRetained; i++ {
		id := startJob(t, m, false, "a", "/a").JobID
		if i == 0 {
			first = id
		}
		waitForState(t, m, id, "")
	}
	if _, err := m.status(first); err != errUnknownJob {
		t.Fatalf("oldest job error = %v, want errUnknownJob", err)
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("builds = %d, want 1", got)
	}
	if got := engine.started(); got != maxRetained+1 {
		t.Fatalf("jobs on the engine = %d, want %d", got, maxRetained+1)
	}
}

func TestRunningStatusMapsLiveChunkProgress(t *testing.T) {
	d := newDrivenEngine()
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return d, nil })
	id := startJob(t, m, false, "a", "/a").JobID

	d.send(t, transferengine.Progress{Phase: transfercore.PhasePreflight})
	out := mustStatus(t, m, id)
	if out.State != string(stateRunning) || out.Phase != transfercore.PhasePreflight || out.Bytes != 0 {
		t.Fatalf("preflight status = %+v", out)
	}
	requireAbsent(t, out, chunkFieldNames...)

	d.send(t, transferengine.Progress{Phase: transfercore.PhaseTransfer, Bytes: 10, Mode: transferengine.ModeStream, Attempts: 1})
	out = mustStatus(t, m, id)
	if out.Phase != transfercore.PhaseTransfer || out.Bytes != 10 {
		t.Fatalf("stream status = %+v", out)
	}
	requireChunk(t, out, "stream", 0, 0, 0, 1, 0)
	requireAbsent(t, out, "chunk_bytes", "chunks_done", "chunks_total", "bytes_per_second")

	d.send(t, transferengine.Progress{
		Phase: transfercore.PhaseTransfer, Bytes: 6, Mode: transferengine.ModeChunked,
		ChunkBytes: 262144, ChunksDone: 2, ChunksTotal: 5, Attempts: 3, BytesPerSecond: 1000,
	})
	out = mustStatus(t, m, id)
	if out.Bytes != 10 {
		t.Fatalf("bytes went down to %d, want 10", out.Bytes)
	}
	requireChunk(t, out, "chunked", 262144, 2, 5, 3, 1000)

	d.send(t, transferengine.Progress{
		Phase: transfercore.PhaseTransfer, Bytes: 30, Mode: transferengine.ModeChunked,
		ChunkBytes: 131072, ChunksDone: 3, ChunksTotal: 6, Attempts: 3, BytesPerSecond: 900,
	})
	out = mustStatus(t, m, id)
	if out.Bytes != 30 || out.State != string(stateRunning) {
		t.Fatalf("chunked status = %+v", out)
	}
	requireChunk(t, out, "chunked", 131072, 3, 6, 3, 900)

	d.send(t, transferengine.Progress{Phase: transfercore.PhaseVerify, Bytes: 20})
	out = mustStatus(t, m, id)
	if out.Phase != transfercore.PhaseVerify || out.Bytes != 30 {
		t.Fatalf("verify status = %+v", out)
	}
	requireChunk(t, out, "chunked", 131072, 3, 6, 3, 900)

	d.end(t, transferengine.Result{
		Kind: transferengine.KindFile, Files: 1, Bytes: 40, SHA256: "aa",
		Mode: transferengine.ModeChunked, ChunkBytes: 131072, ChunksDone: 6, ChunksTotal: 6, Attempts: 4, BytesPerSecond: 950,
	}, nil)
	final := waitForState(t, m, id, string(stateDone))
	if final.Bytes != 40 || final.Files != 1 || final.SHA256 != "aa" || final.Kind != "file" || final.Phase != "" {
		t.Fatalf("final status = %+v", final)
	}
	requireChunk(t, final, "chunked", 131072, 6, 6, 4, 950)
}

func TestBytesNeverDecreaseAcrossTheJob(t *testing.T) {
	fake := &scriptedEngine{}
	fake.set(
		[]transferengine.Progress{
			{Phase: transfercore.PhaseTransfer, Bytes: 100, Mode: transferengine.ModeStream, Attempts: 1},
			{Phase: transfercore.PhaseTransfer, Bytes: 60, Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 1, ChunksTotal: 4, Attempts: 2},
		},
		transferengine.Result{Bytes: 50, Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 1, ChunksTotal: 4, Attempts: 8},
		transfercore.Fail(transfercore.ClassLinkUnstable, transfercore.MsgLinkUnstable),
	)
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
	out := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, "")
	if out.State != string(stateFailed) || out.Bytes != 100 {
		t.Fatalf("status = %+v, want failed with bytes 100", out)
	}
}

func TestDirectoriesAndPlainStreamsOmitChunkFields(t *testing.T) {
	t.Run("finished directory", func(t *testing.T) {
		fake := &scriptedEngine{}
		fake.set(
			[]transferengine.Progress{{Phase: transfercore.PhaseTransfer, Bytes: 4096}, {Phase: transfercore.PhaseTransfer, Bytes: 9000}},
			transferengine.Result{Kind: transferengine.KindDir, Files: 2, Dirs: 1, Bytes: 5000, ManifestSHA256: "bb"}, nil)
		m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
		out := waitForState(t, m, startJob(t, m, false, "d", "/d").JobID, string(stateDone))
		if out.Kind != "directory" || out.Files != 2 || out.Dirs != 1 || out.Bytes != 5000 || out.ManifestSHA256 != "bb" {
			t.Fatalf("status = %+v", out)
		}
		requireAbsent(t, out, chunkFieldNames...)
	})
	t.Run("failed directory", func(t *testing.T) {
		fake := &scriptedEngine{}
		fake.set([]transferengine.Progress{{Phase: transfercore.PhaseTransfer, Bytes: 4096}}, transferengine.Result{},
			transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed"))
		m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
		out := waitForState(t, m, startJob(t, m, true, "d", "/d").JobID, string(stateFailed))
		if out.ErrorClass != "remote_failed" {
			t.Fatalf("status = %+v", out)
		}
		requireAbsent(t, out, chunkFieldNames...)
	})
	t.Run("refused before any transfer", func(t *testing.T) {
		fake := &scriptedEngine{}
		fake.set([]transferengine.Progress{{Phase: transfercore.PhasePreflight}}, transferengine.Result{},
			transfercore.Fail(transfercore.ClassRefusedPath, "transfer path was refused"))
		m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
		out := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateFailed))
		if out.ErrorClass != "refused_path" || out.Message != "transfer path was refused" {
			t.Fatalf("status = %+v", out)
		}
		requireAbsent(t, out, chunkFieldNames...)
	})
	t.Run("plain successful stream", func(t *testing.T) {
		fake := &scriptedEngine{}
		fake.set(
			[]transferengine.Progress{{Phase: transfercore.PhaseTransfer, Bytes: 3, Mode: transferengine.ModeStream, Attempts: 1}},
			transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: 3, SHA256: "aa"}, nil)
		m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
		out := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateDone))
		requireChunk(t, out, "stream", 0, 0, 0, 1, 0)
		requireAbsent(t, out, "chunk_bytes", "chunks_done", "chunks_total", "bytes_per_second")
	})
	t.Run("plain successful stream without progress", func(t *testing.T) {
		fake := &scriptedEngine{}
		fake.set(nil, transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: 3, SHA256: "aa"}, nil)
		m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
		out := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateDone))
		requireChunk(t, out, "stream", 0, 0, 0, 1, 0)
	})
	t.Run("failed plain stream", func(t *testing.T) {
		fake := &scriptedEngine{}
		fake.set(
			[]transferengine.Progress{{Phase: transfercore.PhaseTransfer, Bytes: 3, Mode: transferengine.ModeStream, Attempts: 1}},
			transferengine.Result{}, transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed"))
		m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
		out := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateFailed))
		if out.ErrorClass != "remote_failed" || out.Bytes != 3 {
			t.Fatalf("status = %+v", out)
		}
		requireChunk(t, out, "stream", 0, 0, 0, 1, 0)
	})
}

func TestUnknownModeIsNotPublished(t *testing.T) {
	fake := &scriptedEngine{}
	fake.set(
		[]transferengine.Progress{{Phase: transfercore.PhaseTransfer, Bytes: 3, Mode: "/private/odd", Attempts: 7, ChunksDone: 2}},
		transferengine.Result{Kind: transferengine.KindDir, Files: 1, Bytes: 3, ManifestSHA256: "bb", Mode: "/private/odd"}, nil)
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
	out := waitForState(t, m, startJob(t, m, false, "d", "/d").JobID, string(stateDone))
	requireAbsent(t, out, chunkFieldNames...)
	if strings.Contains(mustEncode(t, out), "/private") {
		t.Fatalf("status leaks the engine's mode text: %+v", out)
	}
}

func TestLinkUnstableMessageIsFixedAndRetryIsAllowed(t *testing.T) {
	fake := &scriptedEngine{}
	fake.set(
		[]transferengine.Progress{
			{Phase: transfercore.PhaseTransfer, Bytes: 50, Mode: transferengine.ModeStream, Attempts: 1},
			{Phase: transfercore.PhaseTransfer, Bytes: 262144, Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 1, ChunksTotal: 4, Attempts: 2},
		},
		transferengine.Result{Bytes: 262144, Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 1, ChunksTotal: 4, Attempts: 9, BytesPerSecond: 500},
		fmt.Errorf("%w: /private/raw ssh transport text", transfercore.Fail(transfercore.ClassLinkUnstable, "/private/raw lower-layer text")),
	)
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
	failed := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, "")
	if failed.State != string(stateFailed) || failed.ErrorClass != "link_unstable" || failed.Message != transfercore.MsgLinkUnstable {
		t.Fatalf("status = %+v", failed)
	}
	if failed.Message != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", failed.Message)
	}
	if failed.Bytes != 262144 || failed.Files != 0 || failed.SHA256 != "" {
		t.Fatalf("failed chunked job carries wrong bytes or result: %+v", failed)
	}
	requireChunk(t, failed, "chunked", 262144, 1, 4, 9, 500)
	if encoded := mustEncode(t, failed); strings.Contains(encoded, "/private") || strings.Contains(encoded, "ssh transport") || strings.Contains(encoded, "lower-layer") {
		t.Fatalf("status leaks lower-layer text: %s", encoded)
	}

	fake.set(nil, transferengine.Result{
		Kind: transferengine.KindFile, Files: 1, Bytes: 1048576, SHA256: "aa",
		Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 4, ChunksTotal: 4, Attempts: 10,
	}, nil)
	retried := waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, string(stateDone))
	if retried.Bytes != 1048576 || retried.SHA256 != "aa" || retried.ErrorClass != "" || retried.Message != "" {
		t.Fatalf("retried status = %+v", retried)
	}
	requireChunk(t, retried, "chunked", 262144, 4, 4, 10, 0)
}

func TestCancelEndsChunkedJobAsCancelled(t *testing.T) {
	d := newDrivenEngine()
	d.onCancel = drivenOutcome{
		result: transferengine.Result{Bytes: 524288, Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 2, ChunksTotal: 4, Attempts: 3, BytesPerSecond: 800},
		err:    transfercore.Fail(transfercore.ClassCancelled, "transfer was cancelled"),
	}
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return d, nil })
	id := startJob(t, m, false, "a", "/a").JobID
	d.send(t, transferengine.Progress{
		Phase: transfercore.PhaseTransfer, Bytes: 524288, Mode: transferengine.ModeChunked,
		ChunkBytes: 262144, ChunksDone: 2, ChunksTotal: 4, Attempts: 3, BytesPerSecond: 800,
	})
	if out := mustStatus(t, m, id); out.State != string(stateRunning) {
		t.Fatalf("status before cancel = %+v", out)
	}
	cancelled, err := m.cancelJob(id)
	if err != nil || !cancelled.Cancelled {
		t.Fatalf("cancel = %+v, %v", cancelled, err)
	}
	out := waitForState(t, m, id, string(stateCancelled))
	if !d.cancelled.Load() {
		t.Fatal("the engine did not see its context cancelled")
	}
	if out.ErrorClass != "cancelled" || out.Message != "transfer was cancelled" {
		t.Fatalf("status = %+v", out)
	}
	if out.Bytes != 524288 {
		t.Fatalf("bytes = %d, want 524288", out.Bytes)
	}
	requireChunk(t, out, "chunked", 262144, 2, 4, 3, 800)
	if again, err := m.cancelJob(id); err != nil || again.Cancelled {
		t.Fatalf("second cancel = %+v, %v", again, err)
	}
	startJob(t, m, false, "a", "/a")
}

func TestCancelWithoutClassifiedErrorIsStillCancelled(t *testing.T) {
	d := newDrivenEngine()
	d.onCancel = drivenOutcome{err: context.Canceled}
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return d, nil })
	id := startJob(t, m, true, "a", "/a").JobID
	d.send(t, transferengine.Progress{Phase: transfercore.PhaseTransfer, Bytes: 5, Mode: transferengine.ModeStream, Attempts: 1})
	if cancelled, err := m.cancelJob(id); err != nil || !cancelled.Cancelled {
		t.Fatalf("cancel = %+v, %v", cancelled, err)
	}
	out := waitForState(t, m, id, string(stateCancelled))
	if out.ErrorClass != "cancelled" || out.Message != "transfer was cancelled" {
		t.Fatalf("status = %+v", out)
	}
	requireChunk(t, out, "stream", 0, 0, 0, 1, 0)
}
