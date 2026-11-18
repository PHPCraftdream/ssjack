package manager

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// fakeEngine is a deterministic Engine stand-in; block, when set, holds
// calls until closed or the context is cancelled.
type fakeEngine struct {
	mu     sync.Mutex
	block  chan struct{}
	result transferengine.Result
	err    error
	calls  int
	phase  string
}

func (f *fakeEngine) Upload(ctx context.Context, root *transferlocal.Root, local, remote string, overwrite bool, progress func(transferengine.Progress)) (transferengine.Result, error) {
	return f.operate(ctx, progress)
}

func (f *fakeEngine) Download(ctx context.Context, root *transferlocal.Root, remote, local string, overwrite bool, progress func(transferengine.Progress)) (transferengine.Result, error) {
	return f.operate(ctx, progress)
}

func (f *fakeEngine) operate(ctx context.Context, progress func(transferengine.Progress)) (transferengine.Result, error) {
	f.mu.Lock()
	f.calls++
	block, phase, result, err := f.block, f.phase, f.result, f.err
	f.mu.Unlock()
	if phase != "" && progress != nil {
		progress(transferengine.Progress{Phase: phase, Bytes: 7})
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return transferengine.Result{}, ctx.Err()
		}
	}
	return result, err
}

func (f *fakeEngine) unblock() {
	f.mu.Lock()
	if f.block != nil {
		close(f.block)
		f.block = nil
	}
	f.mu.Unlock()
}

func (f *fakeEngine) started() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newTestManager(t *testing.T, fake *fakeEngine) *Manager {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks failed: %v", err)
	}
	root, err := transferlocal.ParseRoot(dir, "")
	if err != nil {
		t.Fatalf("ParseRoot failed: %v", err)
	}
	m, err := NewManager([]*transferlocal.Root{root}, []string{"t"}, transfercore.DefaultLimits(),
		func(string) (Engine, error) { return fake, nil })
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	t.Cleanup(m.Close)
	t.Cleanup(fake.unblock)
	return m
}

func startJob(t *testing.T, m *Manager, download bool, local, remote string) StartOutput {
	t.Helper()
	start, err := m.start(StartInput{Target: "t", Local: local, Remote: remote}, download)
	if err != nil {
		t.Fatalf("start(%q, %q) failed: %v", local, remote, err)
	}
	return start
}

// waitForState polls status until the state equals want, or any terminal
// state when want is empty. On timeout it fails with failure-only evidence
// (what, timeout, elapsed, attempts, last state, goroutine dump).
func waitForState(t *testing.T, m *Manager, id, want string) StatusOutput {
	t.Helper()
	var out StatusOutput
	done, lastDesc, lastErr := flakediag.WaitForDesc(t,
		fmt.Sprintf("job %s to reach state %q (any terminal state when %q)", id, want, ""),
		2*time.Second,
		func() (string, bool, error) {
			o, err := m.status(id)
			out = o
			desc := "unavailable"
			if err == nil {
				desc = fmt.Sprintf("state=%q phase=%q", o.State, o.Phase)
			}
			return desc, err == nil && (o.State == want || (want == "" && o.State != string(stateRunning))), err
		})
	if lastErr != nil {
		t.Fatalf("status(%s) failed: %v", id, lastErr)
	}
	if !done {
		t.Fatalf("job %s stuck in state %q, want %q", id, lastDesc, want)
	}
	return out
}

func mustEncode(t *testing.T, value any) string {
	t.Helper()
	data, err := wire.Encode(value)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return data
}

// closeWithin runs Manager.Close on another goroutine and requires it to
// return quickly. On failure prints a goroutine dump for hang diagnosis.
func closeWithin(t *testing.T, m *Manager) {
	t.Helper()
	flakediag.OnFailure(t, func() string {
		return "Close did not return within 5s; goroutine dump:\n" + flakediag.GoroutineDump(0)
	})
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return within 5s")
	}
}

func TestStartReturnsImmediateJobID(t *testing.T) {
	fake := &fakeEngine{result: transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: 3, SHA256: "aa"}}
	m := newTestManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	if start.JobID == "" {
		t.Fatal("start returned an empty job id")
	}
	out := waitForState(t, m, start.JobID, string(stateDone))
	if out.State != string(stateDone) || out.Direction != "upload" || out.Kind != "file" {
		t.Fatalf("status = %+v", out)
	}
	if out.Files != 1 || out.Bytes != 3 || out.SHA256 != "aa" {
		t.Fatalf("status = %+v", out)
	}
}

func TestConcurrencyLimitIsTwo(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m := newTestManager(t, fake)
	first := startJob(t, m, false, "a", "/a")
	second := startJob(t, m, false, "a", "/b")
	if _, err := m.start(StartInput{Target: "t", Local: "c", Remote: "/c"}, false); err == nil || err.Error() != "concurrent transfer limit reached" {
		t.Fatalf("third start error = %v", err)
	}
	fake.unblock()
	waitForState(t, m, first.JobID, "")
	waitForState(t, m, second.JobID, "")
	if _, err := m.start(StartInput{Target: "t", Local: "c", Remote: "/c"}, false); err != nil {
		t.Fatalf("start after capacity freed failed: %v", err)
	}
}

func TestDuplicateDestinationRefused(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m := newTestManager(t, fake)
	refused := "another transfer is using this destination"
	first := startJob(t, m, false, "a", "/a")
	if _, err := m.start(StartInput{Target: "t", Local: "a", Remote: "/a"}, false); err == nil || err.Error() != refused {
		t.Fatalf("duplicate upload error = %v", err)
	}
	second := startJob(t, m, false, "a", "/b")
	fake.unblock()
	waitForState(t, m, first.JobID, "")
	waitForState(t, m, second.JobID, "")
	waitForState(t, m, startJob(t, m, false, "a", "/a").JobID, "")
	fake.mu.Lock()
	fake.block = make(chan struct{})
	fake.mu.Unlock()
	dl := startJob(t, m, true, "down", "/r")
	if _, err := m.start(StartInput{Target: "t", Local: "down", Remote: "/r"}, true); err == nil || err.Error() != refused {
		t.Fatalf("duplicate download error = %v", err)
	}
	fake.unblock()
	waitForState(t, m, dl.JobID, "")
	startJob(t, m, true, "down", "/r")
}

func TestOverwriteRequiresConfirm(t *testing.T) {
	fake := &fakeEngine{}
	m := newTestManager(t, fake)
	input := StartInput{Target: "t", Local: "a", Remote: "/a", Overwrite: true}
	if _, err := m.start(input, false); err == nil || err.Error() != "overwrite requires confirm=true" {
		t.Fatalf("error = %v", err)
	}
	if calls := fake.started(); calls != 0 {
		t.Fatalf("calls = %d, want 0", calls)
	}
	input.Confirm = true
	if _, err := m.start(input, false); err != nil {
		t.Fatalf("confirmed start failed: %v", err)
	}
}

func TestCancelCancelsRunningJob(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m := newTestManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	cancelled, err := m.cancelJob(start.JobID)
	if err != nil || !cancelled.Cancelled {
		t.Fatalf("cancel = %+v, %v", cancelled, err)
	}
	out := waitForState(t, m, start.JobID, string(stateCancelled))
	if out.ErrorClass != "cancelled" {
		t.Fatalf("status = %+v", out)
	}
	if again, err := m.cancelJob(start.JobID); err != nil || again.Cancelled {
		t.Fatalf("second cancel = %+v, %v", again, err)
	}
	if _, err := m.cancelJob("missing"); err != errUnknownJob {
		t.Fatalf("unknown cancel error = %v", err)
	}
}

func TestRetentionEvictsOldestFinished(t *testing.T) {
	fake := &fakeEngine{}
	m := newTestManager(t, fake)
	ids := make([]string, 0, maxRetained)
	for i := 0; i < maxRetained; i++ {
		start := startJob(t, m, false, "a", "/a")
		ids = append(ids, start.JobID)
		waitForState(t, m, start.JobID, "")
	}
	if _, err := m.status(ids[0]); err != nil {
		t.Fatalf("oldest retained status failed: %v", err)
	}
	extra := startJob(t, m, false, "a", "/a")
	waitForState(t, m, extra.JobID, "")
	if _, err := m.status(ids[0]); err != errUnknownJob {
		t.Fatalf("oldest job error = %v, want errUnknownJob", err)
	}
	if _, err := m.status(extra.JobID); err != nil {
		t.Fatalf("newest job status failed: %v", err)
	}
}

func TestCloseCancelsAndJoins(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m := newTestManager(t, fake)
	first := startJob(t, m, false, "a", "/a")
	second := startJob(t, m, false, "a", "/b")
	closeWithin(t, m)
	for _, id := range []string{first.JobID, second.JobID} {
		if out := waitForState(t, m, id, ""); out.State != string(stateCancelled) {
			t.Fatalf("job %s state = %q", id, out.State)
		}
	}
	if _, err := m.start(StartInput{Target: "t", Local: "c", Remote: "/c"}, false); err == nil || err.Error() != "session closed" {
		t.Fatalf("start after close error = %v", err)
	}
	closeWithin(t, m)
}
