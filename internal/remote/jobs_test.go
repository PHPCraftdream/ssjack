package remote

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func awaitJob(t *testing.T, m *Manager, id string) {
	t.Helper()
	j, err := m.get(id)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-j.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not finish")
	}
}

type admissionStartResult struct {
	started StartOutput
	err     error
}

type admissionTestHarness struct {
	ctx           context.Context
	cancel        context.CancelFunc
	release       chan struct{}
	entered       chan struct{}
	gateOnce      sync.Once
	manager       *Manager
	startResult   chan admissionStartResult
	startedDone   chan struct{}
	started       StartOutput
	startErr      error
	startLaunched bool
}

func newAdmissionTestHarness(t *testing.T, provider func(*admissionTestHarness) AdmissionProvider) *admissionTestHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	h := &admissionTestHarness{
		ctx: ctx, cancel: cancel,
		release: make(chan struct{}), entered: make(chan struct{}),
		startResult: make(chan admissionStartResult, 1), startedDone: make(chan struct{}),
	}
	h.manager = NewAdmittedManager(ctx, []string{"test"}, provider(h))
	// Cleanup is installed before any provider barrier can block the test.
	t.Cleanup(func() {
		h.openGate()
		h.cancel()
		if h.startLaunched {
			select {
			case <-h.startedDone:
			case <-time.After(5 * time.Second):
				t.Error("Start goroutine did not join; manager left open")
				return
			}
		}
		closed := make(chan struct{})
		go func() {
			h.manager.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Error("manager workers did not join during cleanup")
		}
	})
	return h
}

func (h *admissionTestHarness) openGate() {
	h.gateOnce.Do(func() { close(h.release) })
}

func (h *admissionTestHarness) start(input StartInput) {
	h.startLaunched = true
	go func() {
		started, err := h.manager.Start(input)
		h.startResult <- admissionStartResult{started: started, err: err}
		close(h.startedDone)
	}()
}

func (h *admissionTestHarness) wait(t *testing.T, barrier <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-barrier:
	case <-h.ctx.Done():
		t.Fatal(message)
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}

func (h *admissionTestHarness) awaitStart(t *testing.T) bool {
	t.Helper()
	select {
	case result := <-h.startResult:
		h.started, h.startErr = result.started, result.err
	case <-h.ctx.Done():
		t.Fatal("Start did not return")
		return false
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
		return false
	}
	select {
	case <-h.startedDone:
		return true
	case <-h.ctx.Done():
		t.Fatal("Start goroutine did not join")
		return false
	case <-time.After(5 * time.Second):
		t.Fatal("Start goroutine did not join")
		return false
	}
}

func TestOutputOffsetsAndExitCode(t *testing.T) {
	m := NewManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		out.Write([]byte{'a', 0, 255, 'b'})
		errOut.Write([]byte("error"))
		return 7, nil
	})
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "test"})
	if err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, started.JobID)
	out, err := m.Read(ReadInput{JobID: started.JobID})
	if err != nil || !out.Done || out.ExitCode != 7 || !bytes.Equal(out.Stdout, []byte{'a', 0, 255, 'b'}) || string(out.Stderr) != "error" {
		t.Fatalf("unexpected result: %+v, %v", out, err)
	}
	second, err := m.Read(ReadInput{JobID: started.JobID, StdoutOffset: out.StdoutOffset, StderrOffset: out.StderrOffset})
	if err != nil || len(second.Stdout) != 0 || len(second.Stderr) != 0 {
		t.Fatal("output was repeated")
	}
	if _, err := m.Read(ReadInput{JobID: started.JobID, StdoutOffset: -1}); err == nil {
		t.Fatal("negative offset was accepted")
	}
}

func TestBoundedCapture(t *testing.T) {
	var capture capture
	data := bytes.Repeat([]byte("x"), outputLimit+100)
	capture.Write(data)
	got, offset, lost, err := capture.read(0)
	if err != nil || !lost || len(got) != chunkLimit || offset != 100+chunkLimit || len(capture.data) > outputLimit {
		t.Fatalf("incorrect buffer bounds: %d %d %v %v", len(got), offset, lost, err)
	}
	capture.Write([]byte("tail"))
	got, _, _, err = capture.read(int64(len(data)))
	if err != nil || string(got) != "tail" {
		t.Fatal("trailing output was lost")
	}
}

func TestCancelLimitsAndClosedSession(t *testing.T) {
	m := NewManager(context.Background(), []string{"test"}, func(ctx context.Context, _, _ string, _, _ io.Writer) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	})
	defer m.Close()
	if _, err := m.Start(StartInput{Target: "other", Command: "test"}); err == nil {
		t.Fatal("unconfigured target was allowed")
	}
	if _, err := m.Start(StartInput{Target: "test", Command: "test", TimeoutSeconds: 3601}); err == nil {
		t.Fatal("oversized timeout was allowed")
	}
	var ids []string
	for range maxActive {
		out, err := m.Start(StartInput{Target: "test", Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, out.JobID)
	}
	if _, err := m.Start(StartInput{Target: "test", Command: "wait"}); err == nil {
		t.Fatal("concurrent operation limit was exceeded")
	}
	if _, err := m.Cancel(ids[0]); err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, ids[0])
	m.Close()
	for _, id := range ids {
		awaitJob(t, m, id)
	}
	if _, err := m.Start(StartInput{Target: "test", Command: "test"}); err == nil {
		t.Fatal("operation started after closure")
	}
	if reply := m.Handle(context.Background(), wire.Request{Operation: "export_key"}); reply.OK {
		t.Fatal("unknown operation was allowed")
	}
}

func TestCompletedJobsAreEvictedWithoutEndingSession(t *testing.T) {
	m := NewManager(context.Background(), []string{"test"}, func(context.Context, string, string, io.Writer, io.Writer) (int, error) { return 0, nil })
	defer m.Close()
	first := ""
	for range maxJobs + 1 {
		out, err := m.Start(StartInput{Target: "test", Command: "done"})
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = out.JobID
		}
		awaitJob(t, m, out.JobID)
	}
	if _, err := m.get(first); err == nil || len(m.jobs) != maxJobs {
		t.Fatal("old completed operations were not evicted")
	}
}

func TestTimeout(t *testing.T) {
	m := NewManager(context.Background(), []string{"test"}, func(ctx context.Context, _, _ string, _, _ io.Writer) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	})
	defer m.Close()
	out, err := m.Start(StartInput{Target: "test", Command: "wait", TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, out.JobID)
	result, err := m.Read(ReadInput{JobID: out.JobID})
	if err != nil || !result.Done || result.Error != context.DeadlineExceeded.Error() {
		t.Fatalf("timeout was lost: %+v, %v", result, err)
	}
}
