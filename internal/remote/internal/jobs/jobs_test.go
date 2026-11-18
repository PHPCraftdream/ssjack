package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
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
		flakediag.OnFailure(t, func() string {
			return fmt.Sprintf("awaitJob: waited 5s for job %s to finish; goroutine dump:\n%s",
				flakediag.Short([]byte(id)), flakediag.GoroutineDump(64*1024))
		})
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
	// Failure-only evidence for the harness's barrier/timeout waits.
	flakediag.OnFailure(t, func() string {
		return fmt.Sprintf("admission harness: ctxErr=%v startLaunched=%v goroutine dump:\n%s",
			h.ctx.Err(), h.startLaunched, flakediag.GoroutineDump(64*1024))
	})
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

// waitTimers replaces the manager's expiry timer: a wait announces its timer
// on armed, and the test fires it by hand, so no test sleeps.
type waitTimers struct {
	armed chan *waitTimer
}

type waitTimer struct {
	d       time.Duration
	c       chan time.Time
	stopped atomic.Bool
}

func newWaitTimers() *waitTimers { return &waitTimers{armed: make(chan *waitTimer, 16)} }

func (f *waitTimers) timer(d time.Duration) (<-chan time.Time, func()) {
	wt := &waitTimer{d: d, c: make(chan time.Time, 1)}
	f.armed <- wt
	return wt.c, func() { wt.stopped.Store(true) }
}

// next returns the timer of the next wait that began to block.
func (f *waitTimers) next(t *testing.T) *waitTimer {
	t.Helper()
	select {
	case wt := <-f.armed:
		return wt
	case <-time.After(5 * time.Second):
		t.Fatal("no wait armed its timer")
		return nil
	}
}

func (wt *waitTimer) fire() { wt.c <- time.Time{} }

// scriptedRun is a runner whose output and exit are driven by the test.
type scriptedRun struct {
	stdout chan string
	stderr chan string
	finish chan int
	wrote  chan struct{}
}

func newScriptedRun() *scriptedRun {
	return &scriptedRun{stdout: make(chan string), stderr: make(chan string), finish: make(chan int), wrote: make(chan struct{}, 16)}
}

func (s *scriptedRun) run(ctx context.Context, _, _ string, stdout, stderr io.Writer) (int, error) {
	for {
		select {
		case text := <-s.stdout:
			stdout.Write([]byte(text))
			s.wrote <- struct{}{}
		case text := <-s.stderr:
			stderr.Write([]byte(text))
			s.wrote <- struct{}{}
		case code := <-s.finish:
			return code, nil
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}
}

// emit hands text to the runner and returns once it is in the job's buffer.
func (s *scriptedRun) emit(t *testing.T, stream chan string, text string) {
	t.Helper()
	select {
	case stream <- text:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not take the output")
	}
	select {
	case <-s.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not write the output")
	}
}

func (s *scriptedRun) exit(t *testing.T, code int) {
	t.Helper()
	select {
	case s.finish <- code:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner did not take the exit code")
	}
}

type readResult struct {
	out ReadOutput
	err error
}

func readAsync(m *Manager, ctx context.Context, input ReadInput) <-chan readResult {
	c := make(chan readResult, 1)
	go func() {
		out, err := m.ReadWait(ctx, input)
		c <- readResult{out: out, err: err}
	}()
	return c
}

func receiveRead(t *testing.T, c <-chan readResult) readResult {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("waiting read did not return")
		return readResult{}
	}
}

func newWaitFixture(t *testing.T) (*Manager, *scriptedRun, *waitTimers, StartOutput) {
	t.Helper()
	run := newScriptedRun()
	m := NewManager(context.Background(), []string{"test"}, run.run)
	t.Cleanup(m.Close)
	timers := newWaitTimers()
	m.timer = timers.timer
	started, err := m.Start(StartInput{Target: "test", Command: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return m, run, timers, started
}

func TestReadWaitDoneJobReturnsAtOnce(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	run.emit(t, run.stdout, "tail")
	run.exit(t, 4)
	awaitJob(t, m, started.JobID)
	out, err := m.ReadWait(context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 25})
	if err != nil || !out.Done || out.ExitCode != 4 || string(out.Stdout) != "tail" {
		t.Fatalf("ReadWait = %+v, %v", out, err)
	}
	// Drained and done: still immediate.
	out, err = m.ReadWait(context.Background(), ReadInput{JobID: started.JobID, StdoutOffset: out.StdoutOffset, WaitSeconds: 25})
	if err != nil || !out.Done || len(out.Stdout) != 0 {
		t.Fatalf("second ReadWait = %+v, %v", out, err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("a finished job armed a wait timer")
	}
}

func TestReadWaitExistingOutputReturnsAtOnce(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	run.emit(t, run.stdout, "abc")
	run.emit(t, run.stderr, "e")
	out, err := m.ReadWait(context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 20})
	if err != nil || out.Done || string(out.Stdout) != "abc" || string(out.Stderr) != "e" || out.StdoutOffset != 3 || out.StderrOffset != 1 {
		t.Fatalf("ReadWait = %+v, %v", out, err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("a read with output armed a wait timer")
	}
	// Output beyond a stale offset exists too.
	out, err = m.ReadWait(context.Background(), ReadInput{JobID: started.JobID, StdoutOffset: 1, StderrOffset: 1, WaitSeconds: 20})
	if err != nil || string(out.Stdout) != "bc" || out.StdoutOffset != 3 {
		t.Fatalf("ReadWait from a stale offset = %+v, %v", out, err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("a read with output beyond the offsets armed a wait timer")
	}
	run.exit(t, 0)
	awaitJob(t, m, started.JobID)
}

func TestReadWaitZeroAndInvalidOffsetReturnAtOnce(t *testing.T) {
	m, _, timers, started := newWaitFixture(t)
	out, err := m.ReadWait(context.Background(), ReadInput{JobID: started.JobID})
	if err != nil || out.Done || len(out.Stdout) != 0 {
		t.Fatalf("ReadWait(0) = %+v, %v", out, err)
	}
	if _, err := m.ReadWait(context.Background(), ReadInput{JobID: started.JobID, StdoutOffset: 99, WaitSeconds: 20}); err == nil {
		t.Fatal("an offset beyond the output was accepted")
	}
	if _, err := m.ReadWait(context.Background(), ReadInput{JobID: "missing", WaitSeconds: 20}); err == nil {
		t.Fatal("an unknown job was accepted")
	}
	if _, err := m.ReadWait(context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: -1}); err != jobwait.ErrWaitRange {
		t.Fatalf("negative wait error = %v", err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("an immediate read armed a wait timer")
	}
}

func TestReadWaitReturnsOnNewStdout(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	results := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 20})
	timer := timers.next(t)
	if timer.d != 20*time.Second {
		t.Fatalf("wait armed %v, want 20s", timer.d)
	}
	run.emit(t, run.stdout, "hello")
	r := receiveRead(t, results)
	if r.err != nil || r.out.Done || string(r.out.Stdout) != "hello" || r.out.StdoutOffset != 5 || len(r.out.Stderr) != 0 {
		t.Fatalf("ReadWait = %+v, %v", r.out, r.err)
	}
	if !timer.stopped.Load() {
		t.Fatal("the wait left its timer armed")
	}
}

func TestReadWaitReturnsOnNewStderr(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	run.emit(t, run.stdout, "xy")
	results := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, StdoutOffset: 2, WaitSeconds: 20})
	timers.next(t)
	run.emit(t, run.stderr, "warn")
	r := receiveRead(t, results)
	if r.err != nil || r.out.Done || string(r.out.Stderr) != "warn" || r.out.StderrOffset != 4 || len(r.out.Stdout) != 0 || r.out.StdoutOffset != 2 {
		t.Fatalf("ReadWait = %+v, %v", r.out, r.err)
	}
}

func TestReadWaitReturnsOnCompletion(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	results := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 20})
	timers.next(t)
	run.exit(t, 3)
	r := receiveRead(t, results)
	if r.err != nil || !r.out.Done || r.out.ExitCode != 3 {
		t.Fatalf("ReadWait = %+v, %v", r.out, r.err)
	}
}

func TestReadWaitExpiryReturnsTheQuietChunk(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	run.emit(t, run.stdout, "abc")
	results := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, StdoutOffset: 3, WaitSeconds: 5})
	timer := timers.next(t)
	timer.fire()
	r := receiveRead(t, results)
	if r.err != nil || r.out.Done || len(r.out.Stdout) != 0 || len(r.out.Stderr) != 0 || r.out.StdoutOffset != 3 || r.out.StdoutMore || r.out.StderrMore || r.out.ExitCode != -1 {
		t.Fatalf("expired ReadWait = %+v, %v", r.out, r.err)
	}
	if !timer.stopped.Load() {
		t.Fatal("the wait left its timer armed")
	}
	run.exit(t, 0)
	awaitJob(t, m, started.JobID)
}

func TestReadWaitContextEndFreesWaiter(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := readAsync(m, ctx, ReadInput{JobID: started.JobID, WaitSeconds: 25})
	timers.next(t)
	cancel()
	if r := receiveRead(t, results); r.err != errSessionClosed {
		t.Fatalf("cancelled wait = %+v, %v; want errSessionClosed", r.out, r.err)
	}
	// The job is untouched and the slot is free again.
	again := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 25})
	timers.next(t)
	run.emit(t, run.stdout, "z")
	if r := receiveRead(t, again); r.err != nil || string(r.out.Stdout) != "z" {
		t.Fatalf("second wait = %+v, %v", r.out, r.err)
	}
}

func TestReadWaitSessionCloseFreesWaiters(t *testing.T) {
	m, _, timers, started := newWaitFixture(t)
	first := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 25})
	second := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 25})
	timers.next(t)
	timers.next(t)
	closed := make(chan struct{})
	go func() { m.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	for _, results := range []<-chan readResult{first, second} {
		r := receiveRead(t, results)
		switch {
		case r.err == errSessionClosed:
		case r.err == nil && r.out.Done:
		default:
			t.Fatalf("wait after close = %+v, %v", r.out, r.err)
		}
	}
}

func TestReadWaitersAreBounded(t *testing.T) {
	m, run, timers, started := newWaitFixture(t)
	var waiting []<-chan readResult
	var armed []*waitTimer
	for i := 0; i < jobwait.MaxSlots; i++ {
		waiting = append(waiting, readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 25}))
		armed = append(armed, timers.next(t))
	}
	// Every slot is taken: one more call answers at once and arms nothing.
	extra := receiveRead(t, readAsync(m, context.Background(), ReadInput{JobID: started.JobID, WaitSeconds: 25}))
	if extra.err != nil || extra.out.Done || len(extra.out.Stdout) != 0 {
		t.Fatalf("call beyond the bound = %+v, %v", extra.out, extra.err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("a call beyond the bound armed a wait timer")
	}
	run.emit(t, run.stdout, "go")
	for _, results := range waiting {
		if r := receiveRead(t, results); r.err != nil || string(r.out.Stdout) != "go" {
			t.Fatalf("woken wait = %+v, %v", r.out, r.err)
		}
	}
	for _, timer := range armed {
		if !timer.stopped.Load() {
			t.Fatal("a wait left its timer armed")
		}
	}
	// The slots came back.
	again := readAsync(m, context.Background(), ReadInput{JobID: started.JobID, StdoutOffset: 2, WaitSeconds: 25})
	timers.next(t).fire()
	if r := receiveRead(t, again); r.err != nil || r.out.Done {
		t.Fatalf("wait after the slots were released = %+v, %v", r.out, r.err)
	}
}

func TestHandleReadWaitSeconds(t *testing.T) {
	m, _, timers, started := newWaitFixture(t)

	reply := m.Handle(context.Background(), wire.Request{
		Operation: "read",
		Data:      mustEncodeWait(t, ReadInput{JobID: started.JobID, WaitSeconds: -1}),
	})
	if reply.OK || reply.Error != jobwait.ErrWaitRange.Error() {
		t.Fatalf("negative wait: reply = %+v", reply)
	}

	waitData := mustEncodeWait(t, ReadInput{JobID: started.JobID, WaitSeconds: 1000})
	replies := make(chan wire.Reply, 1)
	go func() {
		replies <- m.Handle(context.Background(), wire.Request{Operation: "read", Data: waitData})
	}()
	timer := timers.next(t)
	if timer.d != jobwait.MaxSeconds*time.Second {
		t.Fatalf("a wait of 1000 s armed %v, want the 25 s cap", timer.d)
	}
	timer.fire()
	select {
	case reply := <-replies:
		var out ReadOutput
		if !reply.OK || wire.Decode(reply.Data, &out) != nil || out.Done || len(out.Stdout) != 0 {
			t.Fatalf("expired wait reply = %+v", reply)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read with wait_seconds did not return")
	}
}

func mustEncodeWait(t *testing.T, value any) string {
	t.Helper()
	data, err := wire.Encode(value)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return data
}

func TestCaptureChangedWakesOnWrite(t *testing.T) {
	var b capture
	first := b.changed()
	if again := b.changed(); again != first {
		t.Fatal("two subscriptions before a write got different channels")
	}
	b.Write(nil)
	select {
	case <-first:
		t.Fatal("an empty write woke the waiters")
	default:
	}
	b.Write([]byte("x"))
	select {
	case <-first:
	default:
		t.Fatal("a write did not wake the waiters")
	}
	second := b.changed()
	if second == first {
		t.Fatal("a woken channel was handed out again")
	}
	select {
	case <-second:
		t.Fatal("a fresh subscription is already closed")
	default:
	}
}

func jobGuard(t *testing.T) GuardProvider {
	t.Helper()
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic-secret"), {'b', 0, 255}})
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context) (*outputguard.Snapshot, error) { return snapshot, nil }
}

func TestGuardedJobsCaptureOnlyFilteredBytesAcrossWritesAndReads(t *testing.T) {
	m := NewGuardedManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		for _, value := range []byte("before|synthetic-secret|b\x00\xff|after\xfe") {
			if _, err := out.Write([]byte{value}); err != nil {
				return -1, err
			}
		}
		_, err := errOut.Write([]byte("synthetic-secret"))
		return 7, err
	}, jobGuard(t))
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, started.JobID)
	out, err := m.Read(ReadInput{JobID: started.JobID})
	want := []byte("before|[REDACTED]|[REDACTED]|after\xfe")
	if err != nil || !out.Done || out.ExitCode != 7 || out.Error != "" || !bytes.Equal(out.Stdout, want) || string(out.Stderr) != outputguard.Marker || out.StdoutOffset != int64(len(want)) || out.StderrOffset != int64(len(outputguard.Marker)) {
		t.Fatal("guard changed control fields or captured raw output")
	}
	for offset := range len(want) + 1 {
		reread, err := m.Read(ReadInput{JobID: started.JobID, StdoutOffset: int64(offset)})
		if err != nil || !bytes.Equal(reread.Stdout, want[offset:]) {
			t.Fatal("arbitrary read offsets did not address the filtered view")
		}
	}
}

func TestGuardedJobWithholdsPotentialPrefixUntilContinuation(t *testing.T) {
	ready, release := make(chan struct{}), make(chan struct{})
	m := NewGuardedManager(context.Background(), []string{"test"}, func(ctx context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		if _, err := out.Write([]byte("synthetic-")); err != nil {
			return -1, err
		}
		close(ready)
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-release:
		}
		if _, err := out.Write([]byte("secret")); err != nil {
			return -1, err
		}
		_, err := errOut.Write([]byte("public-tail"))
		return 0, err
	}, jobGuard(t))
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		flakediag.OnFailure(t, func() string {
			return fmt.Sprintf("prefix barrier: waited 5s for runner ready; goroutine dump:\n%s",
				flakediag.GoroutineDump(64*1024))
		})
		t.Fatal("runner did not reach controlled prefix barrier")
	}
	out, err := m.Read(ReadInput{JobID: started.JobID})
	if err != nil || out.Done || len(out.Stdout) != 0 || out.StdoutOffset != 0 {
		t.Fatal("running read released an undecided secret prefix")
	}
	close(release)
	awaitJob(t, m, started.JobID)
	out, err = m.Read(ReadInput{JobID: started.JobID})
	if err != nil || !out.Done || string(out.Stdout) != outputguard.Marker || string(out.Stderr) != "public-tail" {
		t.Fatal("stream completion lost replacement or safe final tail")
	}
}

func TestGuardUnavailablePreventsRunnerAndNeverFormatsPrivateErrors(t *testing.T) {
	for _, provider := range []GuardProvider{nil,
		func(context.Context) (*outputguard.Snapshot, error) { return nil, privateJobError{} },
		func(context.Context) (*outputguard.Snapshot, error) { return &outputguard.Snapshot{}, nil },
	} {
		var calls atomic.Int32
		m := NewGuardedManager(context.Background(), []string{"test"}, func(context.Context, string, string, io.Writer, io.Writer) (int, error) {
			calls.Add(1)
			return 0, nil
		}, provider)
		started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
		if err != nil {
			m.Close()
			t.Fatal(err)
		}
		awaitJob(t, m, started.JobID)
		out, err := m.Read(ReadInput{JobID: started.JobID})
		m.Close()
		if err != nil || calls.Load() != 0 || !out.Done || out.Error != outputguard.ErrGuard.Error() || len(out.Stdout)+len(out.Stderr) != 0 {
			t.Fatal("guard refusal executed runner or exposed private diagnostics")
		}
	}
}

type privateJobError struct{}

func (privateJobError) Error() string { panic("private error must never be formatted") }

func TestGuardedRunnerErrorUsesFixedDiagnosticAndClosesBothStreams(t *testing.T) {
	m := NewGuardedManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		_, first := out.Write([]byte("synthetic-secret|safe"))
		_, second := errOut.Write([]byte("synthetic-secret|tail"))
		if first != nil || second != nil {
			return -1, errors.New("synthetic sink failure")
		}
		return 23, privateJobError{}
	}, jobGuard(t))
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, started.JobID)
	out, err := m.Read(ReadInput{JobID: started.JobID})
	if err != nil || !out.Done || out.ExitCode != 23 || out.Error != ErrJob.Error() || string(out.Stdout) != "[REDACTED]|safe" || string(out.Stderr) != "[REDACTED]|tail" {
		t.Fatal("runner error leaked diagnostics, lost safe tails or changed exit code")
	}
}

func admittedGuard(t *testing.T, secret string) *outputguard.Snapshot {
	t.Helper()
	snapshot, err := outputguard.New([][]byte{[]byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestAdmittedOperationIsCapturedBeforeStartReturns(t *testing.T) {
	guard := admittedGuard(t, "admitted-secret")
	var issued atomic.Int32
	h := newAdmissionTestHarness(t, func(h *admissionTestHarness) AdmissionProvider {
		return func(_ context.Context, _, _ string) (AdmittedOperation, error) {
			close(h.entered)
			select {
			case <-h.release:
			case <-h.ctx.Done():
				return AdmittedOperation{}, h.ctx.Err()
			}
			return AdmittedOperation{
				Guard:  guard,
				Issued: func() { issued.Add(1) },
				Runner: func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
					if issued.Load() != 1 {
						return -1, errors.New("runner started before issuance")
					}
					_, err := stdout.Write([]byte("admitted-secret"))
					return 0, err
				},
			}, nil
		}
	})
	h.start(StartInput{Target: "test", Command: "run"})
	h.wait(t, h.entered, "admission provider did not reach barrier")
	select {
	case <-h.startResult:
		t.Fatal("Start returned before admission completed")
	default:
	}
	h.openGate()
	if !h.awaitStart(t) {
		return
	}
	if h.startErr != nil || issued.Load() != 1 {
		t.Fatal("admission failed or issuance did not precede the worker")
	}
	awaitJob(t, h.manager, h.started.JobID)
	out, err := h.manager.Read(ReadInput{JobID: h.started.JobID})
	if err != nil || !out.Done || string(out.Stdout) != outputguard.Marker {
		t.Fatal("admitted runner did not use its captured guard")
	}
}

func TestAdmissionFailureAndIncompleteCaptureScheduleNoJob(t *testing.T) {
	var issued atomic.Int32
	validRunner := Runner(func(context.Context, string, string, io.Writer, io.Writer) (int, error) { return 0, nil })
	cases := []struct {
		name     string
		provider AdmissionProvider
	}{
		{"provider error", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Issued: func() { issued.Add(1) }}, privateJobError{}
		}},
		{"missing runner", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Guard: admittedGuard(t, "secret"), Issued: func() { issued.Add(1) }}, nil
		}},
		{"missing guard", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Runner: validRunner, Issued: func() { issued.Add(1) }}, nil
		}},
		{"invalid guard", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Runner: validRunner, Guard: &outputguard.Snapshot{}, Issued: func() { issued.Add(1) }}, nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			issued.Store(0)
			m := NewAdmittedManager(context.Background(), []string{"test"}, test.provider)
			started, err := m.Start(StartInput{Target: "test", Command: "run"})
			m.Close()
			if err != ErrAdmission || started.JobID != "" || len(m.jobs) != 0 || m.active != 0 || issued.Load() != 0 {
				t.Fatal("failed admission created a scheduled job or exposed provider diagnostics")
			}
		})
	}
}

func TestCapturedAdmissionSurvivesProviderChangeBeforeReturn(t *testing.T) {
	oldGuard := admittedGuard(t, "old-secret")
	newGuard := admittedGuard(t, "new-secret")
	current := AdmittedOperation{
		Guard: oldGuard,
		Runner: func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
			_, err := stdout.Write([]byte("old-secret"))
			return 0, err
		},
	}
	var providerCalls atomic.Int32
	h := newAdmissionTestHarness(t, func(h *admissionTestHarness) AdmissionProvider {
		return func(_ context.Context, _, _ string) (AdmittedOperation, error) {
			providerCalls.Add(1)
			admitted := current
			close(h.entered)
			select {
			case <-h.release:
			case <-h.ctx.Done():
				return AdmittedOperation{}, h.ctx.Err()
			}
			return admitted, nil
		}
	})
	h.start(StartInput{Target: "test", Command: "run"})
	h.wait(t, h.entered, "admission provider did not reach barrier")
	current = AdmittedOperation{
		Guard: newGuard,
		Runner: func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
			_, err := stdout.Write([]byte("new-runner"))
			return 0, err
		},
	}
	h.openGate()
	if !h.awaitStart(t) {
		return
	}
	if h.startErr != nil || providerCalls.Load() != 1 {
		t.Fatal("admission was not captured synchronously")
	}
	awaitJob(t, h.manager, h.started.JobID)
	out, err := h.manager.Read(ReadInput{JobID: h.started.JobID})
	if err != nil || !out.Done || string(out.Stdout) != outputguard.Marker {
		t.Fatal("worker did not use the admitted runner and guard")
	}
}

func TestDisconnectCancelsRemoteOperations(t *testing.T) {
	manager := NewManager(context.Background(), []string{"test"}, func(ctx context.Context, _, _ string, _, _ io.Writer) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	})
	defer manager.Close()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}
	keeper, err := broker.Listen(context.Background(), auth.Session, auth.Token, time.Minute, manager.Handle)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := broker.Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var started StartOutput
	if err := client.Call(context.Background(), "start", StartInput{Target: "test", Command: "wait"}, &started); err != nil {
		t.Fatal(err)
	}
	client.Close()
	awaitJob(t, manager, started.JobID)
	if _, err := manager.Start(StartInput{Target: "test", Command: "again"}); err == nil {
		t.Fatal("new operation started after disconnect")
	}
}
