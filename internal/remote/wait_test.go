package remote

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

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
