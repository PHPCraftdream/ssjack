package transfer

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// fakeTimers replaces the manager's expiry timer: a wait announces its timer on
// armed, and the test fires it by hand, so no test sleeps.
type fakeTimers struct {
	armed chan *fakeTimer
}

type fakeTimer struct {
	d       time.Duration
	c       chan time.Time
	stopped atomic.Bool
}

func newFakeTimers() *fakeTimers { return &fakeTimers{armed: make(chan *fakeTimer, 16)} }

func (f *fakeTimers) timer(d time.Duration) (<-chan time.Time, func()) {
	ft := &fakeTimer{d: d, c: make(chan time.Time, 1)}
	f.armed <- ft
	return ft.c, func() { ft.stopped.Store(true) }
}

// next returns the timer of the next wait that began to block.
func (f *fakeTimers) next(t *testing.T) *fakeTimer {
	t.Helper()
	select {
	case ft := <-f.armed:
		return ft
	case <-time.After(5 * time.Second):
		t.Fatal("no wait armed its timer")
		return nil
	}
}

func (ft *fakeTimer) fire() { ft.c <- time.Time{} }

type statusResult struct {
	out StatusOutput
	err error
}

func statusAsync(m *Manager, ctx context.Context, id string, wait time.Duration) <-chan statusResult {
	c := make(chan statusResult, 1)
	go func() {
		out, err := m.statusWait(ctx, id, wait)
		c <- statusResult{out: out, err: err}
	}()
	return c
}

func receiveStatus(t *testing.T, c <-chan statusResult) statusResult {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("waiting status call did not return")
		return statusResult{}
	}
}

func newWaitManager(t *testing.T, fake *fakeEngine) (*Manager, *fakeTimers) {
	t.Helper()
	m := newTestManager(t, fake)
	timers := newFakeTimers()
	m.timer = timers.timer
	return m, timers
}

func finishedResult() transferengine.Result {
	return transferengine.Result{Kind: transferengine.KindFile, Files: 1, Bytes: 3, SHA256: "aa"}
}

func TestStatusWaitTerminalJobReturnsAtOnce(t *testing.T) {
	m, timers := newWaitManager(t, &fakeEngine{result: finishedResult()})
	start := startJob(t, m, false, "a", "/a")
	waitForState(t, m, start.JobID, string(stateDone))
	out, err := m.statusWait(context.Background(), start.JobID, 25*time.Second)
	if err != nil || out.State != string(stateDone) || out.SHA256 != "aa" {
		t.Fatalf("statusWait = %+v, %v", out, err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("a terminal job armed a wait timer")
	}
}

func TestStatusWaitZeroAndUnknownReturnAtOnce(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	out, err := m.statusWait(context.Background(), start.JobID, 0)
	if err != nil || out.State != string(stateRunning) {
		t.Fatalf("statusWait(0) = %+v, %v", out, err)
	}
	if _, err := m.statusWait(context.Background(), "missing", 20*time.Second); err != errUnknownJob {
		t.Fatalf("unknown job error = %v", err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("an immediate call armed a wait timer")
	}
}

func TestStatusWaitReturnsOnCompletion(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{}), result: finishedResult()}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	results := statusAsync(m, context.Background(), start.JobID, 20*time.Second)
	timer := timers.next(t)
	if timer.d != 20*time.Second {
		t.Fatalf("wait armed %v, want 20s", timer.d)
	}
	fake.unblock()
	r := receiveStatus(t, results)
	if r.err != nil || r.out.State != string(stateDone) || r.out.SHA256 != "aa" || r.out.Files != 1 {
		t.Fatalf("statusWait = %+v, %v", r.out, r.err)
	}
	if !timer.stopped.Load() {
		t.Fatal("the wait left its timer armed")
	}
}

func TestStatusWaitExpiryReturnsRunningRecord(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{}), phase: "transfer"}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	flakediag.WaitFor(t, "running job to report phase=transfer", 2*time.Second, func() (string, bool) {
		out, err := m.status(start.JobID)
		if err != nil {
			return "unavailable", false
		}
		return fmt.Sprintf("state=%q phase=%q", out.State, out.Phase), out.Phase == "transfer"
	})
	results := statusAsync(m, context.Background(), start.JobID, 5*time.Second)
	timer := timers.next(t)
	timer.fire()
	r := receiveStatus(t, results)
	if r.err != nil || r.out.State != string(stateRunning) || r.out.Phase != "transfer" || r.out.Bytes != 7 {
		t.Fatalf("expired statusWait = %+v, %v", r.out, r.err)
	}
	if !timer.stopped.Load() {
		t.Fatal("the wait left its timer armed")
	}
	fake.unblock()
	waitForState(t, m, start.JobID, "")
}

func TestStatusWaitContextEndFreesWaiter(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := statusAsync(m, ctx, start.JobID, 25*time.Second)
	timers.next(t)
	cancel()
	if r := receiveStatus(t, results); r.err != errSessionClosed {
		t.Fatalf("cancelled wait = %+v, %v; want errSessionClosed", r.out, r.err)
	}
	if out, err := m.status(start.JobID); err != nil || out.State != string(stateRunning) {
		t.Fatalf("a freed waiter changed the job: %+v, %v", out, err)
	}
	// The slot came back: a new wait blocks again.
	again := statusAsync(m, context.Background(), start.JobID, 25*time.Second)
	timers.next(t).fire()
	if r := receiveStatus(t, again); r.err != nil || r.out.State != string(stateRunning) {
		t.Fatalf("second wait = %+v, %v", r.out, r.err)
	}
}

func TestStatusWaitSessionCloseFreesWaiters(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	first := statusAsync(m, context.Background(), start.JobID, 25*time.Second)
	second := statusAsync(m, context.Background(), start.JobID, 25*time.Second)
	timers.next(t)
	timers.next(t)
	closeWithin(t, m)
	for _, results := range []<-chan statusResult{first, second} {
		r := receiveStatus(t, results)
		switch {
		case r.err == errSessionClosed:
		case r.err == nil && r.out.State == string(stateCancelled):
		default:
			t.Fatalf("wait after close = %+v, %v", r.out, r.err)
		}
	}
}

func TestStatusWaitJobCancelFreesWaiter(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	results := statusAsync(m, context.Background(), start.JobID, 25*time.Second)
	timers.next(t)
	if out, err := m.cancelJob(start.JobID); err != nil || !out.Cancelled {
		t.Fatalf("cancel = %+v, %v", out, err)
	}
	r := receiveStatus(t, results)
	if r.err != nil || r.out.State != string(stateCancelled) || r.out.ErrorClass != "cancelled" {
		t.Fatalf("wait after cancel = %+v, %v", r.out, r.err)
	}
}

func TestStatusWaitersAreBounded(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{})}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	var waiting []<-chan statusResult
	var armed []*fakeTimer
	for i := 0; i < jobwait.MaxSlots; i++ {
		waiting = append(waiting, statusAsync(m, context.Background(), start.JobID, 25*time.Second))
		armed = append(armed, timers.next(t))
	}
	// Every slot is taken: one more call answers at once and arms nothing.
	extra := statusAsync(m, context.Background(), start.JobID, 25*time.Second)
	if r := receiveStatus(t, extra); r.err != nil || r.out.State != string(stateRunning) {
		t.Fatalf("call beyond the bound = %+v, %v", r.out, r.err)
	}
	if len(timers.armed) != 0 {
		t.Fatal("a call beyond the bound armed a wait timer")
	}
	for _, timer := range armed {
		timer.fire()
	}
	for _, results := range waiting {
		if r := receiveStatus(t, results); r.err != nil || r.out.State != string(stateRunning) {
			t.Fatalf("expired wait = %+v, %v", r.out, r.err)
		}
	}
	// The slots came back.
	again := statusAsync(m, context.Background(), start.JobID, 25*time.Second)
	timers.next(t).fire()
	if r := receiveStatus(t, again); r.err != nil {
		t.Fatalf("wait after the slots were released: %v", r.err)
	}
}

func TestHandleStatusWaitSeconds(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{}), result: finishedResult()}
	m, timers := newWaitManager(t, fake)
	start := startJob(t, m, false, "a", "/a")

	reply, handled := m.Handle(context.Background(), wire.Request{
		Operation: "transfer_status",
		Data:      mustEncode(t, StatusInput{JobID: start.JobID, WaitSeconds: -1}),
	})
	if !handled || reply.OK || reply.Error != jobwait.ErrWaitRange.Error() {
		t.Fatalf("negative wait: reply = %+v, handled = %v", reply, handled)
	}

	waitData := mustEncode(t, StatusInput{JobID: start.JobID, WaitSeconds: 1000})
	replies := make(chan wire.Reply, 1)
	go func() {
		reply, _ := m.Handle(context.Background(), wire.Request{Operation: "transfer_status", Data: waitData})
		replies <- reply
	}()
	timer := timers.next(t)
	if timer.d != jobwait.MaxSeconds*time.Second {
		t.Fatalf("a wait of 1000 s armed %v, want the 25 s cap", timer.d)
	}
	timer.fire()
	select {
	case reply := <-replies:
		var out StatusOutput
		if !reply.OK || wire.Decode(reply.Data, &out) != nil || out.State != string(stateRunning) {
			t.Fatalf("expired wait reply = %+v", reply)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("transfer_status with wait_seconds did not return")
	}

	reply, handled = m.Handle(context.Background(), wire.Request{
		Operation: "transfer_status",
		Data:      mustEncode(t, StatusInput{JobID: "missing", WaitSeconds: 10}),
	})
	if !handled || reply.OK || reply.Error != errUnknownJob.Error() {
		t.Fatalf("unknown job with a wait: reply = %+v, handled = %v", reply, handled)
	}
}
