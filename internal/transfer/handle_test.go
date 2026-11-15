package transfer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestStatusStates(t *testing.T) {
	t.Run("failed hides raw error text", func(t *testing.T) {
		fake := &fakeEngine{err: errors.New("/private/secret raw failure text")}
		m := newTestManager(t, fake)
		start := startJob(t, m, true, "a", "/a")
		out := waitForState(t, m, start.JobID, "")
		if out.State != string(stateFailed) || out.ErrorClass != "internal" || out.Message != "transfer failed" {
			t.Fatalf("status = %+v", out)
		}
		encoded := mustEncode(t, out)
		if strings.Contains(encoded, "/private/secret") || strings.Contains(encoded, "raw failure text") {
			t.Fatalf("status leaks error text: %s", encoded)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		fake := &fakeEngine{err: context.Canceled}
		m := newTestManager(t, fake)
		start := startJob(t, m, false, "a", "/a")
		out := waitForState(t, m, start.JobID, "")
		if out.State != string(stateCancelled) || out.ErrorClass != "cancelled" || out.Message != "transfer was cancelled" {
			t.Fatalf("status = %+v", out)
		}
	})
	t.Run("classified limit failure", func(t *testing.T) {
		fake := &fakeEngine{err: transfercore.Fail(transfercore.ClassLimit, "transfer exceeds the configured limits")}
		m := newTestManager(t, fake)
		start := startJob(t, m, false, "a", "/a")
		out := waitForState(t, m, start.JobID, "")
		if out.State != string(stateFailed) || out.ErrorClass != "limit" {
			t.Fatalf("status = %+v", out)
		}
	})
}

func TestStatusOfRunningJobShowsPhase(t *testing.T) {
	fake := &fakeEngine{block: make(chan struct{}), phase: "transfer"}
	m := newTestManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	deadline := time.Now().Add(2 * time.Second)
	for {
		out, err := m.status(start.JobID)
		if err != nil {
			t.Fatalf("status failed: %v", err)
		}
		if out.Phase == "transfer" && out.Bytes == 7 && out.State == string(stateRunning) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("running status = %+v", out)
		}
		time.Sleep(5 * time.Millisecond)
	}
	fake.unblock()
	waitForState(t, m, start.JobID, "")
}

func TestNoRootsFailsClosed(t *testing.T) {
	m, err := NewManager(nil, []string{"t"}, transfercore.DefaultLimits(), func(string) (Engine, error) { return &fakeEngine{}, nil })
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	t.Cleanup(m.Close)
	data := mustEncode(t, StartInput{Target: "t", Local: "a", Remote: "/a"})
	for _, operation := range []string{"transfer_upload", "transfer_download", "transfer_status", "transfer_cancel"} {
		reply, handled := m.Handle(context.Background(), wire.Request{Operation: operation, Data: data})
		if !handled || reply.OK || reply.Error != errNoRoots.Error() {
			t.Fatalf("%s reply = %+v, handled = %v", operation, reply, handled)
		}
	}
	if _, err := m.start(StartInput{Target: "t", Local: "a", Remote: "/a"}, false); err != errNoRoots {
		t.Fatalf("start error = %v, want errNoRoots", err)
	}
	if _, err := m.status("missing"); err != errUnknownJob {
		t.Fatalf("status error = %v", err)
	}
	if _, err := m.cancelJob("missing"); err != errUnknownJob {
		t.Fatalf("cancel error = %v", err)
	}
}

func TestHandleRouting(t *testing.T) {
	m := newTestManager(t, &fakeEngine{})
	if reply, handled := m.Handle(context.Background(), wire.Request{Operation: "transfer_other"}); handled || reply.OK {
		t.Fatalf("unknown operation: reply = %+v, handled = %v", reply, handled)
	}
	if reply, handled := m.Handle(context.Background(), wire.Request{Operation: "transfer_upload", Data: "{broken"}); !handled || reply.OK {
		t.Fatalf("invalid data: reply = %+v, handled = %v", reply, handled)
	}
	reply, handled := m.Handle(context.Background(), wire.Request{
		Operation: "transfer_upload",
		Data:      mustEncode(t, StartInput{Target: "t", Local: "a", Remote: "/a"}),
	})
	if !handled || !reply.OK {
		t.Fatalf("upload: reply = %+v, handled = %v", reply, handled)
	}
	var out StartOutput
	if wire.Decode(reply.Data, &out) != nil || out.JobID == "" {
		t.Fatalf("upload data = %q", reply.Data)
	}
	if reply, handled := m.Handle(context.Background(), wire.Request{
		Operation: "transfer_status",
		Data:      mustEncode(t, StatusInput{JobID: "missing"}),
	}); !handled || reply.OK || reply.Error != errUnknownJob.Error() {
		t.Fatalf("unknown status: reply = %+v, handled = %v", reply, handled)
	}
}

func TestTargetMustBeApproved(t *testing.T) {
	m := newTestManager(t, &fakeEngine{})
	_, err := m.start(StartInput{Target: "unregistered", Local: "a", Remote: "/a"}, false)
	if err == nil || err.Error() != "target is not allowed" {
		t.Fatalf("error = %v, want target is not allowed", err)
	}
}

func TestRootSelection(t *testing.T) {
	m := newTestManager(t, &fakeEngine{})
	reply, handled := m.Handle(context.Background(), wire.Request{
		Operation: "transfer_upload",
		Data:      mustEncode(t, StartInput{Target: "t", Root: "other", Local: "a", Remote: "/a"}),
	})
	if !handled || reply.OK {
		t.Fatalf("unregistered root: reply = %+v, handled = %v", reply, handled)
	}
	start := startJob(t, m, false, "a", "/a")
	waitForState(t, m, start.JobID, "")
}
