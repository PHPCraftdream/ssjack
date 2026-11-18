package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
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
	flakediag.WaitFor(t, "running job to report phase=transfer bytes=7 state=running", 2*time.Second, func() (string, bool) {
		out, err := m.status(start.JobID)
		if err != nil {
			return "unavailable", false
		}
		return fmt.Sprintf("state=%q phase=%q bytes=%d", out.State, out.Phase, out.Bytes),
			out.Phase == "transfer" && out.Bytes == 7 && out.State == string(stateRunning)
	})
	out, err := m.status(start.JobID)
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if out.Phase != "transfer" || out.Bytes != 7 || out.State != string(stateRunning) {
		t.Fatalf("running status = %+v", out)
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

func TestStatusLinkUnstableHasItsFixedMessage(t *testing.T) {
	fake := &fakeEngine{err: transfercore.Fail(transfercore.ClassLinkUnstable, transfercore.MsgLinkUnstable)}
	m := newTestManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	out := waitForState(t, m, start.JobID, "")
	if out.State != string(stateFailed) || out.ErrorClass != "link_unstable" {
		t.Fatalf("status = %+v", out)
	}
	if out.Message != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", out.Message)
	}
}
func TestStatusChunkFieldsCrossTheKeeperWire(t *testing.T) {
	fake := &scriptedEngine{}
	fake.set(nil, transferengine.Result{
		Kind: transferengine.KindFile, Files: 1, Bytes: 1048576, SHA256: "aa",
		Mode: transferengine.ModeChunked, ChunkBytes: 262144, ChunksDone: 4, ChunksTotal: 4, Attempts: 6, BytesPerSecond: 12345,
	}, nil)
	m := newManagerWithBuild(t, []string{"t"}, func(string) (Engine, error) { return fake, nil })
	reply, handled := m.Handle(context.Background(), wire.Request{
		Operation: "transfer_upload",
		Data:      mustEncode(t, StartInput{Target: "t", Local: "a", Remote: "/a"}),
	})
	if !handled || !reply.OK {
		t.Fatalf("upload: reply = %+v, handled = %v", reply, handled)
	}
	var started StartOutput
	if err := wire.Decode(reply.Data, &started); err != nil || started.JobID == "" {
		t.Fatalf("upload data = %q, %v", reply.Data, err)
	}
	waitForState(t, m, started.JobID, string(stateDone))
	reply, handled = m.Handle(context.Background(), wire.Request{
		Operation: "transfer_status",
		Data:      mustEncode(t, StatusInput{JobID: started.JobID}),
	})
	if !handled || !reply.OK {
		t.Fatalf("status: reply = %+v, handled = %v", reply, handled)
	}
	var out StatusOutput
	if err := wire.Decode(reply.Data, &out); err != nil {
		t.Fatalf("status data = %q, %v", reply.Data, err)
	}
	if out.State != string(stateDone) || out.Bytes != 1048576 || out.SHA256 != "aa" {
		t.Fatalf("status = %+v", out)
	}
	requireChunk(t, out, "chunked", 262144, 4, 4, 6, 12345)
}
