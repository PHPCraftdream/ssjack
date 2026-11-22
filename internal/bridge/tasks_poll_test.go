package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestTaskPollsQueueOnTheKeeperConnection(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	entered := make(chan struct{}, 1)
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	defer release()
	keeper.setStatus(func(call int, input transfer.StatusInput) wire.Reply {
		if call == 1 {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
			return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "running", Direction: "upload", Phase: "first", Bytes: 1}, nil)
		}
		return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "running", Direction: "upload", Phase: "second", Bytes: 1}, nil)
	})
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	blocked := make(chan error, 1)
	go func() {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "transfer_status", Arguments: map[string]any{"job_id": strings.Repeat("0", 64), "wait_seconds": 20}})
		blocked <- err
	}()
	done, desc, _ := flakediag.WaitForDesc(t, "the waiting transfer_status call to reach the keeper", 10*time.Second, func() (string, bool, error) {
		select {
		case <-entered:
			return "the keeper is holding the call", true, nil
		default:
			return "the call has not reached the keeper yet", false, nil
		}
	})
	if !done {
		t.Fatalf("the waiting call never reached the keeper: %s", desc)
	}
	type polledAnswer struct {
		answer *taskAnswer
		err    error
	}
	polled := make(chan polledAnswer, 1)
	go func() {
		answer, err := taskGet(ctx, session, id)
		polled <- polledAnswer{answer: answer, err: err}
	}()
	done, desc, _ = flakediag.WaitForDesc(t, "the poll to wait on the broker client mutex", 10*time.Second, func() (string, bool, error) {
		dump := flakediag.GoroutineDump(256 << 10)
		for _, block := range strings.Split(dump, "\n\n") {
			if strings.Contains(block, "[sync.Mutex.Lock") && strings.Contains(block, "internal/broker") && strings.Contains(block, "(*Client).Call") {
				return block, true, nil
			}
		}
		return "no broker client mutex wait in the dump", false, nil
	})
	if !done {
		t.Fatalf("the poll never queued on the broker client mutex: %s", desc)
	}
	if ops := keeper.ops(); len(ops) != 2 {
		t.Fatalf("the keeper saw %d operations before the release, want 2: %v", len(ops), ops)
	}
	release()
	var got polledAnswer
	done, desc, _ = flakediag.WaitForDesc(t, "tasks/get to answer once the keeper replied", 10*time.Second, func() (string, bool, error) {
		select {
		case got = <-polled:
			return "tasks/get answered", true, nil
		default:
			return "tasks/get is still queued", false, nil
		}
	})
	if !done {
		t.Fatalf("tasks/get never answered after the keeper replied: %s", desc)
	}
	if got.err != nil {
		t.Fatalf("tasks/get failed: %v", got.err)
	}
	if got.answer == nil {
		t.Fatal("tasks/get answered no task")
	}
	if got.answer.Status != "working" {
		t.Fatalf("the poll reported %q, want working", got.answer.Status)
	}
	if !strings.Contains(got.answer.StatusMessage, "Phase: second") {
		t.Fatalf("the poll reported %q, want the second record", got.answer.StatusMessage)
	}
	if ops := keeper.ops(); len(ops) != 3 {
		t.Fatalf("the keeper saw %d operations after the poll, want 3: %v", len(ops), ops)
	}
	if reads := countOps(keeper.ops(), "transfer_status"); reads != 2 {
		t.Fatalf("the keeper read %d statuses, want 2", reads)
	}
	var blockedErr error
	done, desc, _ = flakediag.WaitForDesc(t, "the waiting transfer_status call to return", 10*time.Second, func() (string, bool, error) {
		select {
		case blockedErr = <-blocked:
			return "the waiting call returned", true, nil
		default:
			return "the waiting call is still running", false, nil
		}
	})
	if !done {
		t.Fatalf("the waiting call never returned: %s", desc)
	}
	if blockedErr != nil {
		t.Fatalf("the waiting call failed: %v", blockedErr)
	}
}

func TestTaskCancelAcknowledgesAfterTheKeeperReply(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	entered := make(chan struct{}, 1)
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	keeper := &taskKeeper{}
	keeper.setCancel(func(transfer.CancelInput) wire.Reply {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
		return broker.Result(transfer.CancelOutput{Cancelled: true}, nil)
	})
	keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return runningRecord(input) })
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	type cancelledAnswer struct {
		ack *taskAckAnswer
		err error
	}
	acks := make(chan cancelledAnswer, 1)
	go func() {
		ack, err := taskCancel(ctx, session, id)
		acks <- cancelledAnswer{ack: ack, err: err}
	}()
	done, desc, _ := flakediag.WaitForDesc(t, "tasks/cancel to reach the keeper", 10*time.Second, func() (string, bool, error) {
		select {
		case <-entered:
			return "the keeper holds the cancellation", true, nil
		default:
			return "the cancellation has not reached the keeper yet", false, nil
		}
	})
	if !done {
		t.Fatalf("tasks/cancel never reached the keeper: %s", desc)
	}
	select {
	case <-acks:
		t.Fatal("tasks/cancel was acknowledged before the keeper answered")
	default:
	}
	release()
	var got cancelledAnswer
	done, desc, _ = flakediag.WaitForDesc(t, "tasks/cancel to be acknowledged", 10*time.Second, func() (string, bool, error) {
		select {
		case got = <-acks:
			return "tasks/cancel was acknowledged", true, nil
		default:
			return "tasks/cancel is still waiting for the keeper", false, nil
		}
	})
	if !done {
		t.Fatalf("tasks/cancel was never acknowledged: %s", desc)
	}
	if got.err != nil {
		t.Fatalf("tasks/cancel failed: %v", got.err)
	}
	if got.ack == nil {
		t.Fatal("tasks/cancel answered no acknowledgement")
	}
	if got.ack.ResultType != "complete" {
		t.Fatalf("tasks/cancel answered %q", got.ack.ResultType)
	}
	if cancels := countOps(keeper.ops(), "transfer_cancel"); cancels != 1 {
		t.Fatalf("the keeper saw %d cancellations, want 1", cancels)
	}
}

// requireTaskResultText checks that a completed task result is exactly the
// transfer_status text of its record.
func requireTaskResultText(t *testing.T, answer *taskAnswer, toolText string) {
	t.Helper()
	if answer == nil {
		t.Fatal("tasks/get answered no task")
	}
	if answer.Result == nil {
		t.Fatal("a completed task carried no result")
	}
	if len(answer.Result.Content) != 1 {
		t.Fatalf("the task result is not one content block: %+v", answer.Result)
	}
	text, ok := answer.Result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("the task result is not text: %T", answer.Result.Content[0])
	}
	if text.Text != toolText {
		t.Fatalf("the task result is %q, want the status text %q", text.Text, toolText)
	}
}

func TestTaskCancellationComesFromTheRecord(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t.Run("true then running then cancelled", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setCancel(func(transfer.CancelInput) wire.Reply {
			return broker.Result(transfer.CancelOutput{Cancelled: true}, nil)
		})
		keeper.setStatus(func(call int, input transfer.StatusInput) wire.Reply {
			if call == 1 {
				return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "running", Direction: "upload", Phase: "one"}, nil)
			}
			return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "cancelled", Direction: "upload"}, nil)
		})
		session, _ := newTaskBridge(t, ctx, keeper, newTestClock().Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		ack, err := taskCancel(ctx, session, id)
		if err != nil || ack == nil {
			t.Fatalf("tasks/cancel failed: %+v, %v", ack, err)
		}
		running, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if running.Status != "working" {
			t.Fatalf("a cancelled request left the task %q, want working", running.Status)
		}
		final, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if final.Status != "cancelled" {
			t.Fatalf("the task reported %q, want cancelled", final.Status)
		}
		if final.StatusMessage != "Cancelled job "+id {
			t.Fatalf("the task reported %q", final.StatusMessage)
		}
		if final.Result != nil {
			t.Fatalf("a cancelled task carried a result: %+v", final.Result)
		}
	})
	t.Run("true then done", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setCancel(func(transfer.CancelInput) wire.Reply {
			return broker.Result(transfer.CancelOutput{Cancelled: true}, nil)
		})
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return doneRecord(input) })
		session, _ := newTaskBridge(t, ctx, keeper, newTestClock().Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		ack, err := taskCancel(ctx, session, id)
		if err != nil || ack == nil {
			t.Fatalf("tasks/cancel failed: %+v, %v", ack, err)
		}
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "completed" {
			t.Fatalf("a finished job reported %q, want completed", answer.Status)
		}
		toolText := answerText(t, callTaskTool(t, ctx, session, "transfer_status", map[string]any{"job_id": id}))
		requireTaskResultText(t, answer, toolText)
	})
	t.Run("false then cancelled", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setCancel(func(transfer.CancelInput) wire.Reply {
			return broker.Result(transfer.CancelOutput{Cancelled: false}, nil)
		})
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply {
			return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "cancelled", Direction: "upload"}, nil)
		})
		session, _ := newTaskBridge(t, ctx, keeper, newTestClock().Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		ack, err := taskCancel(ctx, session, id)
		if err != nil || ack == nil {
			t.Fatalf("tasks/cancel failed: %+v, %v", ack, err)
		}
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "cancelled" {
			t.Fatalf("the task reported %q, want cancelled", answer.Status)
		}
	})
	t.Run("false then failed", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setCancel(func(transfer.CancelInput) wire.Reply {
			return broker.Result(transfer.CancelOutput{Cancelled: false}, nil)
		})
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply {
			return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "failed", Direction: "upload", ErrorClass: "refused_path", Message: "transfer path was refused"}, nil)
		})
		session, _ := newTaskBridge(t, ctx, keeper, newTestClock().Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		ack, err := taskCancel(ctx, session, id)
		if err != nil || ack == nil {
			t.Fatalf("tasks/cancel failed: %+v, %v", ack, err)
		}
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "completed" {
			t.Fatalf("a failed job reported %q, want completed", answer.Status)
		}
		toolText := answerText(t, callTaskTool(t, ctx, session, "transfer_status", map[string]any{"job_id": id}))
		requireTaskResultText(t, answer, toolText)
	})
	t.Run("false then done", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setCancel(func(transfer.CancelInput) wire.Reply {
			return broker.Result(transfer.CancelOutput{Cancelled: false}, nil)
		})
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return doneRecord(input) })
		session, _ := newTaskBridge(t, ctx, keeper, newTestClock().Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		ack, err := taskCancel(ctx, session, id)
		if err != nil || ack == nil {
			t.Fatalf("tasks/cancel failed: %+v, %v", ack, err)
		}
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "completed" {
			t.Fatalf("a finished job reported %q, want completed", answer.Status)
		}
	})
}

func TestTaskFrozenFailedWhenTheKeeperLostTheJob(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	keeper.setStatus(func(int, transfer.StatusInput) wire.Reply { return wire.Reply{Error: "unknown transfer job"} })
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	first, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get failed: %v", err)
	}
	if first.Status != "failed" {
		t.Fatalf("a lost job reported %q, want failed", first.Status)
	}
	if first.Result != nil {
		t.Fatalf("a failed task carried a result: %+v", first.Result)
	}
	if first.Error == nil {
		t.Fatal("a failed task carried no error")
	}
	if first.Error.Code != -32603 || first.Error.Message != "the task could not be read" {
		t.Fatalf("a failed task carried %d %q", first.Error.Code, first.Error.Message)
	}
	reads := countOps(keeper.ops(), "transfer_status")
	if reads != 1 {
		t.Fatalf("the keeper read %d statuses, want 1", reads)
	}
	second, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get failed: %v", err)
	}
	if second.Status != first.Status {
		t.Fatalf("the frozen task changed to %q, want %q", second.Status, first.Status)
	}
	if second.LastUpdatedAt != first.LastUpdatedAt {
		t.Fatalf("the frozen task was updated at %q, want %q", second.LastUpdatedAt, first.LastUpdatedAt)
	}
	if second.Error == nil || second.Error.Code != first.Error.Code || second.Error.Message != first.Error.Message {
		t.Fatalf("the frozen task error changed: %+v, want %+v", second.Error, first.Error)
	}
	if after := countOps(keeper.ops(), "transfer_status"); after != reads {
		t.Fatalf("a frozen task read the keeper: %d reads, want %d", after, reads)
	}
}

func TestTaskRetriesAWellFormedReadError(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	keeper.setStatus(func(call int, input transfer.StatusInput) wire.Reply {
		if call == 1 {
			return wire.Reply{Error: "keeper refused the read"}
		}
		return doneRecord(input)
	})
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	if _, err := taskGet(ctx, session, id); err == nil {
		t.Fatal("a refused read answered a task")
	} else {
		wireErr := rpcError(t, err)
		if wireErr.Code != -32603 {
			t.Fatalf("a refused read answered %d, want -32603", wireErr.Code)
		}
		if wireErr.Message != "the task could not be read" {
			t.Fatalf("a refused read answered %q", wireErr.Message)
		}
	}
	answer, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get after a refused read failed: %v", err)
	}
	if answer.Status != "completed" {
		t.Fatalf("a finished job reported %q, want completed", answer.Status)
	}
	toolText := answerText(t, callTaskTool(t, ctx, session, "transfer_status", map[string]any{"job_id": id}))
	requireTaskResultText(t, answer, toolText)
}

func TestTaskFreezesFailedOnALostAttachment(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	session, keeperServer := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	keeperServer.Close()
	first, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get after a lost attachment failed: %v", err)
	}
	if first.Status != "failed" {
		t.Fatalf("a lost attachment reported %q, want failed", first.Status)
	}
	if first.Error == nil {
		t.Fatal("a failed task carried no error")
	}
	if first.Error.Code != -32603 || first.Error.Message != "the task could not be read" {
		t.Fatalf("a failed task carried %d %q", first.Error.Code, first.Error.Message)
	}
	second, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("the second tasks/get failed: %v", err)
	}
	if second.Status != first.Status {
		t.Fatalf("the frozen task changed to %q, want %q", second.Status, first.Status)
	}
	if second.LastUpdatedAt != first.LastUpdatedAt {
		t.Fatalf("the frozen task was updated at %q, want %q", second.LastUpdatedAt, first.LastUpdatedAt)
	}
	if second.Error == nil || second.Error.Code != first.Error.Code || second.Error.Message != first.Error.Message {
		t.Fatalf("the frozen task error changed: %+v, want %+v", second.Error, first.Error)
	}
}

func TestTaskResultEqualsTheStatusText(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply {
		return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "done", Direction: "upload", Kind: "file", Bytes: 3, Files: 1, SHA256: "aa", ErrorClass: "link_unstable", Message: "link was unstable"}, nil)
	})
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	toolText := answerText(t, callTaskTool(t, ctx, session, "transfer_status", map[string]any{"job_id": id}))
	answer, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get failed: %v", err)
	}
	if answer.Status != "completed" {
		t.Fatalf("a finished job reported %q, want completed", answer.Status)
	}
	requireTaskResultText(t, answer, toolText)
	if !strings.Contains(toolText, "Resume:") {
		t.Fatalf("the compared status text carries no resume hint: %q", toolText)
	}
}

func TestTaskBoundsDropTheOldestHandle(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	ids := make([]string, 0, 65)
	for i := 0; i < 65; i++ {
		ids = append(ids, startTask(t, ctx, session, keeper))
	}
	reads := countOps(keeper.ops(), "transfer_status")
	if reads != 0 {
		t.Fatalf("the starts read %d statuses, want none", reads)
	}
	_, err := taskGet(ctx, session, ids[0])
	if err == nil {
		t.Fatal("the oldest handle was still answered")
	}
	if code := rpcError(t, err).Code; code != -32602 {
		t.Fatalf("the oldest handle answered %d, want -32602", code)
	}
	if after := countOps(keeper.ops(), "transfer_status"); after != reads {
		t.Fatalf("the oldest handle read the keeper: %d reads, want %d", after, reads)
	}
	keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return runningRecord(input) })
	newest, err := taskGet(ctx, session, ids[64])
	if err != nil {
		t.Fatalf("tasks/get of the newest handle failed: %v", err)
	}
	if newest.Status != "working" {
		t.Fatalf("the newest handle reported %q, want working", newest.Status)
	}
}

func TestTaskPollComparesTheKeeperRecordNotItsRenderedSpeed(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	keeper := &taskKeeper{}
	keeper.setStatus(func(call int, input transfer.StatusInput) wire.Reply {
		rate := int64(1_300_000)
		if call > 1 {
			rate = 1_300_001
		}
		return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "running", Direction: "upload", Phase: "transfer", Bytes: 52428800, BytesPerSecond: rate}, nil)
	})
	session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	first, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("the first tasks/get failed: %v", err)
	}
	clock.Advance(time.Second)
	second, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("the second tasks/get failed: %v", err)
	}
	if first.StatusMessage != second.StatusMessage {
		t.Fatalf("the rounded record changed the status message: %q then %q", first.StatusMessage, second.StatusMessage)
	}
	if !strings.Contains(second.StatusMessage, "Speed: 1.3 MB/s") {
		t.Fatalf("the status message carries no rounded speed: %q", second.StatusMessage)
	}
	before, err := time.Parse(time.RFC3339, first.LastUpdatedAt)
	if err != nil {
		t.Fatalf("the first lastUpdatedAt is not RFC 3339: %v", err)
	}
	after, err := time.Parse(time.RFC3339, second.LastUpdatedAt)
	if err != nil {
		t.Fatalf("the second lastUpdatedAt is not RFC 3339: %v", err)
	}
	if !after.After(before) {
		t.Fatalf("a changed record left lastUpdatedAt at %s, want later than %s", second.LastUpdatedAt, first.LastUpdatedAt)
	}
}

// pipeTap records both directions of the bridge pipe as whole JSON-RPC lines
// before the SDK decodes them, and can rewrite the server->client ones.
type pipeTap struct {
	mu     sync.Mutex
	reader io.ReadCloser
	writer io.WriteCloser
	down   bytes.Buffer
	up     bytes.Buffer
	wrap   func(string) string
	once   sync.Once
}

func (t *pipeTap) pipes() (mcp.Transport, mcp.Transport) {
	serverIn, clientWrite := io.Pipe()
	clientRead, serverWrite := io.Pipe()
	t.reader, t.writer = clientRead, clientWrite
	return &mcp.IOTransport{Reader: serverIn, Writer: serverWrite}, &mcp.IOTransport{Reader: t, Writer: t}
}

func (t *pipeTap) Read(p []byte) (int, error) {
	n, err := t.reader.Read(p)
	t.mu.Lock()
	t.down.Write(p[:n])
	t.mu.Unlock()
	return n, err
}

func (t *pipeTap) Write(p []byte) (int, error) {
	n, err := t.writer.Write(p)
	t.mu.Lock()
	t.up.Write(p[:n])
	t.mu.Unlock()
	return n, err
}

func (t *pipeTap) Close() error {
	t.once.Do(func() { t.reader.Close(); t.writer.Close() })
	return nil
}

// recorded returns one direction as whole lines, rewritten by wrap.
func (t *pipeTap) recorded(buf *bytes.Buffer, wrap func(string) string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var lines []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if wrap != nil {
				line = wrap(line)
			}
			lines = append(lines, line)
		}
	}
	return lines
}

// taskFrames returns every recorded server->client frame with the method of
// the request it answers.
func (t *pipeTap) taskFrames() [][2]string {
	methods := make(map[string]string)
	for _, frame := range t.recorded(&t.up, nil) {
		var sent struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal([]byte(frame), &sent) == nil && len(sent.ID) != 0 {
			methods[string(sent.ID)] = sent.Method
		}
	}
	var frames [][2]string
	for _, frame := range t.recorded(&t.down, t.wrap) {
		var answer struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal([]byte(frame), &answer) != nil {
			continue
		}
		if method, ok := methods[string(answer.ID)]; ok && taskResultMembers[method] != "" {
			frames = append(frames, [2]string{method, frame})
		}
	}
	return frames
}

// taskResultMembers lists the result member names the design allows per method.
var taskResultMembers = map[string]string{
	"tools/call":   "resultType taskId status statusMessage createdAt lastUpdatedAt ttlMs pollIntervalMs _meta",
	"tasks/get":    "resultType taskId status statusMessage createdAt lastUpdatedAt ttlMs pollIntervalMs result error _meta",
	"tasks/cancel": "resultType _meta",
	"tasks/update": "resultType _meta",
}

// taskFrameViolation names the first member of one task frame the design does
// not allow, or returns "".
func taskFrameViolation(method, frame string) string {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(frame), &envelope); err != nil {
		return fmt.Sprintf("the %s frame did not decode: %v: %s", method, err, frame)
	}
	for name := range envelope {
		if !strings.Contains(" jsonrpc id result error ", " "+name+" ") {
			return fmt.Sprintf("the %s frame carries the extra top-level member %q: %s", method, name, frame)
		}
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(envelope["result"], &result) != nil {
		return ""
	}
	for name := range result {
		if !strings.Contains(" "+taskResultMembers[method]+" ", " "+name+" ") {
			return fmt.Sprintf("the %s result carries the extra member %q: %s", method, name, frame)
		}
	}
	return ""
}

// sentinelRecord is a successful status record whose every displayed field
// carries its own marker.
func sentinelRecord(state string) transfer.StatusOutput {
	return transfer.StatusOutput{
		JobID: "SENTINEL-JOB", State: state, Direction: "SENTINEL-DIRECTION", Phase: "SENTINEL-PHASE", Kind: "SENTINEL-KIND",
		Mode: "SENTINEL-MODE", Files: 8675309, Dirs: 8675310, Bytes: 987654321, SHA256: "SENTINEL-SHA256",
		ManifestSHA256: "SENTINEL-MANIFEST", ErrorClass: "SENTINEL-ERRORCLASS", ChunkBytes: 3141592,
		ChunksDone: 123456, ChunksTotal: 123457, Attempts: 987656, BytesPerSecond: 2718281828,
	}
}

// sentinelForms pairs each record sentinel with the rendered form the status
// line groups or rounds.
var sentinelForms = [][2]string{
	{"SENTINEL-JOB"}, {"SENTINEL-DIRECTION"}, {"SENTINEL-PHASE"}, {"SENTINEL-KIND"}, {"SENTINEL-MODE"},
	{"SENTINEL-SHA256"}, {"SENTINEL-MANIFEST"}, {"SENTINEL-ERRORCLASS"}, {"8675309"}, {"8675310"},
	{"987654321", "987,654,321"}, {"3141592", "3,141,592"}, {"123456"}, {"123457"},
	{"987656", "987,656"}, {"2718281828", "2.7 GB/s"},
}

// sentinelLine and sentinelText are the status message and completed text of
// the sentinel record.
var sentinelLine = "Phase: SENTINEL-PHASE · Mode: SENTINEL-MODE · Chunks: 123456/123457 · Chunk size: 3,141,592 bytes · Attempts: 987,656 · Bytes: 987,654,321 · Files: 8675309 · Dirs: 8675310 · Speed: 2.7 GB/s · SHA-256: SENTINEL-SHA256 · Manifest SHA-256: SENTINEL-MANIFEST · Failed: SENTINEL-ERRORCLASS"
var sentinelText = "Transfer SENTINEL-JOB: SENTINEL-DIRECTION SENTINEL-KIND, done\n" + strings.ReplaceAll(sentinelLine, " · ", "\n")

// leakedSentinel returns the first record sentinel a frame still carries after
// removing the exact texts the test expects the frame to carry.
func leakedSentinel(frame []byte, expect ...string) string {
	body := frame
	for _, text := range expect {
		if encoded, err := json.Marshal(text); err == nil {
			body = bytes.Replace(body, encoded, nil, 1)
		}
	}
	for _, pair := range sentinelForms {
		for _, form := range pair {
			if form != "" && bytes.Contains(body, []byte(form)) {
				return form
			}
		}
	}
	return ""
}

func TestTaskRawCheckNamesAnInjectedMember(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tap := &pipeTap{wrap: func(frame string) string { return frame[:len(frame)-1] + `,"task-leak":true}` }}
	keeper := &taskKeeper{}
	session, _ := newTaskBridgeWith(t, ctx, keeper, nil, true, "2026-07-28", tap.pipes, nil)
	startTask(t, ctx, session, keeper)
	for _, frame := range tap.taskFrames() {
		if violation := taskFrameViolation(frame[0], frame[1]); strings.Contains(violation, `"task-leak"`) {
			return
		}
	}
	t.Fatal("the frame check did not name the injected member")
}

func TestTaskCancelAckCaptureCorrelatesByRequestID(t *testing.T) {
	tap := &pipeTap{}
	tap.up.WriteString(`{"jsonrpc":"2.0","id":7,"method":"tasks/cancel","params":{}}` + "\n")
	tap.down.WriteString(`{"jsonrpc":"2.0","id":6,"result":{"resultType":"complete"}}` + "\n")
	if frames := tap.taskFrames(); len(frames) != 0 {
		t.Fatalf("the capture took another request's answer: %v", frames)
	}
	tap.down.WriteString(`{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete"}}` + "\n")
	frames := tap.taskFrames()
	if len(frames) != 1 || frames[0][0] != "tasks/cancel" {
		t.Fatalf("the capture did not take the answer to the outbound tasks/cancel: %v", frames)
	}
}

func TestTaskSentinelCheckNamesARenderedCopy(t *testing.T) {
	line, err := json.Marshal(sentinelLine)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte(`{"jsonrpc":"2.0","id":1,"result":{"statusMessage":` + string(line) + `,"echo":` + string(line) + `}}`)
	if leaked := leakedSentinel(frame, sentinelLine); leaked == "" {
		t.Fatal("the sentinel check did not see the rendered status line copied into an extra member")
	}
}
