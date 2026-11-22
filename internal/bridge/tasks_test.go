package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	tooltext "github.com/PHPCraftdream/ssjack/internal/bridge/internal/tooltext"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// taskExtension is the identifier of the MCP tasks extension.
const taskExtension = "io.modelcontextprotocol/tasks"

// The client-side wire shapes of the three task methods. They mirror the
// server's shapes so that the acceptance tests speak the extension directly.
type taskGetParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

type taskCancelParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

type taskUpdateParams struct {
	mcp.ParamsBase
	TaskID         string                     `json:"taskId"`
	InputResponses map[string]json.RawMessage `json:"inputResponses,omitempty"`
}

type taskFailureWire struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type taskAnswer struct {
	mcp.ResultBase
	ResultType     string              `json:"resultType"`
	TaskID         string              `json:"taskId"`
	Status         string              `json:"status"`
	StatusMessage  string              `json:"statusMessage"`
	CreatedAt      string              `json:"createdAt"`
	LastUpdatedAt  string              `json:"lastUpdatedAt"`
	TTLMs          int64               `json:"ttlMs"`
	PollIntervalMs int                 `json:"pollIntervalMs"`
	Result         *mcp.CallToolResult `json:"result"`
	Error          *taskFailureWire    `json:"error"`
}

type taskAckAnswer struct {
	mcp.ResultBase
	ResultType string `json:"resultType"`
}

// taskKeeper answers the keeper operations of the transfer and start tools,
// records the operations it saw and mints the job ids it hands out.
type taskKeeper struct {
	mu       sync.Mutex
	seen     []string
	ids      int
	idsUsed  []string
	statuses int
	startFn  func(input transfer.StartInput) wire.Reply
	statusFn func(call int, input transfer.StatusInput) wire.Reply
	cancelFn func(input transfer.CancelInput) wire.Reply
}

func (k *taskKeeper) handle(_ context.Context, req wire.Request) (reply wire.Reply) {
	k.mu.Lock()
	k.seen = append(k.seen, req.Operation)
	statusCall := 0
	if req.Operation == "transfer_status" {
		k.statuses++
		statusCall = k.statuses
	}
	startFn, statusFn, cancelFn := k.startFn, k.statusFn, k.cancelFn
	k.mu.Unlock()
	switch req.Operation {
	case "transfer_upload", "transfer_download":
		var input transfer.StartInput
		if wire.Decode(req.Data, &input) != nil {
			return wire.Reply{Error: "invalid transfer arguments"}
		}
		if startFn != nil {
			return startFn(input)
		}
		return broker.Result(transfer.StartOutput{JobID: k.mint()}, nil)
	case "transfer_status":
		var input transfer.StatusInput
		if wire.Decode(req.Data, &input) != nil {
			return wire.Reply{Error: "invalid transfer arguments"}
		}
		if statusFn != nil {
			return statusFn(statusCall, input)
		}
		return wire.Reply{Error: "unknown transfer job"}
	case "transfer_cancel":
		var input transfer.CancelInput
		if wire.Decode(req.Data, &input) != nil {
			return wire.Reply{Error: "invalid transfer arguments"}
		}
		if cancelFn != nil {
			return cancelFn(input)
		}
		return broker.Result(transfer.CancelOutput{Cancelled: true}, nil)
	case "start", "app_start":
		return broker.Result(remote.StartOutput{JobID: strings.Repeat("ab", 32)}, nil)
	case "targets":
		return broker.Result(remote.TargetsOutput{Targets: []string{"allowed"}}, nil)
	}
	return wire.Reply{Error: "unexpected operation"}
}

func (k *taskKeeper) mint() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ids++
	id := fmt.Sprintf("%064x", k.ids)
	k.idsUsed = append(k.idsUsed, id)
	return id
}

func (k *taskKeeper) ops() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.seen...)
}

func (k *taskKeeper) started() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.idsUsed...)
}

func (k *taskKeeper) setStart(fn func(input transfer.StartInput) wire.Reply) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.startFn = fn
}

func (k *taskKeeper) setStatus(fn func(call int, input transfer.StatusInput) wire.Reply) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.statusFn = fn
}

func (k *taskKeeper) setCancel(fn func(input transfer.CancelInput) wire.Reply) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cancelFn = fn
}

// testClock is the task retention clock of one test.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// newTaskBridge serves the full tool registry over one authenticated keeper
// connection and returns an MCP client session to it.
func newTaskBridge(t *testing.T, ctx context.Context, keeper *taskKeeper, clock func() time.Time, declareExtension bool, version string, configure ...func(*mcp.Client)) (*mcp.ClientSession, *broker.Server) {
	t.Helper()
	return newTaskBridgeWith(t, ctx, keeper, clock, declareExtension, version, nil, nil, configure...)
}

// newTaskBridgeWith builds the bridge of newTaskBridge over an optionally
// wrapped client transport.
func newTaskBridgeWith(t *testing.T, ctx context.Context, keeper *taskKeeper, clock func() time.Time, declareExtension bool, version string, pipe func() (mcp.Transport, mcp.Transport), wrap func(mcp.Transport) mcp.Transport, configure ...func(*mcp.Client)) (*mcp.ClientSession, *broker.Server) {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("5", 64), Token: strings.Repeat("6", 64)}
	server, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, keeper.handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	connection, err := broker.Connect(ctx, server.Endpoint(), server.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	if pipe == nil {
		pipe = func() (mcp.Transport, mcp.Transport) { return mcp.NewInMemoryTransports() }
	}
	serverTransport, clientTransport := pipe()
	if wrap != nil {
		clientTransport = wrap(clientTransport)
	}
	mcpServer := tooltext.NewFullServerWithClock(connection, clock)
	serverSession, err := mcpServer.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverSession.Close() })
	caps := &mcp.ClientCapabilities{}
	if declareExtension {
		caps.AddExtension(taskExtension, map[string]any{})
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "tasks-acceptance", Version: "1"}, &mcp.ClientOptions{Capabilities: caps})
	for _, apply := range configure {
		apply(client)
	}
	if err := mcp.AddSendingCustomMethod[*taskGetParams, *taskAnswer](client, "tasks/get"); err != nil {
		t.Fatal(err)
	}
	if err := mcp.AddSendingCustomMethod[*taskUpdateParams, *taskAckAnswer](client, "tasks/update"); err != nil {
		t.Fatal(err)
	}
	if err := mcp.AddSendingCustomMethod[*taskCancelParams, *taskAckAnswer](client, "tasks/cancel"); err != nil {
		t.Fatal(err)
	}
	session, err := client.Connect(ctx, clientTransport, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, server
}

// recorder keeps the frames the client read, in order.
type recorder struct {
	mu     sync.Mutex
	frames [][]byte
}

// add records one frame.
func (r *recorder) add(frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, append([]byte(nil), frame...))
}

// all returns the frames recorded so far.
func (r *recorder) all() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	frames := make([][]byte, 0, len(r.frames))
	for _, frame := range r.frames {
		frames = append(frames, append([]byte(nil), frame...))
	}
	return frames
}

// count returns the number of frames recorded so far.
func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.frames)
}

// contains reports whether one recorded frame contains text.
func (r *recorder) contains(text string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, frame := range r.frames {
		if bytes.Contains(frame, []byte(text)) {
			return true
		}
	}
	return false
}

// recordingTransport wraps a transport and records every message the client
// reads off it.
type recordingTransport struct {
	inner    mcp.Transport
	recorder *recorder
}

// Connect opens the inner connection inside the recording wrapper.
func (t *recordingTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	connection, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &recordingConnection{Connection: connection, recorder: t.recorder}, nil
}

// recordingConnection re-encodes every successfully read message for the
// recorder.
type recordingConnection struct {
	mcp.Connection
	recorder *recorder
}

// Read records the message it received.
func (c *recordingConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	message, err := c.Connection.Read(ctx)
	if err != nil {
		return message, err
	}
	if encoded, encodeErr := jsonrpc.EncodeMessage(message); encodeErr == nil {
		c.recorder.add(encoded)
	}
	return message, nil
}

func callTaskTool(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || result == nil {
		t.Fatalf("%s: %+v, %v", name, result, err)
	}
	return result
}

func startTask(t *testing.T, ctx context.Context, session *mcp.ClientSession, keeper *taskKeeper) string {
	t.Helper()
	result := callTaskTool(t, ctx, session, "remote_upload", map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"})
	if result.IsError {
		t.Fatalf("remote_upload refused: %+v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("an eligible start answered content instead of a task handle: %+v", result)
	}
	started := keeper.started()
	if len(started) == 0 {
		t.Fatal("the keeper started no job")
	}
	return started[len(started)-1]
}

func taskGet(ctx context.Context, session *mcp.ClientSession, id string) (*taskAnswer, error) {
	return mcp.CallCustomMethod[*taskGetParams, *taskAnswer](ctx, session, "tasks/get", &taskGetParams{TaskID: id})
}

func taskCancel(ctx context.Context, session *mcp.ClientSession, id string) (*taskAckAnswer, error) {
	return mcp.CallCustomMethod[*taskCancelParams, *taskAckAnswer](ctx, session, "tasks/cancel", &taskCancelParams{TaskID: id})
}

func taskUpdate(ctx context.Context, session *mcp.ClientSession, id string) (*taskAckAnswer, error) {
	return mcp.CallCustomMethod[*taskUpdateParams, *taskAckAnswer](ctx, session, "tasks/update", &taskUpdateParams{TaskID: id})
}

func rpcError(t *testing.T, err error) *jsonrpc.Error {
	t.Helper()
	var wireErr *jsonrpc.Error
	if !errors.As(err, &wireErr) {
		t.Fatalf("error %v is not a JSON-RPC error", err)
	}
	return wireErr
}

func answerText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) != 1 {
		t.Fatalf("result is not one content block: %+v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is not text: %T", result.Content[0])
	}
	return text.Text
}

// countOps counts the recorded operations of one name.
func countOps(ops []string, name string) int {
	count := 0
	for _, op := range ops {
		if op == name {
			count++
		}
	}
	return count
}

// runningRecord is a status record of a job still in progress.
func runningRecord(input transfer.StatusInput) wire.Reply {
	return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "running", Direction: "upload", Phase: "one"}, nil)
}

// doneRecord is a status record of a finished single-file transfer.
func doneRecord(input transfer.StatusInput) wire.Reply {
	return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "done", Direction: "upload", Kind: "file", Bytes: 3, Files: 1, SHA256: "aa"}, nil)
}

func TestTaskAdvertisementAndRefusals(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	t.Run("modern", func(t *testing.T) {
		session, _ := newTaskBridge(t, ctx, &taskKeeper{}, clock.Now, true, "2026-07-28")
		caps := session.InitializeResult().Capabilities
		if caps == nil {
			t.Fatal("the server advertised no capabilities")
		}
		if _, ok := caps.Extensions[taskExtension]; !ok {
			t.Fatalf("the server did not advertise %s: %+v", taskExtension, caps.Extensions)
		}
	})
	t.Run("legacy", func(t *testing.T) {
		session, _ := newTaskBridge(t, ctx, &taskKeeper{}, clock.Now, true, "2025-11-25")
		caps := session.InitializeResult().Capabilities
		if caps == nil {
			t.Fatal("the server advertised no capabilities")
		}
		if _, ok := caps.Extensions[taskExtension]; !ok {
			t.Fatalf("the server did not advertise %s: %+v", taskExtension, caps.Extensions)
		}
		_, err := taskGet(ctx, session, strings.Repeat("ab", 32))
		if err == nil {
			t.Fatal("a legacy session reached tasks/get")
		}
		if code := rpcError(t, err).Code; code != -32601 {
			t.Fatalf("a legacy session answered %d, want -32601", code)
		}
	})
	t.Run("non-declaring", func(t *testing.T) {
		keeper := &taskKeeper{}
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, false, "2026-07-28")
		_, err := taskGet(ctx, session, strings.Repeat("ab", 32))
		if err == nil {
			t.Fatal("a non-declaring session reached tasks/get")
		}
		wireErr := rpcError(t, err)
		if wireErr.Code != -32021 {
			t.Fatalf("a non-declaring session answered %d, want -32021", wireErr.Code)
		}
		if !strings.Contains(string(wireErr.Data), taskExtension) {
			t.Fatalf("the refusal does not name the required extension: %s", wireErr.Data)
		}
		before := len(keeper.ops())
		result := callTaskTool(t, ctx, session, "remote_upload", map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"})
		started := keeper.started()
		if len(started) != 1 {
			t.Fatalf("the keeper started %d jobs, want one", len(started))
		}
		id := started[0]
		want := "Started job " + id + "\nCheck progress with transfer_status job_id=" + id + "; use wait_seconds 20 to wait for it."
		if got := answerText(t, result); got != want {
			t.Fatalf("a non-declaring start answered %q, want %q", got, want)
		}
		after := keeper.ops()
		if len(after) != before+1 {
			t.Fatalf("the keeper saw %d operations, want %d: %v", len(after), before+1, after)
		}
		if countOps(after[before:], "transfer_upload") != 1 {
			t.Fatalf("the start did not reach the keeper once: %v", after)
		}
		if countOps(after, "transfer_status") != 0 {
			t.Fatalf("the start read a status: %v", after)
		}
	})
}

func TestTaskStartAnswersAHandleOnlyForTheTransferTools(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	session, _ := newTaskBridge(t, ctx, &taskKeeper{}, clock.Now, true, "2026-07-28")
	for _, name := range []string{"remote_upload", "remote_download"} {
		result := callTaskTool(t, ctx, session, name, map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"})
		if result.IsError || len(result.Content) != 0 {
			t.Fatalf("%s did not answer a task handle: %+v", name, result)
		}
	}
	result := callTaskTool(t, ctx, session, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
	if text := answerText(t, result); !strings.HasPrefix(text, "Started job ") {
		t.Fatalf("remote_exec answered %q", text)
	}
	result = callTaskTool(t, ctx, session, "app_exec", map[string]any{"application": "app", "arguments": []string{"status"}})
	if text := answerText(t, result); !strings.HasPrefix(text, "Started job ") {
		t.Fatalf("app_exec answered %q", text)
	}
}

func TestTaskUnknownForeignAndExpiredHandles(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	t.Run("unknown", func(t *testing.T) {
		keeper := &taskKeeper{}
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
		unknown := strings.Repeat("ab", 32)
		before := keeper.ops()
		if _, err := taskGet(ctx, session, unknown); err == nil {
			t.Fatal("tasks/get answered an unknown handle")
		} else if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("tasks/get answered %d, want -32602", code)
		}
		if _, err := taskCancel(ctx, session, unknown); err == nil {
			t.Fatal("tasks/cancel answered an unknown handle")
		} else if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("tasks/cancel answered %d, want -32602", code)
		}
		if _, err := taskUpdate(ctx, session, unknown); err == nil {
			t.Fatal("tasks/update answered an unknown handle")
		} else if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("tasks/update answered %d, want -32602", code)
		}
		if after := keeper.ops(); len(after) != len(before) {
			t.Fatalf("an unknown handle reached the keeper: %v", after)
		}
	})
	t.Run("foreign", func(t *testing.T) {
		keeperA := &taskKeeper{}
		sessionA, _ := newTaskBridge(t, ctx, keeperA, clock.Now, true, "2026-07-28")
		keeperB := &taskKeeper{}
		sessionB, _ := newTaskBridge(t, ctx, keeperB, clock.Now, true, "2026-07-28")
		foreign := startTask(t, ctx, sessionB, keeperB)
		before := keeperA.ops()
		_, err := taskGet(ctx, sessionA, foreign)
		if err == nil {
			t.Fatal("a foreign handle was answered")
		}
		if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("a foreign handle answered %d, want -32602", code)
		}
		if after := keeperA.ops(); len(after) != len(before) {
			t.Fatalf("a foreign handle reached the keeper: %v", after)
		}
	})
	t.Run("expired", func(t *testing.T) {
		clock := newTestClock()
		keeper := &taskKeeper{}
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply {
			return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "done", Direction: "upload"}, nil)
		})
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "completed" {
			t.Fatalf("a finished job reported %q", answer.Status)
		}
		reads := countOps(keeper.ops(), "transfer_status")
		clock.Advance(time.Hour + time.Second)
		_, err = taskGet(ctx, session, id)
		if err == nil {
			t.Fatal("an expired handle was still answered")
		}
		if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("an expired handle answered %d, want -32602", code)
		}
		if after := countOps(keeper.ops(), "transfer_status"); after != reads {
			t.Fatalf("an expired handle read the keeper: %d reads, want %d", after, reads)
		}
	})
}

func TestTaskCancelErrorPaths(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	t.Run("unknown", func(t *testing.T) {
		keeper := &taskKeeper{}
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
		before := keeper.ops()
		_, err := taskCancel(ctx, session, strings.Repeat("ab", 32))
		if err == nil {
			t.Fatal("tasks/cancel answered an unknown handle")
		}
		if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("tasks/cancel answered %d, want -32602", code)
		}
		if after := keeper.ops(); len(after) != len(before) {
			t.Fatalf("an unknown handle reached the keeper: %v", after)
		}
	})
	t.Run("keeper lost the job", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return runningRecord(input) })
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		keeper.setCancel(func(transfer.CancelInput) wire.Reply { return wire.Reply{Error: "unknown transfer job"} })
		_, err := taskCancel(ctx, session, id)
		if err == nil {
			t.Fatal("a job the keeper lost was cancelled")
		}
		if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("a lost job answered %d, want -32602", code)
		}
		_, err = taskGet(ctx, session, id)
		if err == nil {
			t.Fatal("a job the keeper lost was still answered")
		}
		if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("a lost job was read with %d, want -32602", code)
		}
		if ops := countOps(keeper.ops(), "transfer_cancel"); ops != 1 {
			t.Fatalf("the keeper saw %d cancellations, want 1", ops)
		}
	})
	t.Run("keeper refused", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setCancel(func(transfer.CancelInput) wire.Reply { return wire.Reply{Error: "keeper refused"} })
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		_, err := taskCancel(ctx, session, id)
		if err == nil {
			t.Fatal("a refused cancellation reported success")
		}
		wireErr := rpcError(t, err)
		if wireErr.Code != -32603 {
			t.Fatalf("a refused cancellation answered %d, want -32603", wireErr.Code)
		}
		if wireErr.Message != "the cancellation could not be requested" {
			t.Fatalf("a refused cancellation answered %q", wireErr.Message)
		}
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return runningRecord(input) })
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "working" {
			t.Fatalf("a refused cancellation left the task %q, want working", answer.Status)
		}
	})
	t.Run("frozen record", func(t *testing.T) {
		keeper := &taskKeeper{}
		keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return doneRecord(input) })
		session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
		id := startTask(t, ctx, session, keeper)
		answer, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get failed: %v", err)
		}
		if answer.Status != "completed" {
			t.Fatalf("a finished job reported %q", answer.Status)
		}
		text := answerText(t, answer.Result)
		keeper.setStatus(func(_ int, _ transfer.StatusInput) wire.Reply { return wire.Reply{Error: "unknown transfer job"} })
		keeper.setCancel(func(transfer.CancelInput) wire.Reply { return wire.Reply{Error: "unknown transfer job"} })
		ops := keeper.ops()
		ack, err := taskCancel(ctx, session, id)
		if err != nil || ack == nil {
			t.Fatalf("tasks/cancel of a frozen record: %+v, %v", ack, err)
		}
		if ack.ResultType != "complete" {
			t.Fatalf("tasks/cancel answered %q", ack.ResultType)
		}
		if after := keeper.ops(); fmt.Sprint(after) != fmt.Sprint(ops) {
			t.Fatalf("a frozen cancel reached the keeper: %v, want %v", after, ops)
		}
		if n := countOps(keeper.ops(), "transfer_cancel"); n != 0 {
			t.Fatalf("a frozen record reached the keeper %d times", n)
		}
		again, err := taskGet(ctx, session, id)
		if err != nil {
			t.Fatalf("tasks/get after a frozen cancel failed: %v", err)
		}
		if again.Status != answer.Status || again.LastUpdatedAt != answer.LastUpdatedAt || answerText(t, again.Result) != text {
			t.Fatalf("a frozen record changed: %+v, want %+v", again, answer)
		}
		if after := keeper.ops(); fmt.Sprint(after) != fmt.Sprint(ops) {
			t.Fatalf("a frozen read reached the keeper: %v, want %v", after, ops)
		}
	})
}

func TestTaskUpdateAcknowledgesKnownHandles(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	keeper := &taskKeeper{}
	keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply { return runningRecord(input) })
	session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	before := len(keeper.ops())
	ack, err := taskUpdate(ctx, session, id)
	if err != nil || ack == nil {
		t.Fatalf("tasks/update failed: %+v, %v", ack, err)
	}
	if ack.ResultType != "complete" {
		t.Fatalf("tasks/update answered %q", ack.ResultType)
	}
	if after := len(keeper.ops()); after != before {
		t.Fatalf("tasks/update reached the keeper: %v", keeper.ops())
	}
	answer, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get failed: %v", err)
	}
	if answer.TaskID != id {
		t.Fatalf("tasks/get answered %q, want %q", answer.TaskID, id)
	}
	if answer.Status != "working" {
		t.Fatalf("a running job reported %q", answer.Status)
	}
}

func TestTaskStatusMessageIsTheGoldenFieldLine(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	keeper.setStatus(func(_ int, input transfer.StatusInput) wire.Reply {
		return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "running", Direction: "upload", Phase: "transfer", Mode: "chunked", ChunksDone: 12, ChunksTotal: 64, ChunkBytes: 262144, Attempts: 3, Bytes: 52428800, BytesPerSecond: 1300000}, nil)
	})
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	id := startTask(t, ctx, session, keeper)
	answer, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("tasks/get failed: %v", err)
	}
	if answer.Status != "working" {
		t.Fatalf("a running job reported %q, want working", answer.Status)
	}
	const want = "Phase: transfer · Mode: chunked · Chunks: 12/64 · Chunk size: 262,144 bytes · Attempts: 3 · Bytes: 52,428,800 · Files: 0 · Dirs: 0 · Speed: 1.3 MB/s"
	if answer.StatusMessage != want {
		t.Fatalf("the status message is %q, want %q", answer.StatusMessage, want)
	}
	if answer.Result != nil {
		t.Fatalf("a running task carried a result: %+v", answer.Result)
	}
	if answer.Error != nil {
		t.Fatalf("a running task carried an error: %+v", answer.Error)
	}
}

func TestTaskRawFramesCarryNoCanaries(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	canaries := []string{
		"CANARY-STDERR-7c1f4a",
		"CANARY-SECRET-9e2b6d",
		"CANARY-LOCAL-a1b2",
		"CANARY-REMOTE-c3d4",
	}
	keeper := &taskKeeper{}
	keeper.setStatus(func(call int, _ transfer.StatusInput) wire.Reply {
		switch call {
		case 1:
			return broker.Result(sentinelRecord("running"), nil)
		case 2:
			return wire.Reply{Error: "stderr: CANARY-STDERR-7c1f4a sk-CANARY-SECRET-9e2b6d"}
		}
		return broker.Result(sentinelRecord("done"), nil)
	})
	tap, kept := &pipeTap{}, &recorder{}
	session, _ := newTaskBridgeWith(t, ctx, keeper, nil, true, "2026-07-28", tap.pipes, func(inner mcp.Transport) mcp.Transport {
		return &recordingTransport{inner: inner, recorder: kept}
	})
	result := callTaskTool(t, ctx, session, "remote_upload", map[string]any{"target": "allowed", "local": "CANARY-LOCAL-a1b2", "remote": "/srv/CANARY-REMOTE-c3d4"})
	if result.IsError || len(result.Content) != 0 {
		t.Fatalf("remote_upload did not answer a task handle: %+v", result)
	}
	started := keeper.started()
	if len(started) != 1 {
		t.Fatalf("the keeper started %d jobs, want one", len(started))
	}
	id := started[0]
	first, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("the first tasks/get failed: %v", err)
	}
	if first.Status != "working" {
		t.Fatalf("the first poll reported %q, want working", first.Status)
	}
	if first.StatusMessage != sentinelLine {
		t.Fatalf("the first poll reported the status message %q, want the sentinel line %q", first.StatusMessage, sentinelLine)
	}
	if answer, err := taskGet(ctx, session, id); err == nil {
		t.Fatalf("a refused read answered a task: %+v", answer)
	} else {
		wireErr := rpcError(t, err)
		if wireErr.Code != -32603 {
			t.Fatalf("a refused read answered %d, want -32603", wireErr.Code)
		}
		if wireErr.Message != "the task could not be read" {
			t.Fatalf("a refused read answered %q, want the fixed message", wireErr.Message)
		}
	}
	third, err := taskGet(ctx, session, id)
	if err != nil {
		t.Fatalf("the third tasks/get failed: %v", err)
	}
	if third.Status != "completed" {
		t.Fatalf("the third poll reported %q, want completed", third.Status)
	}
	text := answerText(t, third.Result)
	if text != sentinelText {
		t.Fatalf("the completed text is\n%s\nwant\n%s", text, sentinelText)
	}
	ack, err := taskCancel(ctx, session, id)
	if err != nil || ack == nil {
		t.Fatalf("tasks/cancel failed: %+v, %v", ack, err)
	}
	if kept.count() == 0 {
		t.Fatal("the recording transport kept no frame")
	}
	for _, frame := range kept.all() {
		for _, canary := range canaries {
			if bytes.Contains(frame, []byte(canary)) {
				t.Fatalf("a recorded frame carries %q: %s", canary, frame)
			}
		}
	}
	if !kept.contains(`"resultType":"task"`) {
		t.Fatal("no recorded frame carries the task handle")
	}
	if !kept.contains("the task could not be read") {
		t.Fatal("no recorded frame carries the fixed error message")
	}
	for _, line := range strings.Split(text, "\n") {
		if !kept.contains(line) {
			t.Fatalf("no recorded frame carries the result line %q", line)
		}
	}
	if !kept.contains(`"resultType":"complete"`) {
		t.Fatal("no recorded frame carries a complete answer")
	}
	if got := countOps(keeper.ops(), "transfer_status"); got != 3 {
		t.Fatalf("the keeper saw %d status reads, want three", got)
	}
	rawFrames := tap.taskFrames()
	seen := make(map[string]int)
	for _, frame := range rawFrames {
		seen[frame[0]]++
		if violation := taskFrameViolation(frame[0], frame[1]); violation != "" {
			t.Fatal(violation)
		}
		if leaked := leakedSentinel([]byte(frame[1]), sentinelLine, sentinelText); leaked != "" {
			t.Fatalf("the raw %s frame carries the keeper record sentinel %q: %s", frame[0], leaked, frame[1])
		}
	}
	if seen["tools/call"] != 1 || seen["tasks/get"] != 3 || seen["tasks/cancel"] != 1 {
		t.Fatalf("the recording holds the task answers %v, want one handle, three polls and one ack", seen)
	}
}

// runEligibilitySession drives one fresh declaring session through a bare start
// and a declaring start, in the order bareFirst selects, and checks each answer.
func runEligibilitySession(t *testing.T, ctx context.Context, clock *testClock, bareFirst bool) {
	t.Helper()
	keeper := &taskKeeper{}
	strip, strips := &atomic.Bool{}, &atomic.Int64{}
	session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28", func(client *mcp.Client) {
		client.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if method == "tools/call" && strip.Load() {
					if params := req.GetParams(); params != nil {
						params.SetMeta(nil)
						strips.Add(1)
					}
				}
				return next(ctx, method, req)
			}
		})
	})
	init := session.InitializeResult()
	if init == nil || init.Capabilities == nil {
		t.Fatalf("the session answered %+v", init)
	}
	if init.ProtocolVersion != "2026-07-28" {
		t.Fatalf("the session negotiated %q, want 2026-07-28", init.ProtocolVersion)
	}
	if _, ok := init.Capabilities.Extensions[taskExtension]; !ok {
		t.Fatalf("the session did not see %s: %+v", taskExtension, init.Capabilities.Extensions)
	}
	args := map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"}
	uploads := 1
	if !bareFirst {
		if result := callTaskTool(t, ctx, session, "remote_upload", args); result.IsError || len(result.Content) != 0 {
			t.Fatalf("a declaring call did not answer a task handle: %+v", result)
		}
		uploads++
	}
	strip.Store(true)
	before := strips.Load()
	result := callTaskTool(t, ctx, session, "remote_upload", args)
	if got := strips.Load(); got != before+1 {
		t.Fatalf("the bare call still carried request metadata: the strip ran %d times, want one", got-before)
	}
	started := keeper.started()
	if len(started) != uploads {
		t.Fatalf("the keeper started %d jobs, want %d", len(started), uploads)
	}
	id := started[uploads-1]
	want := "Started job " + id + "\nCheck progress with transfer_status job_id=" + id + "; use wait_seconds 20 to wait for it."
	if got := answerText(t, result); got != want {
		t.Fatalf("a bare call answered %q, want %q", got, want)
	}
	ops := keeper.ops()
	if got := countOps(ops, "transfer_upload"); got != uploads {
		t.Fatalf("the keeper saw %d uploads, want %d: %v", got, uploads, ops)
	}
	if got := countOps(ops, "transfer_status"); got != 0 {
		t.Fatalf("a start read a status: %v", ops)
	}
	strip.Store(false)
	if result := callTaskTool(t, ctx, session, "remote_upload", args); result.IsError || len(result.Content) != 0 {
		t.Fatalf("a declaring call after a bare one did not answer a task handle: %+v", result)
	}
}

func TestTaskEligibilityIgnoresSessionState(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	t.Run("declaring then bare", func(t *testing.T) { runEligibilitySession(t, ctx, clock, false) })
	t.Run("bare first", func(t *testing.T) { runEligibilitySession(t, ctx, clock, true) })
}

func TestTaskStartRefusesAnUnknownArgumentBeforeTheKeeper(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	keeper := &taskKeeper{}
	session, _ := newTaskBridge(t, ctx, keeper, clock.Now, true, "2026-07-28")
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_upload", Arguments: map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin", "bogus": true}})
	if err != nil {
		if code := rpcError(t, err).Code; code != -32602 {
			t.Fatalf("an unknown argument answered %d, want -32602", code)
		}
	} else if result == nil || !result.IsError {
		t.Fatalf("an unknown argument was accepted: %+v", result)
	}
	if ops := keeper.ops(); len(ops) != 0 {
		t.Fatalf("an unknown argument reached the keeper: %v", ops)
	}
}

func TestTaskStartWithoutAJobIDAnswersTodaysText(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	clock := newTestClock()
	args := map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"}
	noJobID := func(transfer.StartInput) wire.Reply {
		return broker.Result(transfer.StartOutput{}, nil)
	}
	declaringKeeper := &taskKeeper{}
	declaringKeeper.setStart(noJobID)
	declaring, _ := newTaskBridge(t, ctx, declaringKeeper, clock.Now, true, "2026-07-28")
	plainKeeper := &taskKeeper{}
	plainKeeper.setStart(noJobID)
	plain, _ := newTaskBridge(t, ctx, plainKeeper, clock.Now, false, "2026-07-28")
	declaringResult := callTaskTool(t, ctx, declaring, "remote_upload", args)
	plainResult := callTaskTool(t, ctx, plain, "remote_upload", args)
	if declaringResult.IsError {
		t.Fatalf("a declaring start without a job id was refused: %+v", declaringResult)
	}
	if len(declaringResult.Content) != 1 {
		t.Fatalf("a declaring start without a job id answered %d content blocks, want one: %+v", len(declaringResult.Content), declaringResult)
	}
	if got, want := answerText(t, declaringResult), answerText(t, plainResult); got != want {
		t.Fatalf("a declaring start without a job id answered %q, want the tool's own text %q", got, want)
	}
	if started := declaringKeeper.started(); len(started) != 0 {
		t.Fatalf("the keeper minted %d job ids, want none", len(started))
	}
	ops := declaringKeeper.ops()
	if got := countOps(ops, "transfer_upload"); got != 1 {
		t.Fatalf("the keeper saw %d uploads, want one: %v", got, ops)
	}
	if got := countOps(ops, "transfer_status"); got != 0 {
		t.Fatalf("a start without a job id read a status: %v", ops)
	}
}
