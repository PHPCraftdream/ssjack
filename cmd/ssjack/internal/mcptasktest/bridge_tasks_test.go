package mcptasktest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/remotemcp"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	// bridgeGate marks the child test that runs the production stdio bridge.
	bridgeGate = "SSJACK_MCP_TASK_TEST_BRIDGE"
	// taskExtension is the identifier of the MCP tasks extension.
	taskExtension = "io.modelcontextprotocol/tasks"

	// modernVersion is the revision whose requests carry the tasks extension.
	modernVersion = "2026-07-28"
	// legacyVersion is the revision the raw probe negotiates.
	legacyVersion = "2025-11-25"

	bridgeTestBudget = 60 * time.Second
	bridgeExitBudget = 20 * time.Second
)

// taskHandle is the tools/call answer of an eligible transfer start: the
// extension's CreateTaskResult shape.
type taskHandle struct {
	ResultType     string          `json:"resultType"`
	TaskID         string          `json:"taskId"`
	Status         string          `json:"status"`
	StatusMessage  string          `json:"statusMessage"`
	CreatedAt      string          `json:"createdAt"`
	LastUpdatedAt  string          `json:"lastUpdatedAt"`
	TTLMs          *int64          `json:"ttlMs"`
	PollIntervalMs *int            `json:"pollIntervalMs"`
	Result         json.RawMessage `json:"result"`
}

// taskHandleFrame is the JSON-RPC envelope of a task handle answer.
type taskHandleFrame struct {
	Result taskHandle `json:"result"`
}

// taskGetParams are the tasks/get parameters of the declaring client.
type taskGetParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

// taskUpdateParams are the tasks/update parameters of the declaring client.
type taskUpdateParams struct {
	mcp.ParamsBase
	TaskID         string                     `json:"taskId"`
	InputResponses map[string]json.RawMessage `json:"inputResponses,omitempty"`
}

// taskCancelParams are the tasks/cancel parameters of the declaring client.
type taskCancelParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

// taskFailure is the nested error of a failed task.
type taskFailure struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

// taskGetResult is one tasks/get answer as the declaring client reads it.
type taskGetResult struct {
	mcp.ResultBase
	ResultType     string              `json:"resultType"`
	TaskID         string              `json:"taskId"`
	Status         string              `json:"status"`
	StatusMessage  string              `json:"statusMessage"`
	CreatedAt      string              `json:"createdAt"`
	LastUpdatedAt  string              `json:"lastUpdatedAt"`
	TTLMs          int64               `json:"ttlMs"`
	PollIntervalMs int                 `json:"pollIntervalMs"`
	Result         *mcp.CallToolResult `json:"result,omitempty"`
	Error          *taskFailure        `json:"error,omitempty"`
}

// taskAck is the empty acknowledgement of tasks/update and tasks/cancel.
type taskAck struct {
	mcp.ResultBase
	ResultType string `json:"resultType"`
}

func TestMCPTaskBridgeChild(t *testing.T) {
	if os.Getenv(bridgeGate) != "1" {
		t.Skip("mcp task bridge child only")
	}
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()
	code, err := remotemcp.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("mcp task bridge child failed: code=%d err=%v", code, err)
	}
}

func TestMCPTaskPathOverTheLaunchedBridge(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()

	keeper := &launchKeeper{}
	command := startBridge(t, ctx, keeper.Handle)
	logbook := &recorder{}
	transport := &recordingTransport{inner: &mcp.CommandTransport{Command: command}, recorder: logbook}

	caps := &mcp.ClientCapabilities{}
	caps.AddExtension(taskExtension, map[string]any{})
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-task-harness", Version: "1"}, &mcp.ClientOptions{Capabilities: caps})
	if err := mcp.AddSendingCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](client, "tasks/get"); err != nil {
		t.Fatalf("could not register tasks/get: %v", err)
	}
	if err := mcp.AddSendingCustomMethod[*taskUpdateParams, *taskAck, taskUpdateParams](client, "tasks/update"); err != nil {
		t.Fatalf("could not register tasks/update: %v", err)
	}
	if err := mcp.AddSendingCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](client, "tasks/cancel"); err != nil {
		t.Fatalf("could not register tasks/cancel: %v", err)
	}
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: modernVersion})
	if err != nil {
		t.Fatalf("the declaring client could not attach to the bridge: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_upload", Arguments: map[string]any{
		"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin",
	}})
	if err != nil {
		t.Fatalf("remote_upload failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("remote_upload was not answered with a task handle: %#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("the task handle carried tool content: %#v", result.Content)
	}

	minted := keeper.minted()
	if len(minted) != 1 {
		t.Fatalf("the keeper started %d jobs, want exactly one transfer", len(minted))
	}
	jobID := minted[0]
	requireOps(t, keeper, "session.describe", "transfer_upload")

	frame, ok := logbook.contains(`"resultType":"task"`)
	if !ok {
		t.Fatalf("no tools/call answer carried a task handle; %d frames were read", logbook.count())
	}
	handle := requireTaskHandle(t, frame, jobID)
	if handle.Status != "working" {
		t.Fatalf("the task handle reported status %q, want working", handle.Status)
	}
	if handle.TTLMs == nil || *handle.TTLMs != 7200000 {
		t.Fatalf("the task handle reported ttlMs %v, want 7200000", handle.TTLMs)
	}
	if handle.PollIntervalMs == nil || *handle.PollIntervalMs != 10000 {
		t.Fatalf("the task handle reported pollIntervalMs %v, want 10000", handle.PollIntervalMs)
	}
	created, err := time.Parse(time.RFC3339, handle.CreatedAt)
	if err != nil {
		t.Fatalf("createdAt %q is not RFC 3339: %v", handle.CreatedAt, err)
	}
	updated, err := time.Parse(time.RFC3339, handle.LastUpdatedAt)
	if err != nil {
		t.Fatalf("lastUpdatedAt %q is not RFC 3339: %v", handle.LastUpdatedAt, err)
	}
	if !created.Equal(updated) {
		t.Fatalf("a fresh task reported createdAt %q and lastUpdatedAt %q", handle.CreatedAt, handle.LastUpdatedAt)
	}

	got, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: jobID})
	if err != nil {
		t.Fatalf("tasks/get failed: %v", err)
	}
	if got == nil {
		t.Fatal("tasks/get returned no answer")
	}
	if got.ResultType != "complete" {
		t.Fatalf("tasks/get reported resultType %q, want complete", got.ResultType)
	}
	if got.Status != "completed" {
		t.Fatalf("tasks/get reported status %q, want completed", got.Status)
	}
	if got.TaskID != jobID {
		t.Fatalf("tasks/get answered for task %q, want %q", got.TaskID, jobID)
	}
	wantText := fmt.Sprintf("Transfer %s: upload file, done\nBytes: 3 · Files: 1 · Dirs: 0\nSHA-256: aa", jobID)
	if got.Result == nil {
		t.Fatal("a completed task carried no result")
	}
	if text := requireSingleText(t, "tasks/get", got.Result); text != wantText {
		t.Fatalf("the completed task text was\n%s\nwant\n%s", text, wantText)
	}
	requireOps(t, keeper, "session.describe", "transfer_upload", "transfer_status")

	acked, err := mcp.CallCustomMethod[*taskUpdateParams, *taskAck, taskUpdateParams](ctx, session, "tasks/update", &taskUpdateParams{TaskID: jobID, InputResponses: map[string]json.RawMessage{"name": json.RawMessage(`{"action":"accept"}`)}})
	if err != nil {
		t.Fatalf("tasks/update failed: %v", err)
	}
	if acked == nil {
		t.Fatal("tasks/update returned no answer")
	}
	if acked.ResultType != "complete" {
		t.Fatalf("tasks/update reported resultType %q, want complete", acked.ResultType)
	}

	cancelled, err := mcp.CallCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](ctx, session, "tasks/cancel", &taskCancelParams{TaskID: jobID})
	if err != nil {
		t.Fatalf("tasks/cancel failed: %v", err)
	}
	if cancelled == nil {
		t.Fatal("tasks/cancel returned no answer")
	}
	if cancelled.ResultType != "complete" {
		t.Fatalf("tasks/cancel reported resultType %q, want complete", cancelled.ResultType)
	}
	requireOps(t, keeper, "session.describe", "transfer_upload", "transfer_status")

	mark := logbook.mark()
	for _, call := range []struct {
		name string
		args map[string]any
	}{
		{"remote_exec", map[string]any{"target": "allowed", "command": "true"}},
		{"app_exec", map[string]any{"application": "app", "arguments": []string{"status"}}},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil {
			t.Fatalf("%s failed: %v", call.name, err)
		}
		if result == nil || result.IsError {
			t.Fatalf("%s was not answered with today's text: %#v", call.name, result)
		}
		text := requireSingleText(t, call.name, result)
		if !strings.HasPrefix(text, "Started job ") {
			t.Fatalf("%s returned %q, want today's started-job text", call.name, text)
		}
	}
	for _, frame := range logbook.since(mark) {
		if bytes.Contains(frame, []byte(`"resultType":"task"`)) {
			t.Fatalf("an exec call was answered with a task handle: %s", frame)
		}
	}
}

func TestMCPTaskLaunchedBridgeAnswersCarryNoCanaries(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()

	keeper := &launchKeeper{}
	keeper.status = func(call int, _ transfer.StatusInput) wire.Reply {
		switch call {
		case 1:
			return broker.Result(sentinelRecord("running"), nil)
		case 2:
			return wire.Reply{Error: "stderr: CANARY-STDERR-7c1f4a sk-CANARY-SECRET-9e2b6d"}
		}
		return broker.Result(sentinelRecord("done"), nil)
	}
	command := startBridge(t, ctx, keeper.Handle)
	logbook := &recorder{}
	transport := &recordingTransport{inner: &mcp.CommandTransport{Command: command}, recorder: logbook}

	caps := &mcp.ClientCapabilities{}
	caps.AddExtension(taskExtension, map[string]any{})
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-canary", Version: "1"}, &mcp.ClientOptions{Capabilities: caps})
	if err := mcp.AddSendingCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](client, "tasks/get"); err != nil {
		t.Fatalf("could not register tasks/get: %v", err)
	}
	if err := mcp.AddSendingCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](client, "tasks/cancel"); err != nil {
		t.Fatalf("could not register tasks/cancel: %v", err)
	}
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: modernVersion})
	if err != nil {
		t.Fatalf("the declaring client could not attach to the bridge: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_upload", Arguments: map[string]any{
		"target": "allowed", "local": "CANARY-LOCAL-a1b2", "remote": "/srv/CANARY-REMOTE-c3d4",
	}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("remote_upload was not answered with a task handle: %#v (%v)", result, err)
	}
	minted := keeper.minted()
	if len(minted) != 1 {
		t.Fatalf("the keeper started %d jobs, want exactly one transfer", len(minted))
	}
	jobID := minted[0]

	working, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: jobID})
	if err != nil || working == nil || working.Status != "working" {
		t.Fatalf("the first poll answered %#v (%v), want working", working, err)
	}

	_, err = mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: jobID})
	var rpcErr *jsonrpc.Error
	if err == nil || !errors.As(err, &rpcErr) || rpcErr.Code != -32603 || rpcErr.Message != "the task could not be read" {
		t.Fatalf("the failed poll answered %v, want -32603 %q", err, "the task could not be read")
	}

	done, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: jobID})
	if err != nil || done == nil {
		t.Fatalf("the third poll failed: %v", err)
	}
	if done.Result == nil {
		t.Fatal("a completed task carried no result")
	}
	if text := requireSingleText(t, "tasks/get", done.Result); text != sentinelText {
		t.Fatalf("the completed task text was\n%s\nwant\n%s", text, sentinelText)
	}

	cancelled, err := mcp.CallCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](ctx, session, "tasks/cancel", &taskCancelParams{TaskID: jobID})
	if err != nil || cancelled == nil || cancelled.ResultType != "complete" {
		t.Fatalf("tasks/cancel answered %#v (%v), want a complete ack", cancelled, err)
	}

	requireOps(t, keeper, "session.describe", "transfer_upload", "transfer_status", "transfer_status", "transfer_status")
	for index, frame := range logbook.since(0) {
		if leaked := leakedSentinel(frame, sentinelLine, sentinelText); leaked != "" {
			t.Fatalf("recorded frame %d carries the keeper record sentinel %q: %s", index, leaked, frame)
		}
	}
	for _, want := range []string{`"resultType":"task"`, `"status":"completed"`, "the task could not be read", `"resultType":"complete"`} {
		if _, ok := logbook.contains(want); !ok {
			t.Fatalf("no recorded frame carried %q; %d frames were read", want, logbook.count())
		}
	}
	for _, canary := range []string{"CANARY-STDERR-7c1f4a", "sk-CANARY-SECRET-9e2b6d", "CANARY-LOCAL-a1b2", "CANARY-REMOTE-c3d4"} {
		for index, frame := range logbook.since(0) {
			if bytes.Contains(frame, []byte(canary)) {
				t.Fatalf("recorded frame %d leaked %q: %s", index, canary, frame)
			}
		}
	}
}

func TestMCPFallbackPinOverTheLaunchedBridge(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()

	keeper := &launchKeeper{}
	command := startBridge(t, ctx, keeper.Handle)
	client := mcp.NewClient(&mcp.Implementation{Name: "fallback-pin", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, &mcp.ClientSessionOptions{ProtocolVersion: modernVersion})
	if err != nil {
		t.Fatalf("the fallback client could not attach to the bridge: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	transferText := func(jobID string) string {
		return "Started job " + jobID + "\nCheck progress with transfer_status job_id=" + jobID + "; use wait_seconds 20 to wait for it."
	}
	readText := func(tool, jobID string) string {
		return "Started job " + jobID + "\nRead output with " + tool + " job_id=" + jobID + "; use wait_seconds 20 to wait for it."
	}
	calls := []struct {
		name string
		args map[string]any
		want func(string) string
	}{
		{"remote_upload", map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"}, transferText},
		{"remote_download", map[string]any{"target": "allowed", "local": "a.bin", "remote": "/srv/a.bin"}, transferText},
		{"remote_exec", map[string]any{"target": "allowed", "command": "true"}, func(jobID string) string { return readText("remote_read", jobID) }},
		{"app_exec", map[string]any{"application": "app", "arguments": []string{"status"}}, func(jobID string) string { return readText("app_read", jobID) }},
	}
	for index, call := range calls {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil {
			t.Fatalf("%s failed: %v", call.name, err)
		}
		if result == nil || result.IsError {
			t.Fatalf("%s was not answered with today's text: %#v", call.name, result)
		}
		text := requireSingleText(t, call.name, result)
		minted := keeper.minted()
		if len(minted) != index+1 {
			t.Fatalf("%s: the keeper minted %d job ids, want %d", call.name, len(minted), index+1)
		}
		if want := call.want(minted[index]); text != want {
			t.Fatalf("%s returned\n%s\nwant\n%s", call.name, text, want)
		}
	}

	listing, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list failed: %v", err)
	}
	described := make(map[string]*mcp.Tool, len(listing.Tools))
	for index := range listing.Tools {
		described[listing.Tools[index].Name] = listing.Tools[index]
	}
	for _, name := range []string{"remote_upload", "remote_download"} {
		tool := described[name]
		if tool == nil {
			t.Fatalf("%s is not listed", name)
		}
		for _, want := range []string{"transfer_status", "wait_seconds 20"} {
			if !strings.Contains(tool.Description, want) {
				t.Fatalf("%s keeps no polling step: its description lacks %q", name, want)
			}
		}
	}
}

// requireSingleText fails unless result is exactly one text content block with
// no structured content, and returns its text.
func requireSingleText(t *testing.T, name string, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil {
		t.Fatalf("%s: no result", name)
	}
	if result.StructuredContent != nil {
		t.Fatalf("%s: the result carries structured content: %#v", name, result.StructuredContent)
	}
	if len(result.Content) != 1 {
		t.Fatalf("%s: the result carried %d content blocks, want exactly one text block", name, len(result.Content))
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: the content block is not text: %#v", name, result.Content[0])
	}
	return text.Text
}

// requireTaskHandle decodes one recorded tools/call answer as a task handle of
// jobID.
func requireTaskHandle(t *testing.T, frame []byte, jobID string) *taskHandle {
	t.Helper()
	var typed taskHandleFrame
	if err := json.Unmarshal(frame, &typed); err != nil {
		t.Fatalf("the task handle did not decode: %s (%v)", frame, err)
	}
	handle := &typed.Result
	if handle.ResultType != "task" {
		t.Fatalf("the task handle reported resultType %q: %s", handle.ResultType, frame)
	}
	if handle.TaskID != jobID {
		t.Fatalf("the task id is %q, want the job id the keeper minted for the start (%q)", handle.TaskID, jobID)
	}
	if len(handle.TaskID) != 64 || strings.ToLower(handle.TaskID) != handle.TaskID {
		t.Fatalf("the task id is not 64 lowercase hex characters: %q", handle.TaskID)
	}
	var envelope map[string]any
	if err := json.Unmarshal(frame, &envelope); err != nil {
		t.Fatalf("the task handle envelope did not decode: %s (%v)", frame, err)
	}
	object, ok := envelope["result"].(map[string]any)
	if !ok {
		t.Fatalf("the task handle was not a JSON object: %s", frame)
	}
	if _, present := object["result"]; present {
		t.Fatalf("a working task handle carried a result: %s", frame)
	}
	return handle
}

// requireOps fails unless the keeper saw exactly these operations, in order.
func requireOps(t *testing.T, keeper *launchKeeper, want ...string) {
	t.Helper()
	got := keeper.ops()
	if len(got) != len(want) {
		t.Fatalf("the keeper saw %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("the keeper saw %v, want %v", got, want)
		}
	}
}

// launchKeeper is the fake keeper of the launched-bridge tests: it records the
// operations in order, mints one fresh job id per start and answers the
// transfer tool set with content-free synthetic records.
type launchKeeper struct {
	mu          sync.Mutex
	operations  []string
	jobIDs      []string
	statusCalls int

	// status replaces the default terminal upload record; call is the 1-based
	// ordinal of the transfer_status call.
	status func(call int, input transfer.StatusInput) wire.Reply
	// cancel replaces the default "the cancellation was requested" answer.
	cancel func(input transfer.CancelInput) wire.Reply
}

// Handle answers one keeper request.
func (k *launchKeeper) Handle(_ context.Context, request wire.Request) wire.Reply {
	k.mu.Lock()
	k.operations = append(k.operations, request.Operation)
	k.mu.Unlock()
	switch request.Operation {
	case "session.describe":
		return broker.Result(broker.Descriptor{
			Protocol: broker.FullProtocol, Mode: broker.ModeFull, Complete: true,
			Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"},
		}, nil)
	case "targets":
		return broker.Result(remote.TargetsOutput{Targets: []string{"allowed"}}, nil)
	case "start", "app_start", "transfer_upload", "transfer_download":
		return broker.Result(remote.StartOutput{JobID: k.mint()}, nil)
	case "transfer_status":
		var input transfer.StatusInput
		if wire.Decode(request.Data, &input) != nil {
			return wire.Reply{Error: "invalid transfer status"}
		}
		k.mu.Lock()
		k.statusCalls++
		call, hook := k.statusCalls, k.status
		k.mu.Unlock()
		if hook != nil {
			return hook(call, input)
		}
		return broker.Result(transfer.StatusOutput{
			JobID: input.JobID, State: "done", Direction: "upload", Kind: "file",
			Bytes: 3, Files: 1, SHA256: "aa",
		}, nil)
	case "transfer_cancel":
		var input transfer.CancelInput
		if wire.Decode(request.Data, &input) != nil {
			return wire.Reply{Error: "invalid transfer cancel"}
		}
		k.mu.Lock()
		hook := k.cancel
		k.mu.Unlock()
		if hook != nil {
			return hook(input)
		}
		return broker.Result(transfer.CancelOutput{Cancelled: true}, nil)
	}
	return wire.Reply{Error: "unsupported keeper operation"}
}

// mint records and returns the next fresh job id.
func (k *launchKeeper) mint() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	jobID := fmt.Sprintf("%064x", len(k.jobIDs)+1)
	k.jobIDs = append(k.jobIDs, jobID)
	return jobID
}

// ops returns the operation names the keeper saw, in order.
func (k *launchKeeper) ops() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.operations...)
}

// minted returns the job ids the keeper minted, in order.
func (k *launchKeeper) minted() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.jobIDs...)
}

// bridgeProcess is one prepared bridge child; the SDK transport starts it, the
// raw helper starts it behind its own pipes.
type bridgeProcess struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser

	mu     sync.Mutex
	waited bool
}

// startBridgeProcess prepares the child and, with withPipes, starts it with
// pipes the caller owns. The child receives the fixture .mcp.json in its
// working directory and the one-use keeper attachment in its environment.
func startBridgeProcess(t *testing.T, ctx context.Context, keeper broker.Handler, withPipes bool) *bridgeProcess {
	t.Helper()
	session, token := strings.Repeat("7", 64), strings.Repeat("8", 64)
	server, err := broker.Listen(ctx, session, token, 2*time.Minute, keeper)
	if err != nil {
		t.Fatalf("the synthetic keeper is unavailable: %v", err)
	}
	t.Cleanup(server.Close)

	root := t.TempDir()
	config := `{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"]}}}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(config), 0600); err != nil {
		t.Fatalf("could not write the fixed MCP config: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("could not locate the test binary: %v", err)
	}
	process := &bridgeProcess{command: exec.Command(executable, "-test.run=^TestMCPTaskBridgeChild$")}
	process.command.Dir = root
	process.command.Env = append(os.Environ(),
		bridgeGate+"=1",
		broker.EnvSession+"="+session,
		broker.EnvToken+"="+token,
		broker.EnvEndpoint+"="+server.Endpoint(),
		broker.EnvPin+"="+server.Pin(),
	)
	process.command.Stderr = os.Stderr
	if withPipes {
		stdin, err := process.command.StdinPipe()
		if err != nil {
			t.Fatalf("could not attach the child's stdin: %v", err)
		}
		stdout, err := process.command.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			t.Fatalf("could not attach the child's stdout: %v", err)
		}
		process.stdin, process.stdout = stdin, stdout
		if err := process.command.Start(); err != nil {
			t.Fatalf("could not start the bridge child: %v", err)
		}
	}
	t.Cleanup(func() {
		if process.stdin == nil {
			// The MCP transport started this child and reaps it through its own
			// Connection.Close, which the cleanup registered right after
			// startBridge runs first; a bounded wait here would race with it.
			return
		}
		_ = process.stdin.Close()
		if err := process.waitBounded(t, bridgeExitBudget); err != nil {
			t.Logf("the mcp task bridge child ended with: %v", err)
		}
	})
	return process
}

// startBridge prepares the bridge child and returns its command: the MCP
// transport starts it and the session's Close reaps it, so the pipes stay in
// the SDK's hands. Use startRawBridge for a child this package starts itself.
func startBridge(t *testing.T, ctx context.Context, keeper broker.Handler) *exec.Cmd {
	t.Helper()
	return startBridgeProcess(t, ctx, keeper, false).command
}

// startRawBridge starts the bridge child behind pipes the raw test owns and
// reaps itself.
func startRawBridge(t *testing.T, ctx context.Context, keeper broker.Handler) (io.WriteCloser, io.ReadCloser, *bridgeProcess) {
	t.Helper()
	process := startBridgeProcess(t, ctx, keeper, true)
	return process.stdin, process.stdout, process
}

// waitBounded waits for the child and kills it when the budget expires.
func (p *bridgeProcess) waitBounded(t *testing.T, timeout time.Duration) error {
	t.Helper()
	p.mu.Lock()
	if p.waited {
		p.mu.Unlock()
		return nil
	}
	p.waited = true
	command := p.command
	p.mu.Unlock()
	if command.Process == nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var err error
	finished, desc, _ := flakediag.WaitForDesc(t, "the mcp task bridge child to exit", timeout, func() (string, bool, error) {
		select {
		case err = <-done:
			return "the child exited", true, nil
		default:
			return "the child is still running", false, nil
		}
	})
	if finished {
		return err
	}
	_ = command.Process.Kill()
	finished, desc, _ = flakediag.WaitForDesc(t, "the killed mcp task bridge child to exit", bridgeExitBudget, func() (string, bool, error) {
		select {
		case err = <-done:
			return "the child exited after the kill", true, nil
		default:
			return "the child is still running after the kill", false, nil
		}
	})
	if !finished {
		t.Errorf("the mcp task bridge child did not exit after the bounded kill: %s", desc)
		return nil
	}
	t.Errorf("the mcp task bridge child exited only after the bounded kill: %v", err)
	return err
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

// contains returns the first recorded frame containing text.
func (r *recorder) contains(text string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, frame := range r.frames {
		if bytes.Contains(frame, []byte(text)) {
			return append([]byte(nil), frame...), true
		}
	}
	return nil, false
}

// count returns the number of frames recorded so far.
func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.frames)
}

// mark returns a cursor for since.
func (r *recorder) mark() int { return r.count() }

// since returns the frames recorded after mark.
func (r *recorder) since(mark int) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mark >= len(r.frames) {
		return nil
	}
	return append([][]byte(nil), r.frames[mark:]...)
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

const rawTaskMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"` + modernVersion + `","io.modelcontextprotocol/clientCapabilities":{"extensions":{"` + taskExtension + `":{}}}}`

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

// sentinelFields is the field part of the sentinel record's status text: the
// Phase/Mode/Chunks/Chunk size/Attempts line, the Bytes/Files/Dirs/Speed line,
// and the SHA-256, Manifest SHA-256 and Failed lines.
var sentinelFields = []string{
	"Phase: SENTINEL-PHASE · Mode: SENTINEL-MODE · Chunks: 123456/123457 · Chunk size: 3,141,592 bytes · Attempts: 987,656",
	"Bytes: 987,654,321 · Files: 8675309 · Dirs: 8675310 · Speed: 2.7 GB/s",
	"SHA-256: SENTINEL-SHA256",
	"Manifest SHA-256: SENTINEL-MANIFEST",
	"Failed: SENTINEL-ERRORCLASS",
}

// sentinelLine and sentinelText are the status message and completed text of
// the sentinel record.
var sentinelLine = strings.Join(sentinelFields, " · ")
var sentinelText = "Transfer SENTINEL-JOB: SENTINEL-DIRECTION SENTINEL-KIND, done\n" + strings.Join(sentinelFields, "\n")

// encodedText returns one text value as the SDK writes it in a frame: a JSON
// string without HTML escaping, with newlines escaped.
func encodedText(text string) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(text) != nil {
		return nil
	}
	return bytes.TrimRight(buffer.Bytes(), "\n")
}

// leakedSentinel returns the first record sentinel a frame still carries after
// removing the exact texts the test expects the frame to carry.
func leakedSentinel(frame []byte, expect ...string) string {
	body := frame
	for _, text := range expect {
		if encoded := encodedText(text); encoded != nil {
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

// rawAnswerID returns the id of one raw reply.
func rawAnswerID(line string) int {
	var answer struct {
		ID int `json:"id"`
	}
	if json.Unmarshal([]byte(line), &answer) != nil {
		return 0
	}
	return answer.ID
}

func TestMCPTaskRawFramesCarryOnlyTheContractMembers(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()
	keeper := &launchKeeper{}
	keeper.status = func(call int, _ transfer.StatusInput) wire.Reply {
		if call == 1 {
			return broker.Result(sentinelRecord("running"), nil)
		}
		return broker.Result(sentinelRecord("done"), nil)
	}
	stdin, stdout, _ := startRawBridge(t, ctx, keeper.Handle)
	t.Cleanup(func() { _ = stdout.Close() })
	reader := newRawReader(stdout, nil)
	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+modernVersion+`","capabilities":{},"clientInfo":{"name":"raw-task","version":"1"}}}`)
	reader.next(t, ctx, "initialize reply")
	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remote_upload","arguments":{"target":"allowed","local":"a.bin","remote":"/srv/a.bin"},`+rawTaskMeta+`}}`)
	frames := [][2]string{{"tools/call", reader.next(t, ctx, "tools/call reply")}}
	minted := keeper.minted()
	if len(minted) != 1 {
		t.Fatalf("the keeper started %d jobs, want one", len(minted))
	}
	for id := 3; id <= 4; id++ {
		writeRawFrame(t, stdin, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tasks/get","params":{"taskId":%q,`, id, minted[0])+rawTaskMeta+`}}`)
		frames = append(frames, [2]string{"tasks/get", reader.next(t, ctx, "tasks/get reply")})
	}
	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":5,"method":"tasks/cancel","params":{"taskId":"`+minted[0]+`",`+rawTaskMeta+`}}`)
	ack := reader.next(t, ctx, "tasks/cancel reply")
	if rawAnswerID(ack) != 5 {
		t.Fatalf("the tasks/cancel capture is not the answer to request 5: %s", ack)
	}
	frames = append(frames, [2]string{"tasks/cancel", ack})
	if !bytes.Contains([]byte(frames[1][1]), []byte("SENTINEL-PHASE")) || !bytes.Contains([]byte(frames[2][1]), []byte("SENTINEL-JOB")) {
		t.Fatalf("the raw polls do not carry the sentinel record: %v", frames[1:])
	}
	for _, frame := range frames {
		if violation := taskFrameViolation(frame[0], frame[1]); violation != "" {
			t.Fatal(violation)
		}
		if leaked := leakedSentinel([]byte(frame[1]), sentinelLine, sentinelText); leaked != "" {
			t.Fatalf("the raw %s frame carries the keeper record sentinel %q: %s", frame[0], leaked, frame[1])
		}
	}
}

func TestMCPTaskRawFrameCheckNamesAnInjectedMember(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), bridgeTestBudget)
	defer cancel()
	keeper := &launchKeeper{}
	stdin, stdout, _ := startRawBridge(t, ctx, keeper.Handle)
	t.Cleanup(func() { _ = stdout.Close() })
	reader := newRawReader(stdout, func(line string) string { return line[:len(line)-1] + `,"task-leak":true}` })
	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+modernVersion+`","capabilities":{},"clientInfo":{"name":"raw-task","version":"1"}}}`)
	reader.next(t, ctx, "initialize reply")
	writeRawFrame(t, stdin, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remote_upload","arguments":{"target":"allowed","local":"a.bin","remote":"/srv/a.bin"},`+rawTaskMeta+`}}`)
	handle := reader.next(t, ctx, "tools/call reply")
	if violation := taskFrameViolation("tools/call", handle); !strings.Contains(violation, `"task-leak"`) {
		t.Fatalf("the frame check did not name the injected member: %q", violation)
	}
}

func TestMCPTaskCancelAckCaptureCorrelatesByRequestID(t *testing.T) {
	if rawAnswerID(`{"jsonrpc":"2.0","id":6,"result":{"resultType":"complete"}}`) == 5 {
		t.Fatal("the capture took another request's answer")
	}
	if rawAnswerID(`{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete"}}`) != 5 {
		t.Fatal("the capture did not take the answer to the outbound tasks/cancel")
	}
}
