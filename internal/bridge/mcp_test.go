package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const fullToolCount = 12

// contractKeeper answers every full-mode operation with a fixed result.
func contractKeeper(_ context.Context, req wire.Request) wire.Reply {
	switch req.Operation {
	case "targets":
		return broker.Result(remote.TargetsOutput{Targets: []string{"allowed"}}, nil)
	case "start":
		var input remote.StartInput
		if wire.Decode(req.Data, &input) != nil || input.Target != "allowed" {
			return wire.Reply{Error: "target is not allowed"}
		}
		return broker.Result(remote.StartOutput{JobID: "test-job"}, nil)
	case "read":
		return broker.Result(remote.ReadOutput{JobID: "test-job", Stdout: []byte("Hello"), StdoutOffset: 5, Done: true, ExitCode: 0}, nil)
	case "cancel", "app_cancel":
		return broker.Result(remote.CancelOutput{Cancelled: true}, nil)
	case "app_list":
		return broker.Result(application.ListOutput{Applications: []application.Description{{Name: "synthetic", Profile: "allowed"}}}, nil)
	case "app_start":
		var input application.Input
		if wire.Decode(req.Data, &input) != nil || input.Application != "synthetic" || len(input.Arguments) != 1 || input.Arguments[0] != "status" {
			return wire.Reply{Error: "invalid application"}
		}
		return broker.Result(remote.StartOutput{JobID: "app-job"}, nil)
	case "app_read":
		return broker.Result(remote.ReadOutput{JobID: "app-job", Stdout: []byte("Application result"), StdoutOffset: 18, Done: true, ExitCode: 0}, nil)
	case "transfer_upload", "transfer_download":
		var input transfer.StartInput
		if wire.Decode(req.Data, &input) != nil || input.Target != "allowed" || input.Local != "a.txt" || input.Remote != "/srv/a.txt" {
			return wire.Reply{Error: "invalid transfer"}
		}
		return broker.Result(transfer.StartOutput{JobID: "transfer-job"}, nil)
	case "transfer_status":
		return broker.Result(transfer.StatusOutput{
			JobID: "transfer-job", State: "done", Direction: "upload", Kind: "file", Files: 1, Bytes: 3, SHA256: "aa",
			Mode: "chunked", ChunkBytes: 262144, ChunksDone: 2, ChunksTotal: 5, Attempts: 3, BytesPerSecond: 1000,
		}, nil)
	case "transfer_cancel":
		return broker.Result(transfer.CancelOutput{Cancelled: true}, nil)
	default:
		return wire.Reply{Error: "denied"}
	}
}

// requireTextContract fails unless the result is the plain-text contract: no
// structured content, exactly one text block and no JSON look. It returns the
// text.
func requireTextContract(t *testing.T, name string, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil {
		t.Fatalf("%s: no result", name)
	}
	if result.StructuredContent != nil {
		t.Fatalf("%s: the result carries structured content: %+v", name, result.StructuredContent)
	}
	text, err := ResultText(result)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if text == "" || strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		t.Fatalf("%s: the text is empty or looks like JSON: %q", name, text)
	}
	return text
}

func TestMCPToolsAreTextOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, _ := connectBridge(t, ctx, contractKeeper, nil)
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != fullToolCount {
		t.Fatalf("unexpected tool list: %+v, %v", tools, err)
	}
	for _, tool := range tools.Tools {
		if tool.OutputSchema != nil {
			t.Fatalf("%s declares an output schema: %+v", tool.Name, tool.OutputSchema)
		}
		if len(tool.Description) > 2000 || strings.Contains(tool.Description, `:\`) {
			t.Fatalf("%s description is unbounded or carries a local path: %q", tool.Name, tool.Description)
		}
		if !strings.Contains(tool.Description, "plain text") {
			t.Fatalf("%s description does not say what text comes back: %q", tool.Name, tool.Description)
		}
	}
	for _, call := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"remote_targets", map[string]any{}, "1 approved target:\n- allowed"},
		{"remote_exec", map[string]any{"target": "allowed", "command": "echo hello"}, "Started job test-job\nRead output with remote_read job_id=test-job; use wait_seconds 20 to wait for it."},
		{"remote_read", map[string]any{"job_id": "test-job"}, "Job test-job: done (exit code 0)\nstdout (bytes 0-5):\nHello\n[end of stdout]\n" +
			"Next: stdout_offset=5 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no"},
		{"remote_cancel", map[string]any{"job_id": "test-job"}, "Cancelled job test-job"},
		{"app_list", map[string]any{}, "1 registered application:\n- synthetic (profile allowed)"},
		{"app_exec", map[string]any{"application": "synthetic", "arguments": []string{"status"}}, "Started job app-job\nRead output with app_read job_id=app-job; use wait_seconds 20 to wait for it."},
		{"app_read", map[string]any{"job_id": "app-job"}, "Job app-job: done (exit code 0)\nstdout (bytes 0-18):\nApplication result\n[end of stdout]\n" +
			"Next: stdout_offset=18 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no"},
		{"app_cancel", map[string]any{"job_id": "app-job"}, "Cancelled job app-job"},
		{"remote_upload", map[string]any{"target": "allowed", "local": "a.txt", "remote": "/srv/a.txt"}, "Started job transfer-job\nCheck progress with transfer_status job_id=transfer-job; use wait_seconds 20 to wait for it."},
		{"remote_download", map[string]any{"target": "allowed", "local": "a.txt", "remote": "/srv/a.txt"}, "Started job transfer-job\nCheck progress with transfer_status job_id=transfer-job; use wait_seconds 20 to wait for it."},
		{"transfer_status", map[string]any{"job_id": "transfer-job"}, "Transfer transfer-job: upload file, done\n" +
			"Mode: chunked · Chunks: 2/5 · Chunk size: 262,144 bytes · Attempts: 3\n" +
			"Bytes: 3 · Files: 1 · Dirs: 0 · Speed: 1.0 kB/s\n" +
			"SHA-256: aa"},
		{"transfer_cancel", map[string]any{"job_id": "transfer-job"}, "Cancelled job transfer-job"},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || result.IsError {
			t.Fatalf("%s: %+v, %v", call.name, result, err)
		}
		text := requireTextContract(t, call.name, result)
		if text != call.want {
			t.Fatalf("%s returned\n%s\nwant\n%s", call.name, text, call.want)
		}
	}
}

func TestMCPToolDescriptionsNameTheirText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, _ := connectBridge(t, ctx, contractKeeper, nil)
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	for name, wants := range map[string][]string{
		"remote_upload":   {"link_unstable", "resume", "twice the file size", "Directories are never chunked", "transfer_cancel removes", "Started job"},
		"remote_download": {"link_unstable", "resume", "twice the file size", "Directories are never chunked", "transfer_cancel removes", "Started job"},
		"transfer_status": {"link_unstable", "refused_path", "never decreases", "Manifest SHA-256", "wait_seconds", "Chunks", "Mode", "Attempts", "Speed", "docs/FILE-TRANSFER.md", "Failed: <error_class>"},
		"remote_read":     {"wait_seconds", "done in the first line indicates", "[end of stdout]", "base64", "Next:", "docs/REMOTE-MCP.md"},
		"app_read":        {"wait_seconds", "drain both streams", "[end of stdout]", "base64", "docs/REMOTE-MCP.md"},
		"transfer_cancel": {"removed", "link failure keeps", "had already finished"},
		"remote_exec":     {"Started job", "remote_read"},
		"app_exec":        {"Started job", "app_read"},
		"remote_targets":  {"count line"},
		"app_list":        {"count line", "hint"},
		"remote_cancel":   {"Cancelled job", "had already finished"},
		"app_cancel":      {"Cancelled job", "had already finished"},
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("tool %s is not listed", name)
		}
		for _, want := range wants {
			if !strings.Contains(tool.Description, want) {
				t.Fatalf("%s description lacks %q: %q", name, want, tool.Description)
			}
		}
	}
}

func TestMCPErrorsAreNeatText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, _ := connectBridge(t, ctx, contractKeeper, nil)
	for _, call := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"remote_exec", map[string]any{"target": "other", "command": "echo hello"}, "target is not allowed"},
		{"app_exec", map[string]any{"application": "other", "arguments": []string{"status"}}, "invalid application"},
		{"remote_upload", map[string]any{"target": "allowed", "local": "b.txt", "remote": "/srv/b.txt"}, "invalid transfer"},
		{"remote_read", map[string]any{"job_id": "j", "wait_seconds": -1}, "wait_seconds must be between 0 and 25"},
		{"app_read", map[string]any{"job_id": "j", "wait_seconds": -1}, "wait_seconds must be between 0 and 25"},
		{"transfer_status", map[string]any{"job_id": "j", "wait_seconds": -1}, "wait_seconds must be between 0 and 25"},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || !result.IsError {
			t.Fatalf("%s: the failure was not propagated as a tool error: %+v, %v", call.name, result, err)
		}
		if text := requireTextContract(t, call.name, result); text != call.want {
			t.Fatalf("%s failed with %q, want %q", call.name, text, call.want)
		}
	}
}

func TestMCPFullModeKeeperErrorKeepsTheSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, keeper := connectBridge(t, ctx, contractKeeper, nil)
	if result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "other", "command": "x"}}); err != nil || !result.IsError {
		t.Fatalf("expected a tool error: %+v, %v", result, err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_targets", Arguments: map[string]any{}})
	if err != nil || result.IsError {
		t.Fatalf("a call after a tool error failed: %+v, %v", result, err)
	}
	select {
	case <-keeper.Done():
		t.Fatal("a tool error ended the keeper session")
	default:
	}
}

// testForeignGeneric is declared at the test root to pin the historical type
// name of a generic instantiated with an implementation package argument.
type testForeignGeneric[T any] struct{ value T }

func TestMCPParseResultRejectsForeignAndNonPointerResults(t *testing.T) {
	for _, out := range []struct {
		result any
		want   string
	}{
		{&remote.ReadOutput{}, "unsupported result type *remote.ReadOutput"},
		{map[string]remote.ReadOutput{}, "unsupported result type map[string]remote.ReadOutput"},
		{ReadOutput{}, "unsupported result type bridge.ReadOutput"},
		{&apptransport.InfoOutput{}, "unsupported result type *apptransport.InfoOutput"},
		{testForeignGeneric[remote.ReadOutput]{}, "unsupported result type bridge.testForeignGeneric[github.com/PHPCraftdream/ssjack/internal/remote.ReadOutput]"},
	} {
		if err := ParseResult("", out.result); err == nil || err.Error() != out.want {
			t.Fatalf("ParseResult accepted or mislabeled %T: err %v, want %q", out.result, err, out.want)
		}
	}
}

var cancelStartedJob = regexp.MustCompile(`Started job (\S+)`)

func TestCancelToolsReportTheKeeperAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("remote_cancel of a running job says cancelled", func(t *testing.T) {
		manager := remote.NewManager(ctx, []string{"t"}, func(ctx context.Context, _, _ string, _, _ io.Writer) (int, error) {
			<-ctx.Done()
			return -1, ctx.Err()
		})
		session, _ := connectBridge(t, ctx, func(callCtx context.Context, req wire.Request) wire.Reply { return manager.Handle(callCtx, req) }, nil)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "t", "command": "wait"}})
		if err != nil || res.IsError {
			t.Fatalf("remote_exec failed: result=%+v err=%v", res, err)
		}
		text, err := ResultText(res)
		if err != nil {
			t.Fatal(err)
		}
		id := cancelStartedJob.FindStringSubmatch(text)
		if len(id) != 2 {
			t.Fatalf("could not extract job ID from %q", text)
		}
		res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_cancel", Arguments: map[string]any{"job_id": id[1]}})
		if err != nil || res.IsError {
			t.Fatalf("remote_cancel failed: result=%+v err=%v", res, err)
		}
		text, err = ResultText(res)
		if err != nil || text != "Cancelled job "+id[1] {
			t.Fatalf("remote_cancel answered %q: %v", text, err)
		}
	})

	t.Run("remote_cancel of a finished job says it had already finished", func(t *testing.T) {
		manager := remote.NewManager(ctx, []string{"t"}, func(_ context.Context, _, _ string, _, _ io.Writer) (int, error) { return 0, nil })
		session, _ := connectBridge(t, ctx, func(callCtx context.Context, req wire.Request) wire.Reply { return manager.Handle(callCtx, req) }, nil)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "t", "command": "done"}})
		if err != nil || res.IsError {
			t.Fatalf("remote_exec failed: result=%+v err=%v", res, err)
		}
		text, err := ResultText(res)
		if err != nil {
			t.Fatal(err)
		}
		id := cancelStartedJob.FindStringSubmatch(text)
		if len(id) != 2 {
			t.Fatalf("could not extract job ID from %q", text)
		}
		res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_read", Arguments: map[string]any{"job_id": id[1], "wait_seconds": 20}})
		if err != nil || res.IsError {
			t.Fatalf("remote_read failed: result=%+v err=%v", res, err)
		}
		doneText, err := ResultText(res)
		if err != nil || !strings.Contains(doneText, "done (exit code 0)") {
			t.Fatalf("job not observed done: %q, %v", doneText, err)
		}
		res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_cancel", Arguments: map[string]any{"job_id": id[1]}})
		if err != nil || res.IsError {
			t.Fatalf("remote_cancel failed: result=%+v err=%v", res, err)
		}
		text, err = ResultText(res)
		if err != nil || text != "Job "+id[1]+" had already finished" {
			t.Fatalf("remote_cancel answered %q: %v", text, err)
		}
	})

	t.Run("remote_cancel of an unknown job errors", func(t *testing.T) {
		manager := remote.NewManager(ctx, []string{"t"}, func(_ context.Context, _, _ string, _, _ io.Writer) (int, error) { return 0, nil })
		session, _ := connectBridge(t, ctx, func(callCtx context.Context, req wire.Request) wire.Reply { return manager.Handle(callCtx, req) }, nil)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_cancel", Arguments: map[string]any{"job_id": "no-such-job"}})
		if err != nil || !res.IsError {
			t.Fatalf("remote_cancel of an unknown job = %+v, %v", res, err)
		}
	})

	t.Run("app_cancel of a running job says cancelled", func(t *testing.T) {
		handler := func(_ context.Context, req wire.Request) wire.Reply {
			if req.Operation == "app_cancel" {
				return broker.Result(remote.CancelOutput{Cancelled: true}, nil)
			}
			return wire.Reply{Error: "denied"}
		}
		session, _ := connectBridge(t, ctx, handler, nil)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "app_cancel", Arguments: map[string]any{"job_id": "app-job"}})
		if err != nil || res.IsError {
			t.Fatalf("app_cancel failed: result=%+v err=%v", res, err)
		}
		text, err := ResultText(res)
		if err != nil || text != "Cancelled job app-job" {
			t.Fatalf("unexpected cancellation result %q: %v", text, err)
		}
	})

	t.Run("app_cancel of a finished job says it had already finished", func(t *testing.T) {
		handler := func(_ context.Context, req wire.Request) wire.Reply {
			if req.Operation == "app_cancel" {
				return broker.Result(remote.CancelOutput{Cancelled: false}, nil)
			}
			return wire.Reply{Error: "denied"}
		}
		session, _ := connectBridge(t, ctx, handler, nil)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "app_cancel", Arguments: map[string]any{"job_id": "app-job"}})
		if err != nil || res.IsError {
			t.Fatalf("app_cancel failed: result=%+v err=%v", res, err)
		}
		text, err := ResultText(res)
		if err != nil || text != "Job app-job had already finished" {
			t.Fatalf("unexpected cancellation result %q: %v", text, err)
		}
	})
}

func (k *taskKeeper) setExecRead(fn func(call int, input remote.ReadInput) remote.ReadOutput) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.execReadFn = fn
}

func TestExecTaskRunningDoneAndCancellation(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{}
	keeper.setExecRead(func(call int, input remote.ReadInput) remote.ReadOutput {
		if call == 1 {
			return remote.ReadOutput{JobID: input.JobID, Done: false}
		}
		return remote.ReadOutput{JobID: input.JobID, Done: true, ExitCode: 0}
	})
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	started := callTaskTool(t, ctx, session, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
	if started.IsError || len(started.Content) != 0 {
		t.Fatalf("remote_exec did not return task handle: %+v", started)
	}
	id := keeper.started()[0]
	running, err := taskGet(ctx, session, id)
	if err != nil || running.Status != "working" || running.StatusMessage != "" {
		t.Fatalf("running task: %+v, %v; want working with empty statusMessage", running, err)
	}
	done, err := taskGet(ctx, session, id)
	if err != nil || done.Status != "completed" {
		t.Fatalf("completed task: %+v, %v", done, err)
	}
	want := "Status: finished · exit code 0\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no · job " + id
	if got := answerText(t, done.Result); got != want {
		t.Fatalf("completed result %q, want %q", got, want)
	}

	cancelKeeper := &taskKeeper{}
	cancelSession, _ := newTaskBridge(t, ctx, cancelKeeper, nil, true, "2026-07-28")
	cancelStarted := callTaskTool(t, ctx, cancelSession, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
	if cancelStarted.IsError || len(cancelStarted.Content) != 0 {
		t.Fatalf("remote_exec did not return task handle for cancellation: %+v", cancelStarted)
	}
	cancelID := cancelKeeper.started()[0]
	if _, err := taskCancel(ctx, cancelSession, cancelID); err != nil {
		t.Fatalf("tasks/cancel: %v", err)
	}
	if got := cancelKeeper.execCancels; len(got) != 1 || got[0] != "cancel:"+cancelID {
		t.Fatalf("tasks/cancel keeper operations %v, want cancel:%s", got, cancelID)
	}

	appKeeper := &taskKeeper{}
	appSession, _ := newTaskBridge(t, ctx, appKeeper, nil, true, "2026-07-28")
	appStarted := callTaskTool(t, ctx, appSession, "app_exec", map[string]any{"application": "allowed", "arguments": []string{"status"}})
	if appStarted.IsError || len(appStarted.Content) != 0 {
		t.Fatalf("app_exec did not return task handle: %+v", appStarted)
	}
	appID := appKeeper.started()[0]
	if result, err := appSession.CallTool(ctx, &mcp.CallToolParams{Name: "app_cancel", Arguments: map[string]any{"job_id": appID}}); err != nil || result.IsError || answerText(t, result) != "Cancelled job "+appID {
		t.Fatalf("app_cancel: %+v, %v", result, err)
	}
	if got := appKeeper.execCancels; len(got) != 1 || got[0] != "app_cancel:"+appID {
		t.Fatalf("app task cancellation operations %v", got)
	}
}

func TestExecTaskInterceptionEligibilityAndFallback(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	testEligibleStart := func(t *testing.T, tool string, args map[string]any) {
		t.Helper()
		keeper := &taskKeeper{}
		recorded := &recorder{}
		session, _ := newTaskBridgeWith(t, ctx, keeper, nil, true, "2026-07-28", nil, func(inner mcp.Transport) mcp.Transport {
			return &recordingTransport{inner: inner, recorder: recorded}
		})
		result := callTaskTool(t, ctx, session, tool, args)
		if result.IsError || len(result.Content) != 0 {
			t.Fatalf("eligible start did not return a handle: %+v", result)
		}
		id := keeper.started()[0]
		var rawHandle string
		for _, frame := range recorded.all() {
			var response struct {
				Result struct {
					TaskID string `json:"taskId"`
				} `json:"result"`
			}
			if json.Unmarshal(frame, &response) == nil && response.Result.TaskID != "" {
				rawHandle = response.Result.TaskID
			}
		}
		if rawHandle != id {
			t.Fatalf("raw tools/call handle taskId %q, want keeper job id %q: %q", rawHandle, id, recorded.all())
		}
		if got := keeper.ops(); len(got) != 1 || got[0] != map[string]string{"remote_exec": "start", "app_exec": "app_start"}[tool] {
			t.Fatalf("start operations %v", got)
		}
		answer, err := taskGet(ctx, session, id)
		if err != nil || answer.TaskID != id || answer.Status != "working" {
			t.Fatalf("task handle id/status: %+v, %v", answer, err)
		}
	}
	t.Run("remote_exec", func(t *testing.T) {
		testEligibleStart(t, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
	})
	t.Run("app_exec", func(t *testing.T) {
		testEligibleStart(t, "app_exec", map[string]any{"application": "allowed", "arguments": []string{"status"}})
	})
	t.Run("non-declaring", func(t *testing.T) {
		runFallback := func(tool string) {
			keeper := &taskKeeper{}
			session, _ := newTaskBridge(t, ctx, keeper, nil, false, "2026-07-28")
			args := map[string]any{"target": "allowed", "command": "true"}
			want := func(id string) string {
				return "Started job " + id + "\nRead output with remote_read job_id=" + id + "; use wait_seconds 20 to wait for it."
			}
			if tool == "app_exec" {
				args = map[string]any{"application": "allowed", "arguments": []string{"status"}}
				want = func(id string) string {
					return "Started job " + id + "\nRead output with app_read job_id=" + id + "; use wait_seconds 20 to wait for it."
				}
			}
			result := callTaskTool(t, ctx, session, tool, args)
			id := keeper.started()[0]
			if got := answerText(t, result); got != want(id) {
				t.Fatalf("fallback %q, want %q", got, want(id))
			}
			if _, err := taskGet(ctx, session, id); err == nil || rpcError(t, err).Code != -32602 {
				t.Fatalf("fallback unexpectedly created task %q: %v", id, err)
			}
		}
		t.Run("remote_exec", func(t *testing.T) { runFallback("remote_exec") })
		t.Run("app_exec", func(t *testing.T) { runFallback("app_exec") })
	})
	t.Run("legacy_revision", func(t *testing.T) {
		keeper := &taskKeeper{}
		session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2025-11-25")
		result := callTaskTool(t, ctx, session, "app_exec", map[string]any{"application": "allowed", "arguments": []string{"status"}})
		if !strings.HasPrefix(answerText(t, result), "Started job ") || strings.Contains(answerText(t, result), "task") {
			t.Fatalf("legacy fallback %q", answerText(t, result))
		}
	})
	t.Run("legacy_pre_revision", func(t *testing.T) {
		keeper := &taskKeeper{}
		session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-27")
		result := callTaskTool(t, ctx, session, "app_exec", map[string]any{"application": "allowed", "arguments": []string{"status"}})
		if !strings.HasPrefix(answerText(t, result), "Started job ") || strings.Contains(answerText(t, result), "task") {
			t.Fatalf("legacy fallback %q", answerText(t, result))
		}
	})
	t.Run("refused start", func(t *testing.T) {
		runRefusedStart := func(tool string) {
			keeper := &taskKeeper{execStartError: "refused"}
			session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
			args := map[string]any{"target": "allowed", "command": "true"}
			if tool == "app_exec" {
				args = map[string]any{"application": "allowed", "arguments": []string{"status"}}
			}
			result := callTaskTool(t, ctx, session, tool, args)
			if !result.IsError || answerText(t, result) != "refused" {
				t.Fatalf("refusal changed: %+v", result)
			}
			if _, err := taskGet(ctx, session, strings.Repeat("ab", 32)); err == nil || rpcError(t, err).Code != -32602 {
				t.Fatalf("refused start created a task: %v", err)
			}
		}
		t.Run("remote_exec", func(t *testing.T) { runRefusedStart("remote_exec") })
		t.Run("app_exec", func(t *testing.T) { runRefusedStart("app_exec") })
	})
}

func TestExecToolsUseSharedBrokerAndPreserveErrorsAndBytes(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &taskKeeper{execRead: remote.ReadOutput{Done: true, ExitCode: 0, Stdout: []byte{0xff}, StdoutOffset: 10}}
	session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
	testTool := func(t *testing.T, tool, op string) {
		t.Helper()
		args := map[string]any{"target": "allowed", "command": "true"}
		if tool == "app_exec" {
			args = map[string]any{"application": "allowed", "arguments": []string{"status"}}
		}
		result := callTaskTool(t, ctx, session, tool, args)
		if result.IsError || len(result.Content) != 0 {
			t.Fatalf("start: %+v", result)
		}
		started := keeper.started()
		id := started[len(started)-1]
		if _, err := taskCancel(ctx, session, id); err != nil {
			t.Fatalf("task cancel: %v", err)
		}
		wantCancel := "cancel:" + id
		if tool == "app_exec" {
			wantCancel = "app_cancel:" + id
		}
		if keeper.execCancels[len(keeper.execCancels)-1] != wantCancel {
			t.Fatalf("cancel operation %q, want %q", keeper.execCancels[len(keeper.execCancels)-1], wantCancel)
		}
		answer, err := taskGet(ctx, session, id)
		if err != nil || answer.Status != "completed" {
			t.Fatalf("get: %+v %v", answer, err)
		}
		want := "Status: finished · exit code 0\nResume: stdout_offset=9 stderr_offset=0 · more: stdout=yes stderr=no · lost: stdout=no stderr=no · job " + id
		if got := answerText(t, answer.Result); got != want {
			t.Fatalf("raw-byte resume result %q, want %q", got, want)
		}
		if got := countOps(keeper.ops(), op); got != 1 {
			t.Fatalf("selected read operation %q count=%d", op, got)
		}
	}
	t.Run("remote_task_tools", func(t *testing.T) { testTool(t, "remote_exec", "read") })
	t.Run("application_task_tools", func(t *testing.T) { testTool(t, "app_exec", "app_read") })
	keeper.mu.Lock()
	reads := append([]remote.ReadInput(nil), keeper.execReads...)
	keeper.mu.Unlock()
	if len(reads) != 2 {
		t.Fatalf("read inputs: %+v", reads)
	}
	for _, input := range reads {
		if input.StdoutOffset != 0 || input.StderrOffset != 0 || input.WaitSeconds != 0 || input.JobID == "" {
			t.Fatalf("read did not use zero offsets/wait and job ID: %+v", input)
		}
	}
	t.Run("session closed", func(t *testing.T) {
		keeper := &taskKeeper{}
		session, server := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
		result := callTaskTool(t, ctx, session, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
		if result.IsError || len(result.Content) != 0 {
			t.Fatalf("start: %+v", result)
		}
		server.Close()
		id := keeper.started()[0]
		answer, err := taskGet(ctx, session, id)
		if err != nil || answer.Status != "failed" {
			t.Fatalf("closed attachment mapping: %+v %v", answer, err)
		}
	})
	t.Run("unknown operation", func(t *testing.T) {
		keeper := &taskKeeper{execErr: "unknown operation"}
		session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
		callTaskTool(t, ctx, session, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
		id := keeper.started()[0]
		answer, err := taskGet(ctx, session, id)
		if err != nil || answer.Status != "failed" {
			t.Fatalf("unknown-operation mapping: %+v %v", answer, err)
		}
	})
	t.Run("ordinary error", func(t *testing.T) {
		keeper := &taskKeeper{execErr: "temporary"}
		session, _ := newTaskBridge(t, ctx, keeper, nil, true, "2026-07-28")
		callTaskTool(t, ctx, session, "remote_exec", map[string]any{"target": "allowed", "command": "true"})
		id := keeper.started()[0]
		answer, err := taskGet(ctx, session, id)
		if answer != nil || err == nil {
			t.Fatalf("ordinary error should be returned: %+v %v", answer, err)
		}
		var rpcErr *jsonrpc.Error
		if !errors.As(err, &rpcErr) || rpcErr.Code != -32603 || rpcErr.Message != "the task could not be read" {
			t.Fatalf("ordinary error mapping: %v", err)
		}
	})
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
