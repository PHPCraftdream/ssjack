package bridge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/broker"
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
