package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestMCPToolsOverAuthenticatedConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("1", 64), Token: strings.Repeat("2", 64)}
	keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
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
			return broker.Result(remote.ReadOutput{JobID: "test-job", Stdout: []byte("Hello"), Done: true, ExitCode: 0}, nil)
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
			return broker.Result(remote.ReadOutput{JobID: "app-job", Stdout: []byte("Application result"), Done: true, ExitCode: 0}, nil)
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
	})
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	connection, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := NewServer(connection).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "dev"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 12 {
		t.Fatalf("unexpected tool list: %+v, %v", tools, err)
	}
	for _, call := range []struct {
		name string
		args map[string]any
		text string
	}{
		{"remote_targets", map[string]any{}, "allowed"},
		{"remote_exec", map[string]any{"target": "allowed", "command": "echo hello"}, "test-job"},
		{"remote_read", map[string]any{"job_id": "test-job"}, "Hello"},
		{"remote_cancel", map[string]any{"job_id": "test-job"}, "true"},
		{"app_list", map[string]any{}, "synthetic"},
		{"app_exec", map[string]any{"application": "synthetic", "arguments": []string{"status"}}, "app-job"},
		{"app_read", map[string]any{"job_id": "app-job"}, "Application result"},
		{"app_cancel", map[string]any{"job_id": "app-job"}, "true"},
		{"remote_upload", map[string]any{"target": "allowed", "local": "a.txt", "remote": "/srv/a.txt"}, "transfer-job"},
		{"remote_download", map[string]any{"target": "allowed", "local": "a.txt", "remote": "/srv/a.txt"}, "transfer-job"},
		{"transfer_status", map[string]any{"job_id": "transfer-job"}, "done"},
		{"transfer_cancel", map[string]any{"job_id": "transfer-job"}, "true"},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || result.IsError {
			t.Fatalf("%s: %+v, %v", call.name, result, err)
		}
		data, err := json.Marshal(result)
		if err != nil || !strings.Contains(string(data), call.text) || strings.Contains(string(data), auth.Token) {
			t.Fatalf("unexpected response for %s", call.name)
		}
	}
	chunkFields := []string{"mode", "chunk_bytes", "chunks_done", "chunks_total", "attempts", "bytes_per_second"}
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	for name, wants := range map[string][]string{
		"remote_upload":   {"link_unstable", "resume", "twice the file size", "Directories are never chunked", "transfer_cancel removes"},
		"remote_download": {"link_unstable", "resume", "twice the file size", "Directories are never chunked", "transfer_cancel removes"},
		"transfer_status": append([]string{"link_unstable", "refused_path", "never decreases", "manifest_sha256", "wait_seconds"}, chunkFields...),
		"remote_read":     {"wait_seconds", "done indicates"},
		"app_read":        {"wait_seconds", "drain both streams"},
		"transfer_cancel": {"removed", "link failure keeps"},
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("tool %s is not listed", name)
		}
		if len(tool.Description) > 2000 || strings.Contains(tool.Description, `:\`) {
			t.Fatalf("%s description is unbounded or carries a local path: %q", name, tool.Description)
		}
		for _, want := range wants {
			if !strings.Contains(tool.Description, want) {
				t.Fatalf("%s description lacks %q: %q", name, want, tool.Description)
			}
		}
	}
	schemaData, err := json.Marshal(byName["transfer_status"].OutputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatalf("transfer_status output schema is not an object schema: %v", err)
	}
	required := map[string]bool{}
	for _, name := range schema.Required {
		required[name] = true
	}
	for _, field := range chunkFields {
		if _, ok := schema.Properties[field]; !ok {
			t.Fatalf("transfer_status output schema lacks %q: %s", field, schemaData)
		}
		if required[field] {
			t.Fatalf("transfer_status output schema requires the optional field %q", field)
		}
	}
	status, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "transfer_status", Arguments: map[string]any{"job_id": "transfer-job"}})
	if err != nil || status.IsError {
		t.Fatalf("transfer_status: %+v, %v", status, err)
	}
	structuredData, err := json.Marshal(status.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var structured map[string]any
	if err := json.Unmarshal(structuredData, &structured); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]any{
		"mode": "chunked", "chunk_bytes": float64(262144), "chunks_done": float64(2), "chunks_total": float64(5),
		"attempts": float64(3), "bytes_per_second": float64(1000),
	} {
		if structured[field] != want {
			t.Fatalf("structured %s = %v, want %v: %s", field, structured[field], want, structuredData)
		}
	}
	denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "other", "command": "echo hello"}})
	if err != nil || !denied.IsError {
		t.Fatal("target error was not propagated to the MCP client")
	}
}
