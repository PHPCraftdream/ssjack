package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"storagehost/internal/broker"
	"storagehost/internal/remote"
	"storagehost/internal/wire"
)

func TestMCPToolsOverAuthenticatedConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Session: strings.Repeat("1", 64), EnvToken: strings.Repeat("2", 64), DiskToken: strings.Repeat("3", 64)}
	keeper, err := broker.Listen(ctx, auth.Session, auth.EnvToken, auth.DiskToken, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
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
		case "cancel":
			return broker.Result(remote.CancelOutput{Cancelled: true}, nil)
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
	if err != nil || len(tools.Tools) != 4 {
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
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || result.IsError {
			t.Fatalf("%s: %+v, %v", call.name, result, err)
		}
		data, err := json.Marshal(result)
		if err != nil || !strings.Contains(string(data), call.text) || strings.Contains(string(data), auth.EnvToken) || strings.Contains(string(data), auth.DiskToken) {
			t.Fatalf("unexpected response for %s", call.name)
		}
	}
	denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "other", "command": "echo hello"}})
	if err != nil || !denied.IsError {
		t.Fatal("target error was not propagated to the MCP client")
	}
}
