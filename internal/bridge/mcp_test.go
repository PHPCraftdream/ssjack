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
			return broker.Result(application.ListOutput{Applications: []application.Description{{Name: "clawwright", Profile: "allowed"}}}, nil)
		case "app_start":
			var input application.Input
			if wire.Decode(req.Data, &input) != nil || input.Application != "clawwright" || len(input.Arguments) != 1 || input.Arguments[0] != "status" {
				return wire.Reply{Error: "invalid application"}
			}
			return broker.Result(remote.StartOutput{JobID: "app-job"}, nil)
		case "app_read":
			return broker.Result(remote.ReadOutput{JobID: "app-job", Stdout: []byte("Clawwright result"), Done: true, ExitCode: 0}, nil)
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
	if err != nil || len(tools.Tools) != 8 {
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
		{"app_list", map[string]any{}, "clawwright"},
		{"app_exec", map[string]any{"application": "clawwright", "arguments": []string{"status"}}, "app-job"},
		{"app_read", map[string]any{"job_id": "app-job"}, "Clawwright result"},
		{"app_cancel", map[string]any{"job_id": "app-job"}, "true"},
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
	denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "other", "command": "echo hello"}})
	if err != nil || !denied.IsError {
		t.Fatal("target error was not propagated to the MCP client")
	}
}
