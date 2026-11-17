package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// connectBridge serves the full tool set over one authenticated keeper
// connection and returns an MCP client session to it. configure, when set,
// runs on the MCP server before it connects.
func connectBridge(t *testing.T, ctx context.Context, handler broker.Handler, configure func(*mcp.Server)) (*mcp.ClientSession, *broker.Server) {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("5", 64), Token: strings.Repeat("6", 64)}
	keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keeper.Close)
	connection, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := NewServer(connection)
	if configure != nil {
		configure(server)
	}
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "dev"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session, keeper
}

type seenCall struct {
	operation string
	wait      int
}

// recordingKeeper answers the polling operations and records the wait_seconds
// each request carried.
type recordingKeeper struct {
	mu   sync.Mutex
	seen []seenCall
}

func (k *recordingKeeper) handle(_ context.Context, req wire.Request) wire.Reply {
	switch req.Operation {
	case "read", "app_read":
		var input remote.ReadInput
		if wire.Decode(req.Data, &input) != nil {
			return wire.Reply{Error: "invalid read"}
		}
		k.record(req.Operation, input.WaitSeconds)
		return broker.Result(remote.ReadOutput{JobID: input.JobID, Stdout: []byte("out"), StdoutOffset: 3, Done: true}, nil)
	case "transfer_status":
		var input transfer.StatusInput
		if wire.Decode(req.Data, &input) != nil {
			return wire.Reply{Error: "invalid status"}
		}
		k.record(req.Operation, input.WaitSeconds)
		return broker.Result(transfer.StatusOutput{JobID: input.JobID, State: "done", Direction: "upload"}, nil)
	}
	return wire.Reply{Error: "denied"}
}

func (k *recordingKeeper) record(operation string, wait int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seen = append(k.seen, seenCall{operation: operation, wait: wait})
}

func (k *recordingKeeper) calls() []seenCall {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]seenCall(nil), k.seen...)
}

func resultText(result *mcp.CallToolResult) string {
	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(data)
}

func TestPollingToolsWaitSecondsArguments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &recordingKeeper{}
	session, _ := connectBridge(t, ctx, keeper.handle, nil)
	for _, tool := range []struct{ name, operation string }{
		{"remote_read", "read"},
		{"app_read", "app_read"},
		{"transfer_status", "transfer_status"},
	} {
		t.Run(tool.name, func(t *testing.T) {
			for _, ok := range []struct {
				label string
				wait  any
				want  int
			}{
				{"omitted", nil, 0},
				{"zero", 0, 0},
				{"twenty", 20, 20},
				{"cap", 25, 25},
				{"above the cap", 26, 25},
				{"far above the cap", 100000, 25},
			} {
				before := len(keeper.calls())
				arguments := map[string]any{"job_id": "j"}
				if ok.wait != nil {
					arguments["wait_seconds"] = ok.wait
				}
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool.name, Arguments: arguments})
				if err != nil || result.IsError {
					t.Fatalf("%s: %+v, %v", ok.label, result, err)
				}
				calls := keeper.calls()
				if len(calls) != before+1 || calls[before].operation != tool.operation || calls[before].wait != ok.want {
					t.Fatalf("%s: keeper saw %+v after %d earlier calls, want %s with wait_seconds %d", ok.label, calls, before, tool.operation, ok.want)
				}
				requireTextContract(t, tool.name, result)
			}
			for _, bad := range []struct {
				label string
				wait  any
			}{
				{"negative", -1},
				{"very negative", -100000},
				{"fraction", 1.5},
				{"text", "20"},
			} {
				before := len(keeper.calls())
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool.name, Arguments: map[string]any{"job_id": "j", "wait_seconds": bad.wait}})
				if err == nil && !result.IsError {
					t.Fatalf("%s: wait_seconds was accepted: %s", bad.label, resultText(result))
				}
				if bad.label == "negative" && !strings.Contains(resultText(result), "wait_seconds must be between 0 and 25") {
					t.Fatalf("%s: the refusal is not the fixed message: %s", bad.label, resultText(result))
				}
				if after := len(keeper.calls()); after != before {
					t.Fatalf("%s: a refused argument reached the keeper", bad.label)
				}
			}
		})
	}
}

func TestPollingToolDescriptionsAndSchemas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	keeper := &recordingKeeper{}
	session, _ := connectBridge(t, ctx, keeper.handle, nil)
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	for _, name := range []string{"remote_read", "app_read", "transfer_status"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("tool %s is not listed", name)
		}
		if len(tool.Description) > 2000 || strings.Contains(tool.Description, `:\`) {
			t.Fatalf("%s description is unbounded or carries a local path: %q", name, tool.Description)
		}
		for _, want := range []string{"wait_seconds", "0 to 25", "larger counts as 25", "prefer one call with wait_seconds 20"} {
			if !strings.Contains(tool.Description, want) {
				t.Fatalf("%s description lacks %q: %q", name, want, tool.Description)
			}
		}
		data, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]struct {
				Type        string `json:"type"`
				Description string `json:"description"`
			} `json:"properties"`
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s input schema is not an object schema: %v", name, err)
		}
		wait, ok := schema.Properties["wait_seconds"]
		if !ok || wait.Type != "integer" || !strings.Contains(wait.Description, "25") {
			t.Fatalf("%s input schema lacks an integer wait_seconds described with its cap: %s", name, data)
		}
		required := map[string]bool{}
		for _, field := range schema.Required {
			required[field] = true
		}
		if required["wait_seconds"] || !required["job_id"] {
			t.Fatalf("%s input schema requirements changed: %s", name, data)
		}
	}
	for _, name := range []string{"remote_exec", "remote_upload", "remote_download"} {
		if tool := byName[name]; tool == nil || !strings.Contains(tool.Description, "wait_seconds 20") || len(tool.Description) > 2000 {
			t.Fatalf("%s description does not point at wait_seconds: %+v", name, tool)
		}
	}
}

// A waiting read that the model abandons must not end the keeper session: the
// next call still works once the keeper answers the abandoned one.
func TestAbandonedWaitingCallKeepsTheKeeperSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	entered := make(chan struct{}, 4)
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	defer release()
	handler := func(_ context.Context, req wire.Request) wire.Reply {
		switch req.Operation {
		case "read":
			var input remote.ReadInput
			if wire.Decode(req.Data, &input) != nil {
				return wire.Reply{Error: "invalid read"}
			}
			if input.WaitSeconds > 0 {
				entered <- struct{}{}
				<-gate
			}
			return broker.Result(remote.ReadOutput{JobID: input.JobID, Done: true}, nil)
		case "targets":
			return broker.Result(remote.TargetsOutput{Targets: []string{"allowed"}}, nil)
		}
		return wire.Reply{Error: "denied"}
	}
	requestContexts := make(chan context.Context, 8)
	session, keeper := connectBridge(t, ctx, handler, func(server *mcp.Server) {
		server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if method == "tools/call" {
					select {
					case requestContexts <- ctx:
					default:
					}
				}
				return next(ctx, method, req)
			}
		})
	})
	callCtx, endCall := context.WithCancel(ctx)
	defer endCall()
	failed := make(chan error, 1)
	go func() {
		_, err := session.CallTool(callCtx, &mcp.CallToolParams{Name: "remote_read", Arguments: map[string]any{"job_id": "j", "wait_seconds": 20}})
		failed <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting read did not reach the keeper")
	}
	endCall()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("an abandoned call reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned call did not return")
	}
	var requestContext context.Context
	select {
	case requestContext = <-requestContexts:
	case <-time.After(5 * time.Second):
		t.Fatal("the request was not observed")
	}
	select {
	case <-requestContext.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the MCP request context did not end")
	}
	release()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_targets", Arguments: map[string]any{}})
	if err != nil || result.IsError || !strings.Contains(resultText(result), "allowed") {
		t.Fatalf("a call after the abandoned wait failed: %+v, %v", result, err)
	}
	select {
	case <-keeper.Done():
		t.Fatal("an abandoned waiting call ended the keeper session")
	default:
	}
}
