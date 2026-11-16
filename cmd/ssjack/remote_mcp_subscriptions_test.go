package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const remoteMCPSubscriptionsTestMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"subscriptions-test-client","version":"1"}}`

// startStdioMCPSubscriptionsToolFixture owns a configured SDK server with a
// tool capability so modern toolsListChanged subscriptions are accepted.
func startStdioMCPSubscriptionsToolFixture(t *testing.T, listenDeadlines ...chan time.Time) (io.WriteCloser, io.ReadCloser, context.CancelFunc, <-chan error, <-chan struct{}) {
	t.Helper()
	if len(listenDeadlines) > 1 {
		t.Fatal("at most one listen deadline observer may be supplied")
	}
	serverIn, clientIn := io.Pipe()
	clientOut, serverOut := io.Pipe()
	server := mcp.NewServer(&mcp.Implementation{Name: "subscriptions-fixture", Version: "1"}, nil)
	if len(listenDeadlines) == 1 {
		deadlineObserved := listenDeadlines[0]
		// Register before configureMCPStdioServer: the configure middleware is
		// then outermost and this observer receives its bounded context.
		server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if method == "subscriptions/listen" {
					if deadline, ok := ctx.Deadline(); ok {
						select {
						case deadlineObserved <- deadline:
						default:
						}
					}
				}
				return next(ctx, method, req)
			}
		})
	}
	configureMCPStdioServer(server)
	server.AddTool(&mcp.Tool{Name: "fixture_tool", Description: "subscription capability fixture", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	runErr, runDone := make(chan error, 1), make(chan struct{})
	go func() {
		runErr <- server.Run(ctx, newMCPStdioTransport(serverIn, serverOut))
		close(runDone)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientIn.Close()
		_ = clientOut.Close()
		_ = serverIn.Close()
		_ = serverOut.Close()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("owned subscriptions SDK server goroutine did not join")
		}
	})
	return clientIn, clientOut, cancel, runErr, runDone
}

func TestMCPStdioModernSubscriptionsListenLifecycle(t *testing.T) {
	in, out, cancel, runErr, runDone := startStdioMCPSubscriptionsToolFixture(t)

	// The acknowledgement is a notification on the listen stream, not the
	// listen RPC's result. Its metadata correlates it to the listen request.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, out), 1)

	// A normal modern call can complete while the subscription remains parked.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, out), false, 2)[2]
	assertMCPSubscriptionsModernResult(t, listed, "tools/list")
	tools, ok := listed["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools/list did not return the fixture tool: %#v", listed["tools"])
	}
	tool, ok := tools[0].(map[string]any)
	if !ok || tool["name"] != "fixture_tool" {
		t.Fatalf("tools/list returned an unexpected fixture entry: %#v", tools[0])
	}

	// The single-listen admission limit has a stable invalid-params refusal.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, out), 3, -32602, "subscriptions/listen already active")

	// The SDK's listen handler returns a complete result after the peer
	// cancellation notification. Observing it proves the middleware released
	// its one active slot before the next listen.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"test",`+remoteMCPSubscriptionsTestMeta+`}}`)
	finished := sdkCallResults(t, readMCPLine(t, out), false, 1)[1]
	assertMCPSubscriptionsListenResult(t, finished, 1)

	// A new listen can now occupy the released slot.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":4,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, out), 4)

	// Run cancellation can close the transport before a response is written.
	// The protocol permits that abrupt shutdown without a listen result; if the
	// SDK wins the race and writes the complete result first, validate it too.
	// Start the shutdown reader before cancellation: SDK Close may race a
	// completed result with transport closure, and an accepted pipe write must
	// not block Run while this test waits for the server goroutine.
	shutdownRead, shutdownReadExited := startMCPSubscriptionsShutdownRead(out)
	t.Cleanup(func() {
		select {
		case <-shutdownReadExited:
			return
		default:
		}
		_ = out.Close()
		select {
		case <-shutdownReadExited:
		case <-time.After(time.Second):
			t.Error("owned shutdown response reader did not exit after its reader was released")
		}
	})
	cancel()
	if err := awaitSignal(t, runErr, "configured SDK server did not return after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("configured SDK server returned an unexpected shutdown error: %v", err)
	}
	awaitSignal(t, runDone, "configured SDK server completion was not joined")
	result := awaitSignal(t, shutdownRead, "shutdown reader did not observe the response or EOF")
	awaitSignal(t, shutdownReadExited, "shutdown reader did not exit")
	if result.err != nil && !errors.Is(result.err, io.EOF) {
		t.Fatalf("shutdown reader returned an unexpected error: %v", result.err)
	}
	if result.line != "" && !strings.HasSuffix(result.line, "\n") {
		// A writer interrupted by transport closure may leave a partial frame;
		// EOF makes that an abrupt close, not a JSON-RPC response.
		if !errors.Is(result.err, io.EOF) {
			t.Fatalf("incomplete shutdown frame did not end with EOF: %v", result.err)
		}
	} else if result.line != "" {
		shutdownResult := sdkCallResults(t, result.line, false, 4)[4]
		assertMCPSubscriptionsListenResult(t, shutdownResult, 4)
	}
	assertMCPSubscriptionsReaderEOF(t, out)
}

func TestMCPStdioModernSubscriptionsWithNoAcceptedNotifications(t *testing.T) {
	in, out, cancel, runErr, runDone := startStdioMCPSubscriptionsToolFixture(t)

	// The tools-only fixture advertises neither resources nor prompts, so none
	// of these requested subscriptions is accepted.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":20,"method":"subscriptions/listen","params":{"notifications":{"resourcesListChanged":true,"promptsListChanged":true,"resourceSubscriptions":["file:///not-advertised"]},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsEmptyAck(t, readMCPLine(t, out), 20)
	completed := sdkCallResults(t, readMCPLine(t, out), false, 20)[20]
	assertMCPSubscriptionsListenResult(t, completed, 20)

	// The empty listen must finish without inventing notifications and leave
	// ordinary requests usable on the same connection.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":21,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, out), false, 21)[21]
	assertMCPSubscriptionsModernResult(t, listed, "tools/list")
	tools, ok := listed["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools/list after an empty subscription returned unexpected tools: %#v", listed["tools"])
	}
	cancel()
	if err := awaitSignal(t, runErr, "configured SDK server did not return after cancellation of the empty subscription fixture"); !errors.Is(err, context.Canceled) {
		t.Fatalf("configured SDK server returned an unexpected shutdown error after the empty subscription: %v", err)
	}
	awaitSignal(t, runDone, "empty subscription SDK server completion was not joined")
	// Any unsolicited notification queued after tools/list is data, not EOF.
	assertMCPSubscriptionsReaderEOF(t, out)
}

func TestMCPStdioSubscriptionsListenHasConfiguredDeadline(t *testing.T) {
	deadlines := make(chan time.Time, 1)
	in, out, _, _, _ := startStdioMCPSubscriptionsToolFixture(t, deadlines)

	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":30,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, out), 30)
	deadline := awaitSignal(t, deadlines, "listen middleware did not observe a context deadline")
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > remoteMCPSubscriptionsListenBudget+250*time.Millisecond {
		t.Fatalf("listen deadline was outside the configured budget: remaining %s, budget %s", remaining, remoteMCPSubscriptionsListenBudget)
	}
}

func TestMCPStdioSubscriptionsListenRequiresModernNotifications(t *testing.T) {
	in, out, _, _, _ := startStdioMCPSubscriptionsToolFixture(t)

	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":10,"method":"subscriptions/listen","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, out), 10, -32602, "")

	// subscriptions/listen exists only in the modern per-request protocol.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":11,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, out), 11, -32601, "method not found")
}

func assertMCPSubscriptionsAck(t *testing.T, line string, listenID int64) {
	t.Helper()
	message, err := jsonrpc.DecodeMessage([]byte(strings.TrimSpace(line)))
	if err != nil {
		t.Fatalf("subscriptions acknowledgement did not decode: %v", err)
	}
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.ID.IsValid() || request.Method != "notifications/subscriptions/acknowledged" {
		t.Fatalf("listen stream did not begin with an acknowledgement notification: %#v", message)
	}
	var params struct {
		Meta          map[string]json.RawMessage `json:"_meta"`
		Notifications struct {
			ToolsListChanged     bool `json:"toolsListChanged"`
			PromptsListChanged   bool `json:"promptsListChanged"`
			ResourcesListChanged bool `json:"resourcesListChanged"`
		} `json:"notifications"`
	}
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("subscriptions acknowledgement parameters did not decode: %v", err)
	}
	var gotID int64
	if raw, ok := params.Meta[mcp.MetaKeySubscriptionID]; !ok || json.Unmarshal(raw, &gotID) != nil || gotID != listenID {
		t.Fatalf("acknowledgement subscriptionId did not match listen request %d: %s", listenID, raw)
	}
	if len(params.Meta) != 1 || !params.Notifications.ToolsListChanged || params.Notifications.PromptsListChanged || params.Notifications.ResourcesListChanged {
		t.Fatalf("acknowledgement did not contain exactly the accepted tools subscription: %s", request.Params)
	}
}

type mcpSubscriptionsShutdownRead struct {
	line string
	err  error
}

func startMCPSubscriptionsShutdownRead(reader io.Reader) (<-chan mcpSubscriptionsShutdownRead, <-chan struct{}) {
	read := make(chan mcpSubscriptionsShutdownRead, 1)
	started, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		var line []byte
		one := make([]byte, 1)
		close(started)
		for {
			n, err := reader.Read(one)
			line = append(line, one[:n]...)
			if n > 0 && line[len(line)-1] == '\n' {
				read <- mcpSubscriptionsShutdownRead{line: string(line), err: err}
				return
			}
			if err != nil {
				read <- mcpSubscriptionsShutdownRead{line: string(line), err: err}
				return
			}
		}
	}()
	<-started
	return read, exited
}

func assertMCPSubscriptionsReaderEOF(t *testing.T, reader io.ReadCloser) {
	t.Helper()
	type readResult struct {
		n   int
		err error
	}
	read := make(chan readResult, 1)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		buf := make([]byte, 1)
		n, err := reader.Read(buf)
		read <- readResult{n: n, err: err}
	}()
	select {
	case result := <-read:
		awaitSignal(t, exited, "shutdown EOF reader did not exit")
		if result.n != 0 || !errors.Is(result.err, io.EOF) {
			t.Fatalf("shutdown reader did not reach EOF: read %d bytes, error %v", result.n, result.err)
		}
	case <-time.After(time.Second):
		_ = reader.Close()
		awaitSignal(t, exited, "shutdown EOF reader did not exit after its reader was released")
		t.Fatal("shutdown reader remained open after the SDK server joined")
	}
}

func assertMCPSubscriptionsEmptyAck(t *testing.T, line string, listenID int64) {
	t.Helper()
	message, err := jsonrpc.DecodeMessage([]byte(strings.TrimSpace(line)))
	if err != nil {
		t.Fatalf("subscriptions acknowledgement did not decode: %v", err)
	}
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.ID.IsValid() || request.Method != "notifications/subscriptions/acknowledged" {
		t.Fatalf("listen stream did not begin with an acknowledgement notification: %#v", message)
	}
	var params struct {
		Meta          map[string]json.RawMessage `json:"_meta"`
		Notifications json.RawMessage            `json:"notifications"`
	}
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("subscriptions acknowledgement parameters did not decode: %v", err)
	}
	var gotID int64
	if raw, ok := params.Meta[mcp.MetaKeySubscriptionID]; !ok || json.Unmarshal(raw, &gotID) != nil || gotID != listenID {
		t.Fatalf("acknowledgement subscriptionId did not match listen request %d: %s", listenID, raw)
	}
	var notifications map[string]json.RawMessage
	if err := json.Unmarshal(params.Notifications, &notifications); err != nil || len(notifications) != 0 || string(params.Notifications) != `{}` {
		t.Fatalf("acknowledgement did not contain the exact empty notifications object: %s", params.Notifications)
	}
	if len(params.Meta) != 1 {
		t.Fatalf("empty acknowledgement metadata contained fields beyond subscriptionId: %s", request.Params)
	}
}

func assertMCPSubscriptionsError(t *testing.T, line string, wantID int64, wantCode int64, wantMessage string) {
	t.Helper()
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int64           `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &envelope); err != nil {
		t.Fatalf("JSON-RPC error response did not decode: %v", err)
	}
	if envelope.JSONRPC != "2.0" || envelope.ID != wantID || len(envelope.Result) != 0 || envelope.Error == nil || envelope.Error.Code != wantCode || (wantMessage != "" && envelope.Error.Message != wantMessage) {
		t.Fatalf("unexpected error response for id %d: %s", wantID, line)
	}
}

func assertMCPSubscriptionsModernResult(t *testing.T, result map[string]any, method string) {
	t.Helper()
	meta, ok := result["_meta"].(map[string]any)
	serverInfo, infoOK := meta[mcp.MetaKeyServerInfo].(map[string]any)
	if result["resultType"] != "complete" || !ok || !infoOK || serverInfo["name"] != "subscriptions-fixture" {
		t.Fatalf("%s did not return a modern protocol result: %#v", method, result)
	}
}

func assertMCPSubscriptionsListenResult(t *testing.T, result map[string]any, listenID int64) {
	t.Helper()
	assertMCPSubscriptionsModernResult(t, result, "subscriptions/listen")
	meta, ok := result["_meta"].(map[string]any)
	gotID, idOK := meta[mcp.MetaKeySubscriptionID].(float64)
	if !ok || !idOK || gotID != float64(listenID) {
		t.Fatalf("listen result subscriptionId did not match request %d: %#v", listenID, result["_meta"])
	}
}
