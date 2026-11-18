package remotemcp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

const modernStdioServerName = "stdio-modern-fixture"

func startModernStdioSDKFixture(t *testing.T) (io.WriteCloser, io.ReadCloser, context.CancelFunc, <-chan error) {
	t.Helper()
	serverIn, serverInWriter := io.Pipe()
	clientOut, clientOutWriter := io.Pipe()
	server := mcp.NewServer(&mcp.Implementation{Name: modernStdioServerName, Version: "1"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{}})
	server.AddTool(&mcp.Tool{Name: "echo", Description: "echo input text", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Text string `json:"text"`
		}
		if request != nil && request.Params != nil {
			if err := json.Unmarshal(request.Params.Arguments, &args); err != nil {
				return nil, err
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil
	})
	configureMCPStdioServer(server)
	ctx, cancel := context.WithCancel(context.Background())
	runErr, runDone := make(chan error, 1), make(chan struct{})
	go func() {
		runErr <- server.Run(ctx, newMCPStdioTransport(serverIn, clientOutWriter))
		close(runDone)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientOutWriter.Close()
		_ = clientOut.Close()
		_ = serverInWriter.Close()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("custom SDK fixture server did not join")
		}
	})
	return serverInWriter, clientOut, cancel, runErr
}

func modernMeta() string {
	return `"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcpProtocol20260728 + `","io.modelcontextprotocol/clientCapabilities":{}}`
}

func modernizeParams(params string) string {
	prefix := params[:len(params)-1]
	if len(prefix) != 0 && prefix[len(prefix)-1] != '{' {
		prefix += ","
	}
	return prefix + modernMeta() + "}"
}

func assertCompleteModernResult(t *testing.T, result map[string]any) {
	t.Helper()
	if result["resultType"] != "complete" {
		t.Fatalf("modern resultType = %v, want complete", result["resultType"])
	}
	meta, ok := result["_meta"].(map[string]any)
	serverInfo, infoOK := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if !ok || !infoOK || serverInfo["name"] != modernStdioServerName || serverInfo["version"] != "1" {
		t.Fatalf("modern result omitted serverInfo: %#v", result["_meta"])
	}
}

func assertModernCacheFields(t *testing.T, result map[string]any) {
	t.Helper()
	if _, ok := result["ttlMs"].(float64); !ok {
		t.Fatalf("modern result omitted numeric ttlMs: %#v", result)
	}
	if result["cacheScope"] != "public" {
		t.Fatalf("modern result cacheScope = %v, want public", result["cacheScope"])
	}
}

func assertEchoText(t *testing.T, result map[int64]map[string]any, id int64, want string) {
	t.Helper()
	content, ok := result[id]["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("tools/call content = %#v", result[id]["content"])
	}
	item, ok := content[0].(map[string]any)
	if !ok || item["type"] != "text" || item["text"] != want {
		t.Fatalf("tools/call content item = %#v, want text %q", content[0], want)
	}
}

func assertRPCError(t *testing.T, line string, id, wantCode int64, wantMessage string) json.RawMessage {
	t.Helper()
	var envelope struct {
		ID     int64           `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int64           `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		t.Fatalf("error response did not decode: %q: %v", line, err)
	}
	if envelope.ID != id || len(envelope.Result) != 0 || envelope.Error == nil || envelope.Error.Code != wantCode || (wantMessage != "" && envelope.Error.Message != wantMessage) {
		var code int64
		var message string
		var data string
		if envelope.Error != nil {
			code = envelope.Error.Code
			message = envelope.Error.Message
			data = string(envelope.Error.Data)
		}
		if len(data) > 200 {
			data = data[:200] + "..."
		}
		t.Fatalf("error response id=%d code=%d message=%q data=%q, want id %d code %d message %q", envelope.ID, code, message, data, id, wantCode, wantMessage)
	}
	return envelope.Error.Data
}

// Raw initialize-era requests must keep working against the configured SDK
// server, including actual list and call traffic for each of the four versions.
func TestMCPStdioSDKLegacyRawInitializeListsAndCallsTool(t *testing.T) {
	for _, version := range []string{mcpProtocol20241105, mcpProtocol20250326, mcpProtocol20250618, mcpProtocol20251125} {
		t.Run(version, func(t *testing.T) {
			in, out, cancel, runErr := startModernStdioSDKFixture(t)
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":{},"clientInfo":{"name":"raw-legacy-client","version":"1"}}}`)
			initialized := sdkCallResults(t, readMCPLine(t, out), false, 1)[1]
			if initialized["protocolVersion"] != version {
				t.Fatalf("initialize negotiated %v, want exact version %s", initialized["protocolVersion"], version)
			}
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
			listed := sdkCallResults(t, readMCPLine(t, out), false, 2)[2]
			tools, ok := listed["tools"].([]any)
			if !ok || len(tools) != 1 {
				t.Fatalf("legacy tools/list = %#v, want one echo tool", listed["tools"])
			}
			tool, ok := tools[0].(map[string]any)
			if !ok || tool["name"] != "echo" {
				t.Fatalf("legacy tools/list = %#v, want the echo tool", listed["tools"])
			}
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"legacy `+version+`"}}}`)
			assertEchoText(t, sdkCallResults(t, readMCPLine(t, out), false, 3), 3, "legacy "+version)
			cancel()
			if err := awaitSignal(t, runErr, "custom SDK fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
				t.Fatalf("custom SDK fixture ended unexpectedly: %v", err)
			}
		})
	}
}

// Modern discover responses advertise the complete transport surface. A new
// fixture then proves modern list/call requests work without prior negotiation.
func TestMCPStdioSDKModernDiscoverResponseAndStatelessRequests(t *testing.T) {
	in, out, cancel, runErr := startModernStdioSDKFixture(t)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20260728+`","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	discovered := sdkCallResults(t, readMCPLine(t, out), false, 1)[1]
	assertCompleteModernResult(t, discovered)
	versions, ok := discovered["supportedVersions"].([]any)
	wantVersions := []string{mcpProtocol20260728, mcpProtocol20251125, mcpProtocol20250618, mcpProtocol20250326, mcpProtocol20241105}
	if !ok || len(versions) != len(wantVersions) {
		t.Fatalf("discover supportedVersions = %#v", discovered["supportedVersions"])
	}
	for i, want := range wantVersions {
		if versions[i] != want {
			t.Fatalf("discover supportedVersions = %#v, want exact order %#v", versions, wantVersions)
		}
	}
	capabilities, ok := discovered["capabilities"].(map[string]any)
	toolsCap, toolsOK := capabilities["tools"].(map[string]any)
	if !ok || !toolsOK || toolsCap["listChanged"] != true {
		t.Fatalf("discover capabilities omitted tool listChanged: %#v", discovered["capabilities"])
	}
	assertModernCacheFields(t, discovered)
	cancel()
	if err := awaitSignal(t, runErr, "custom SDK discover fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("custom SDK discover fixture ended unexpectedly: %v", err)
	}

	// A fresh fixture ensures the stateless calls are not inheriting state from discover.
	in, out, cancel, runErr = startModernStdioSDKFixture(t)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20260728+`","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	listed := sdkCallResults(t, readMCPLine(t, out), false, 2)[2]
	assertCompleteModernResult(t, listed)
	assertModernCacheFields(t, listed)
	listedTools, ok := listed["tools"].([]any)
	if !ok || len(listedTools) != 1 {
		t.Fatalf("stateless tools/list = %#v, want one echo tool", listed["tools"])
	}
	listedTool, ok := listedTools[0].(map[string]any)
	if !ok || listedTool["name"] != "echo" {
		t.Fatalf("stateless tools/list = %#v", listed["tools"])
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"stateless call"},`+modernMeta()+`}}`)
	called := sdkCallResults(t, readMCPLine(t, out), false, 3)
	assertCompleteModernResult(t, called[3])
	assertEchoText(t, called, 3, "stateless call")
	cancel()
	if err := awaitSignal(t, runErr, "custom SDK stateless fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("custom SDK stateless fixture ended unexpectedly: %v", err)
	}
}

// The bridge must reject unsupported or malformed request metadata precisely,
// while leaving supported legacy discovery and initialize fallback to the SDK.
func TestMCPStdioSDKProtocolMetadataRefusalsPreserveLegacyFallback(t *testing.T) {
	in, out, cancel, runErr := startModernStdioSDKFixture(t)
	for id, requested := range map[int]string{1: "2020-01-01", 2: "2099-01-01"} {
		writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":`+strconv.Itoa(id)+`,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+requested+`"}}}`)
		data := assertRPCError(t, readMCPLine(t, out), int64(id), -32022, "Unsupported protocol version")
		var detail struct {
			Supported []string `json:"supported"`
			Requested string   `json:"requested"`
		}
		if err := json.Unmarshal(data, &detail); err != nil {
			t.Fatalf("unsupported-version data did not decode: %s: %v", data, err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 2 {
			t.Fatalf("unsupported-version data has unexpected fields: %s", data)
		}
		want := []string{mcpProtocol20260728, mcpProtocol20251125, mcpProtocol20250618, mcpProtocol20250326, mcpProtocol20241105}
		if detail.Requested != requested || len(detail.Supported) != len(want) {
			t.Fatalf("unsupported-version data = %#v, requested %s supported %#v", detail, requested, want)
		}
		for i := range want {
			if detail.Supported[i] != want[i] {
				t.Fatalf("unsupported-version supported = %#v, want %#v", detail.Supported, want)
			}
		}
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":7}}}`)
	assertRPCError(t, readMCPLine(t, out), 3, -32602, "Invalid params")

	for id, capabilities := range map[int]string{30: ``, 31: `,"io.modelcontextprotocol/clientCapabilities":null`} {
		writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":`+strconv.Itoa(id)+`,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20260728+`"`+capabilities+`}}}`)
		assertRPCError(t, readMCPLine(t, out), int64(id), -32602, "")
	}

	// Legacy and versionless discover requests are left for the SDK to refuse;
	// neither refusal prevents the ordinary initialize handshake.
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":4,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20251125+`"}}}`)
	assertRPCError(t, readMCPLine(t, out), 4, -32601, "")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":5,"method":"server/discover"}`)
	assertRPCError(t, readMCPLine(t, out), 5, -32601, "")
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":6,"method":"initialize","params":{"protocolVersion":"`+mcpProtocol20241105+`","capabilities":{},"clientInfo":{"name":"fallback-client","version":"1"}}}`)
	initialized := sdkCallResults(t, readMCPLine(t, out), false, 6)[6]
	if initialized["protocolVersion"] != mcpProtocol20241105 {
		t.Fatalf("versionless probe broke legacy initialize: %#v", initialized)
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"text":"fallback works"}}}`)
	assertEchoText(t, sdkCallResults(t, readMCPLine(t, out), false, 7), 7, "fallback works")
	cancel()
	if err := awaitSignal(t, runErr, "custom SDK refusal fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("custom SDK refusal fixture ended unexpectedly: %v", err)
	}
}

// Modern protocol removals and unimplemented method families must receive
// nonfatal method-not-found replies; notifications are dropped without ending the session.
func TestMCPStdioSDKModernRemovedMethodsRefuseWithoutClosing(t *testing.T) {
	in, out, cancel, runErr := startModernStdioSDKFixture(t)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20260728+`","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	assertCompleteModernResult(t, sdkCallResults(t, readMCPLine(t, out), false, 1)[1])

	methods := []struct {
		method string
		params string
	}{
		{"ping", `{}`},
		{"initialize", `{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"removed-method-client","version":"1"}}`},
		{"logging/setLevel", `{"level":"info"}`},
		{"roots/list", `{}`},
		{"sampling/createMessage", `{}`},
		{"tasks/list", `{}`},
		{"resources/list", `{}`},
		{"resources/read", `{"uri":"file:///synthetic"}`},
		{"resources/templates/list", `{}`},
		{"prompts/list", `{}`},
		{"prompts/get", `{"name":"missing"}`},
	}
	for i, tc := range methods {
		id := i + 2
		writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":`+strconv.Itoa(id)+`,"method":"`+tc.method+`","params":`+modernizeParams(tc.params)+`}`)
		assertRPCError(t, readMCPLine(t, out), int64(id), -32601, "")
	}
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/roots/list_changed","params":{}}`)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"ignored"}}`)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20260728+`","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	listed := sdkCallResults(t, readMCPLine(t, out), false, 99)[99]
	assertCompleteModernResult(t, listed)
	if _, ok := listed["tools"]; !ok {
		t.Fatalf("session did not survive refused modern methods and notifications: %#v", listed)
	}
	cancel()
	if err := awaitSignal(t, runErr, "custom SDK method-refusal fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("custom SDK method-refusal fixture ended unexpectedly: %v", err)
	}
}

// Exercise the pinned SDK client on IOTransport streams for both modern
// discovery and forced legacy initialize, with bounded round trips.
func TestMCPStdioSDKClientConnectsModernAndForcedLegacyVersions(t *testing.T) {
	for _, version := range []string{mcpProtocol20260728, mcpProtocol20251125} {
		t.Run(version, func(t *testing.T) {
			in, out, cancelServer, runErr := startModernStdioSDKFixture(t)
			ctx, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelClient()
			client := mcp.NewClient(&mcp.Implementation{Name: "stdio-client", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
			session, err := client.Connect(ctx, &mcp.IOTransport{Reader: out, Writer: in}, &mcp.ClientSessionOptions{ProtocolVersion: version})
			if err != nil {
				t.Fatalf("SDK client connect failed: %v", err)
			}
			defer session.Close()
			initializeResult := session.InitializeResult()
			if initializeResult == nil || initializeResult.ProtocolVersion != version {
				t.Fatalf("SDK session initialize result = %#v, want protocol %s", initializeResult, version)
			}
			listing, err := session.ListTools(ctx, nil)
			if err != nil || listing == nil || len(listing.Tools) != 1 || listing.Tools[0].Name != "echo" {
				t.Fatalf("SDK ListTools = %#v, %v", listing, err)
			}
			called, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "client " + version}})
			if err != nil || called == nil || len(called.Content) != 1 {
				t.Fatalf("SDK CallTool = %#v, %v", called, err)
			}
			textContent, ok := called.Content[0].(*mcp.TextContent)
			if !ok || textContent.Text != "client "+version {
				t.Fatalf("SDK CallTool content = %#v, want echoed text for %s", called.Content[0], version)
			}
			cancelServer()
			if err := awaitSignal(t, runErr, "custom SDK fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
				t.Fatalf("custom SDK fixture ended unexpectedly: %v", err)
			}
			if err := session.Close(); err != nil {
				t.Fatalf("SDK session close failed: %v", err)
			}
		})
	}
}

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
