package remotemcp

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
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
	ctx, cancel := context.WithCancel(context.Background())
	configureMCPStdioServer(server, ctx)
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

func assertModernCacheFields(t *testing.T, result map[string]any, wantTTLMs float64, wantScope string) {
	t.Helper()
	if ttl, ok := result["ttlMs"].(float64); !ok || ttl != wantTTLMs {
		t.Fatalf("modern result ttlMs = %#v, want %v", result["ttlMs"], wantTTLMs)
	}
	if result["cacheScope"] != wantScope {
		t.Fatalf("modern result cacheScope = %v, want %s", result["cacheScope"], wantScope)
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
	assertModernCacheFields(t, discovered, 0, "public")
	cancel()
	if err := awaitSignal(t, runErr, "custom SDK discover fixture did not stop after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("custom SDK discover fixture ended unexpectedly: %v", err)
	}

	// A fresh fixture ensures the stateless calls are not inheriting state from discover.
	in, out, cancel, runErr = startModernStdioSDKFixture(t)
	writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+mcpProtocol20260728+`","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	listed := sdkCallResults(t, readMCPLine(t, out), false, 2)[2]
	assertCompleteModernResult(t, listed)
	assertModernCacheFields(t, listed, float64(remoteMCPToolListCacheTTLMs), remoteMCPToolListCacheScope)
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

// mcpSubscriptionsFixture is one owned SDK server with a tool capability, so
// modern toolsListChanged subscriptions are accepted.
type mcpSubscriptionsFixture struct {
	in      io.WriteCloser
	out     io.ReadCloser
	cancel  context.CancelFunc
	runErr  <-chan error
	runDone <-chan struct{}
	server  *mcp.Server
	listens chan context.Context
}

// newMCPSubscriptionsFixture owns a configured SDK server with a tool
// capability so modern toolsListChanged subscriptions are accepted.
func newMCPSubscriptionsFixture(t *testing.T) *mcpSubscriptionsFixture {
	t.Helper()
	serverIn, clientIn := io.Pipe()
	clientOut, serverOut := io.Pipe()
	server := mcp.NewServer(&mcp.Implementation{Name: "subscriptions-fixture", Version: "1"}, nil)
	// Registered before configureMCPStdioServer, so the configure middleware is
	// outermost and this observer receives the context the listen runs with.
	listens := make(chan context.Context, 4)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "subscriptions/listen" {
				select {
				case listens <- ctx:
				default:
				}
			}
			return next(ctx, method, req)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	configureMCPStdioServer(server, ctx)
	server.AddTool(&mcp.Tool{Name: "fixture_tool", Description: "subscription capability fixture", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
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
	return &mcpSubscriptionsFixture{in: clientIn, out: clientOut, cancel: cancel, runErr: runErr, runDone: runDone, server: server, listens: listens}
}

func TestMCPStdioModernSubscriptionsListenLifecycle(t *testing.T) {
	fixture := newMCPSubscriptionsFixture(t)

	// The acknowledgement is a notification on the listen stream, not the
	// listen RPC's result. Its metadata correlates it to the listen request.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, fixture.out), 1)

	// A normal modern call can complete while the subscription remains parked.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, fixture.out), false, 2)[2]
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
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, fixture.out), 3, -32602, "subscriptions/listen already active")

	// The SDK's listen handler returns a complete result after the peer
	// cancellation notification. Observing it proves the middleware released
	// its one active slot before the next listen.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"test",`+remoteMCPSubscriptionsTestMeta+`}}`)
	finished := sdkCallResults(t, readMCPLine(t, fixture.out), false, 1)[1]
	assertMCPSubscriptionsListenResult(t, finished, 1)

	// A new listen can now occupy the released slot.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":4,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, fixture.out), 4)

	// Run cancellation can close the transport before a response is written.
	// The protocol permits that abrupt shutdown without a listen result; if the
	// SDK wins the race and writes the complete result first, validate it too.
	// Start the shutdown reader before cancellation: SDK Close may race a
	// completed result with transport closure, and an accepted pipe write must
	// not block Run while this test waits for the server goroutine.
	shutdownRead, shutdownReadExited := startMCPSubscriptionsShutdownRead(fixture.out)
	t.Cleanup(func() {
		select {
		case <-shutdownReadExited:
			return
		default:
		}
		_ = fixture.out.Close()
		select {
		case <-shutdownReadExited:
		case <-time.After(time.Second):
			t.Error("owned shutdown response reader did not exit after its reader was released")
		}
	})
	fixture.cancel()
	if err := awaitSignal(t, fixture.runErr, "configured SDK server did not return after cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("configured SDK server returned an unexpected shutdown error: %v", err)
	}
	awaitSignal(t, fixture.runDone, "configured SDK server completion was not joined")
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
	assertMCPSubscriptionsReaderEOF(t, fixture.out)
}

func TestMCPStdioModernSubscriptionsWithNoAcceptedNotifications(t *testing.T) {
	fixture := newMCPSubscriptionsFixture(t)

	// The tools-only fixture advertises neither resources nor prompts, so none
	// of these requested subscriptions is accepted.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":20,"method":"subscriptions/listen","params":{"notifications":{"resourcesListChanged":true,"promptsListChanged":true,"resourceSubscriptions":["file:///not-advertised"]},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsEmptyAck(t, readMCPLine(t, fixture.out), 20)
	completed := sdkCallResults(t, readMCPLine(t, fixture.out), false, 20)[20]
	assertMCPSubscriptionsListenResult(t, completed, 20)

	// The empty listen must finish without inventing notifications and leave
	// ordinary requests usable on the same connection.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":21,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, fixture.out), false, 21)[21]
	assertMCPSubscriptionsModernResult(t, listed, "tools/list")
	tools, ok := listed["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools/list after an empty subscription returned unexpected tools: %#v", listed["tools"])
	}
	fixture.cancel()
	if err := awaitSignal(t, fixture.runErr, "configured SDK server did not return after cancellation of the empty subscription fixture"); !errors.Is(err, context.Canceled) {
		t.Fatalf("configured SDK server returned an unexpected shutdown error after the empty subscription: %v", err)
	}
	awaitSignal(t, fixture.runDone, "empty subscription SDK server completion was not joined")
	// Any unsolicited notification queued after tools/list is data, not EOF.
	assertMCPSubscriptionsReaderEOF(t, fixture.out)
}

// An accepted listen holds the single admission slot until the client ends it:
// the bridge imposes no deadline of its own, so nothing but cancellation,
// transport close or shutdown can end it early.
func TestMCPStdioSubscriptionsListenStaysOpenUntilClientCancel(t *testing.T) {
	flakediag.Begin(t)
	flakediag.OnFailure(t, func() string { return flakediag.GoroutineDump(0) })
	fixture := newMCPSubscriptionsFixture(t)

	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":40,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, fixture.out), 40)
	listenCtx := awaitSignal(t, fixture.listens, "listen middleware did not observe the admitted listen")
	if deadline, ok := listenCtx.Deadline(); ok {
		t.Fatalf("accepted listen carried a self-imposed deadline (%s remaining), want the session lifetime", time.Until(deadline))
	}

	// Ordinary requests still complete while the listen stays parked, and the
	// only reply line is the tools/list one: no listen result was written.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":41,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, fixture.out), false, 41)[41]
	assertMCPSubscriptionsModernResult(t, listed, "tools/list")

	// The listen is still the session's one active listen and its context is
	// still live: the bridge did not end it while the connection stayed open.
	if err := listenCtx.Err(); err != nil {
		t.Fatalf("listen context ended before the client cancelled it: %v", err)
	}
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":42,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, fixture.out), 42, -32602, "subscriptions/listen already active")

	// Only the genuine client cancellation releases the slot.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":40,"reason":"test",`+remoteMCPSubscriptionsTestMeta+`}}`)
	finished := sdkCallResults(t, readMCPLine(t, fixture.out), false, 40)[40]
	assertMCPSubscriptionsListenResult(t, finished, 40)
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":43,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, fixture.out), 43)
}

// A tool registered after the client's first tools/list reaches the open listen
// as tools/list_changed, and the refreshed list is in stable name order.
func TestMCPStdioSubscriptionsListenDeliversLateToolRegistration(t *testing.T) {
	flakediag.Begin(t)
	flakediag.OnFailure(t, func() string { return flakediag.GoroutineDump(0) })
	fixture := newMCPSubscriptionsFixture(t)

	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":50,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, fixture.out), 50)

	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":51,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	listed := sdkCallResults(t, readMCPLine(t, fixture.out), false, 51)[51]
	assertMCPSubscriptionsModernResult(t, listed, "tools/list")
	if names := subscriptionToolNames(t, listed); len(names) != 1 || names[0] != "fixture_tool" {
		t.Fatalf("tools/list before the late registration = %v, want the fixture tool only", names)
	}
	assertModernCacheFields(t, listed, float64(remoteMCPToolListCacheTTLMs), remoteMCPToolListCacheScope)

	// The registry change notification is asynchronous in the SDK, so it may
	// arrive after the AddTool call that caused it.
	fixture.server.AddTool(&mcp.Tool{Name: "affix_late_tool", Description: "late registration fixture", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	assertMCPSubscriptionsToolListChanged(t, readMCPLine(t, fixture.out), 50)

	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":52,"method":"tools/list","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	refreshed := sdkCallResults(t, readMCPLine(t, fixture.out), false, 52)[52]
	assertMCPSubscriptionsModernResult(t, refreshed, "tools/list")
	if names := subscriptionToolNames(t, refreshed); len(names) != 2 || names[0] != "affix_late_tool" || names[1] != "fixture_tool" {
		t.Fatalf("tools/list after the late registration = %v, want stable name order", names)
	}
}

// mcpSubscriptionsSession is one connected SDK session whose bridge shutdown is a
// separate signal, so a test can end the bridge lifetime without closing the
// session or cancelling the client's own context.
type mcpSubscriptionsSession struct {
	in       io.WriteCloser
	out      io.ReadCloser
	shutdown context.CancelFunc
	listens  chan context.Context
}

// newMCPSubscriptionsSession connects a configured SDK server over owned pipes.
// The observation middleware is registered before configureMCPStdioServer, so the
// configure middleware is outermost and this observer receives the context the
// listen actually runs with.
func newMCPSubscriptionsSession(t *testing.T) *mcpSubscriptionsSession {
	t.Helper()
	serverIn, clientIn := io.Pipe()
	clientOut, serverOut := io.Pipe()
	server := mcp.NewServer(&mcp.Implementation{Name: "subscriptions-fixture", Version: "1"}, nil)
	listens := make(chan context.Context, 4)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "subscriptions/listen" {
				select {
				case listens <- ctx:
				default:
				}
			}
			return next(ctx, method, req)
		}
	})
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	configureMCPStdioServer(server, shutdownCtx)
	server.AddTool(&mcp.Tool{Name: "fixture_tool", Description: "subscription capability fixture", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	sessionCtx, endSession := context.WithCancel(context.Background())
	session, err := server.Connect(sessionCtx, newMCPStdioTransport(serverIn, serverOut), nil)
	if err != nil {
		t.Fatalf("subscriptions fixture session did not connect: %v", err)
	}
	t.Cleanup(func() {
		endSession()
		shutdown()
		// Release the client reader first: a completion frame the test did not read
		// must not hold the session drain.
		_ = clientIn.Close()
		_ = clientOut.Close()
		closed := make(chan struct{})
		go func() {
			_ = session.Close()
			close(closed)
		}()
		joinExited(t, closed, "subscriptions fixture session did not close")
		_ = serverIn.Close()
		_ = serverOut.Close()
	})
	return &mcpSubscriptionsSession{in: clientIn, out: clientOut, shutdown: shutdown, listens: listens}
}

// A shutdown must unpark an admitted listen by itself: the SDK cancels a parked
// listen only after it recorded the request ID, and it releases the request for
// asynchronous handling before that record, so a close that starts in between has
// nothing else to end the handler. The assertion is the listen's own context, so
// it does not depend on any frame the server writes afterwards.
func TestMCPStdioSubscriptionsListenShutdownUnparksWithoutClientCancel(t *testing.T) {
	flakediag.Begin(t)
	flakediag.OnFailure(t, func() string { return flakediag.GoroutineDump(0) })
	fixture := newMCPSubscriptionsSession(t)

	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":60,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsAck(t, readMCPLine(t, fixture.out), 60)
	listenCtx := awaitSignal(t, fixture.listens, "listen middleware did not observe the admitted listen")

	// Only the bridge's own shutdown, with the client still attached and silent.
	fixture.shutdown()
	awaitSignal(t, listenCtx.Done(), "shutdown left the admitted listen parked")
}

// The SDK records the listen ID inside its own request handling, so the instant
// between its asynchronous release and that record has no injectable seam from
// outside the SDK. What follows from it can be covered deterministically: a
// listen admitted after the bridge lifetime already ended must not park.
func TestMCPStdioSubscriptionsListenAdmittedAfterShutdownCannotPark(t *testing.T) {
	flakediag.Begin(t)
	flakediag.OnFailure(t, func() string { return flakediag.GoroutineDump(0) })
	fixture := newMCPSubscriptionsSession(t)

	// The bridge lifetime ends before the request exists, so the request is
	// dispatched into a shutdown that has already begun.
	fixture.shutdown()
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":70,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},`+remoteMCPSubscriptionsTestMeta+`}}`)
	listenCtx := awaitSignal(t, fixture.listens, "listen middleware did not observe the listen admitted after shutdown")
	awaitSignal(t, listenCtx.Done(), "listen admitted after shutdown ran on a live context and would park")
}

func subscriptionToolNames(t *testing.T, result map[string]any) []string {
	t.Helper()
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("tools/list result carried no tool array: %#v", result["tools"])
	}
	names := make([]string, 0, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("tools/list entry was not an object: %#v", entry)
		}
		name, ok := tool["name"].(string)
		if !ok {
			t.Fatalf("tools/list entry carried no name: %#v", tool)
		}
		names = append(names, name)
	}
	return names
}

func assertMCPSubscriptionsToolListChanged(t *testing.T, line string, listenID int64) {
	t.Helper()
	message, err := jsonrpc.DecodeMessage([]byte(strings.TrimSpace(line)))
	if err != nil {
		t.Fatalf("tools/list_changed notification did not decode: %v", err)
	}
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.ID.IsValid() || request.Method != "notifications/tools/list_changed" {
		t.Fatalf("late tool registration did not notify the open listen: %#v", message)
	}
	var params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("tools/list_changed parameters did not decode: %v", err)
	}
	var gotID int64
	if raw, ok := params.Meta[mcp.MetaKeySubscriptionID]; !ok || json.Unmarshal(raw, &gotID) != nil || gotID != listenID {
		t.Fatalf("tools/list_changed subscriptionId did not match listen request %d: %s", listenID, request.Params)
	}
	if len(params.Meta) != 1 {
		t.Fatalf("tools/list_changed metadata carried fields beyond subscriptionId: %s", request.Params)
	}
}

func TestMCPStdioSubscriptionsListenRequiresModernNotifications(t *testing.T) {
	fixture := newMCPSubscriptionsFixture(t)

	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":10,"method":"subscriptions/listen","params":{`+remoteMCPSubscriptionsTestMeta+`}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, fixture.out), 10, -32602, "")

	// subscriptions/listen exists only in the modern per-request protocol.
	writeMCPFrame(t, fixture.in, `{"jsonrpc":"2.0","id":11,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`)
	assertMCPSubscriptionsError(t, readMCPLine(t, fixture.out), 11, -32601, "method not found")
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
