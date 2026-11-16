package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
