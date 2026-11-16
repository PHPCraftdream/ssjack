package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Regression for the 2026-11-15 drop: Claude Code probes stdio servers with
// server/discover before initialize and offers protocol 2025-11-25. The bridge
// must preserve the session while answering supported modern discovery requests.

// assertMethodNotFound checks one reply: the given ids, each carrying exactly
// the standard method-not-found error and no result.
func assertMethodNotFound(t *testing.T, line string, wantArray bool, wantIDs ...int64) {
	t.Helper()
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || (trimmed[0] == '[') != wantArray {
		t.Fatalf("refusal container mismatch: want array=%v got %q", wantArray, trimmed)
	}
	raws := []json.RawMessage{json.RawMessage(trimmed)}
	if wantArray {
		raws = nil
		if err := json.Unmarshal([]byte(trimmed), &raws); err != nil {
			t.Fatalf("refusal array did not decode: %q", trimmed)
		}
	}
	if len(raws) != len(wantIDs) {
		t.Fatalf("refusal carried %d responses, want %d: %q", len(raws), len(wantIDs), trimmed)
	}
	for i, raw := range raws {
		var envelope struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int64           `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   *struct {
				Code    int64  `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("refusal did not decode: %q", raw)
		}
		if envelope.JSONRPC != "2.0" || envelope.ID != wantIDs[i] || envelope.Result != nil || envelope.Error == nil || envelope.Error.Code != -32601 {
			t.Fatalf("refusal %d is not method-not-found for id %d: %q", i, wantIDs[i], raw)
		}
	}
}

func readRequest(t *testing.T, connection *mcpStdioConnection, method string, id any) {
	t.Helper()
	message, err := connection.Read(context.Background())
	if err != nil {
		t.Fatalf("read before %s failed: %v", method, err)
	}
	request, ok := message.(*jsonrpc.Request)
	if !ok || request.Method != method || request.ID.Raw() != id {
		t.Fatalf("connection yielded %#v, want %s with id %v", message, method, id)
	}
}

func TestMCPStdioConnectionPassesDiscoverAndDropsUnknownNotification(t *testing.T) {
	stream := strings.Join([]string{
		`{"jsonrpc":"2.0","id":7,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`,
		`{"jsonrpc":"2.0","id":8,"method":"ping"}`,
	}, "\n") + "\n"
	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{out})
	readRequest(t, connection, "server/discover", int64(7))
	if out.Len() != 0 {
		t.Fatalf("connection refused discover before the SDK could handle it: %q", out.String())
	}
	readRequest(t, connection, "ping", int64(8))
	if out.Len() != 0 {
		t.Fatalf("connection replied to an admitted request: %q", out.String())
	}
	if _, err := connection.Read(context.Background()); err != io.EOF {
		t.Fatalf("connection did not end at EOF: %v", err)
	}
}

func TestMCPStdioConnectionRefusesEveryOutsideMethod(t *testing.T) {
	for i, method := range []string{"subscriptions/listen", "resources/list", "resources/read", "prompts/list", "completion/complete", "logging/setLevel", "$/arbitrary"} {
		id := int64(100 + i)
		stream := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q}`+"\n"+`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n", id, method)
		out := bytes.NewBuffer(nil)
		connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{out})
		readRequest(t, connection, "tools/list", int64(1))
		assertMethodNotFound(t, out.String(), false, id)
	}
}

func TestMCPStdioConnectionRefusalJoinsLegacyBatchReply(t *testing.T) {
	stream := `[{"jsonrpc":"2.0","id":2,"method":"resources/list"},{"jsonrpc":"2.0","id":3,"method":"ping"}]` + "\n" +
		`[{"jsonrpc":"2.0","id":4,"method":"prompts/list"}]` + "\n" + `{"jsonrpc":"2.0","id":5,"method":"ping"}` + "\n"
	out := bytes.NewBuffer(nil)
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{out})
	readRequest(t, connection, "ping", int64(3))
	if out.Len() != 0 {
		t.Fatalf("incomplete batch emitted a partial reply: %q", out.String())
	}
	id3, _ := jsonrpc.MakeID(float64(3))
	if err := connection.Write(context.Background(), &jsonrpc.Response{ID: id3, Result: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	var batch []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &batch); err != nil || len(batch) != 2 {
		t.Fatalf("mixed batch was not answered as one two-element array: %q", out.String())
	}
	assertMethodNotFound(t, string(batch[0]), false, 2)
	if !strings.Contains(string(batch[1]), `"id":3`) || !strings.Contains(string(batch[1]), `"result":{}`) {
		t.Fatalf("batch lost the supported call's result: %q", batch[1])
	}
	out.Reset()
	readRequest(t, connection, "ping", int64(5))
	assertMethodNotFound(t, out.String(), true, 4)
}

func TestMCPStdioConnectionInboundResponseStaysFatal(t *testing.T) {
	stream := `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"
	connection := newMCPStdioTransport(io.NopCloser(strings.NewReader(stream)), nopWriteCloser{bytes.NewBuffer(nil)})
	if _, err := connection.Read(context.Background()); !errors.Is(err, errMCPStdioUnsupportedMethod) {
		t.Fatalf("inbound response was not refused: %v", err)
	}
}

func TestMCPStdioCauseNamesBridgeRefusals(t *testing.T) {
	for err, want := range map[error]string{
		errMCPStdioUnsupportedMethod:                      "unsupported-message",
		fmt.Errorf("read: %w", errMCPStdioInvalidMessage): "invalid-message",
		errMCPStdioMessageLimit:                           "stdio-limit",
		errMCPStdioMessageCountLimit:                      "stdio-limit",
		errMCPStdioConcurrentRead:                         "concurrent-read",
		io.EOF:                                            "eof",
	} {
		if got := stdioCause(err); got != want {
			t.Fatalf("stdioCause(%v) = %q, want %q", err, got, want)
		}
	}
	if got := stdioCause(nil); got != "none" {
		t.Fatalf("stdioCause(nil) = %q", got)
	}
}

// Raw legacy initialize requests remain supported for every initialize-era
// protocol version. Unknown versions fall back to the newest legacy version;
// discovery is exercised separately because a modern discover establishes
// request-scoped state and must not be followed by initialize.
func TestMCPStdioSDKLegacyInitializeNegotiatesVersions(t *testing.T) {
	for _, tc := range []struct{ offered, want string }{
		{mcpProtocol20241105, mcpProtocol20241105},
		{mcpProtocol20250326, mcpProtocol20250326},
		{mcpProtocol20250618, mcpProtocol20250618},
		{mcpProtocol20251125, mcpProtocol20251125},
		{mcpProtocol20260728, mcpProtocol20251125},
		{"2020-01-01", mcpProtocol20251125},
		{"2099-01-01", mcpProtocol20251125},
	} {
		t.Run(tc.offered, func(t *testing.T) {
			in, out, cancel, runErr := startStdioSDKFixture(t, "stdio-legacy-fixture")
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"`+tc.offered+`","capabilities":{"roots":{}},"clientInfo":{"name":"legacy-client","version":"1"}}}`)
			initialized := sdkCallResults(t, readMCPLine(t, out), false, 2)
			if initialized[2]["protocolVersion"] != tc.want {
				t.Fatalf("offered %s negotiated %v, want %s", tc.offered, initialized[2]["protocolVersion"], tc.want)
			}
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
			writeMCPFrame(t, in, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
			if _, ok := sdkCallResults(t, readMCPLine(t, out), false, 3)[3]["tools"]; !ok {
				t.Fatal("tools/list after initialize carried no tools field")
			}
			cancel()
			if err := awaitSignal(t, runErr, "owned server run did not join"); !errors.Is(err, context.Canceled) {
				t.Fatalf("session did not survive until the orderly cancellation: %v", err)
			}
		})
	}
}

// The transport's protocol surface is a fixed five-version list, newest first.
func TestBridgeDeclaresExactSDKProtocolVersionSurface(t *testing.T) {
	want := []string{mcpProtocol20260728, mcpProtocol20251125, mcpProtocol20250618, mcpProtocol20250326, mcpProtocol20241105}
	got := supportedMCPProtocols()
	if !slices.Equal(got, want) {
		t.Fatalf("supported MCP versions = %v, want exactly %v", got, want)
	}
	if sdk := mcp.SupportedProtocolVersions(); !slices.Equal(sdk, want) {
		t.Fatalf("pinned SDK versions = %v, want exactly %v", sdk, want)
	}
	for _, version := range want {
		if !supportedMCPProtocol(version) {
			t.Errorf("bridge does not admit advertised protocol version %s", version)
		}
	}
	if negotiatedMCPVersion(mcpProtocol20260728) != mcpProtocol20251125 || negotiatedMCPVersion("") != mcpProtocol20251125 || negotiatedMCPVersion("2020-01-01") != mcpProtocol20251125 {
		t.Error("stateless, empty, or unknown version did not negotiate to the latest initialize-era version")
	}
}
