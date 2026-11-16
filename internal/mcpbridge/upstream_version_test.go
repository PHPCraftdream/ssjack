package mcpbridge

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// eraConnection scripts one upstream peer's JSON-RPC responses in order and
// records every written request so tests can pin the handshake era.
type eraConnection struct {
	started chan struct{}
	closed  chan struct{}
	written chan *jsonrpc.Request
	seenMu  sync.Mutex
	seen    []*jsonrpc.Request
	script  []func(req *jsonrpc.Request) jsonrpc.Message
	served  int // only the SDK's single reader goroutine touches this
	once    sync.Once
}

func newEraConnection(script ...func(req *jsonrpc.Request) jsonrpc.Message) *eraConnection {
	return &eraConnection{started: make(chan struct{}), closed: make(chan struct{}), written: make(chan *jsonrpc.Request, 16), script: script}
}

func (c *eraConnection) Write(_ context.Context, m jsonrpc.Message) error {
	request, _ := m.(*jsonrpc.Request)
	if request == nil {
		return nil
	}
	c.seenMu.Lock()
	c.seen = append(c.seen, request)
	c.seenMu.Unlock()
	select {
	case c.written <- request:
	default:
		return io.ErrShortWrite
	}
	return nil
}

func (c *eraConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-c.started:
	default:
		close(c.started)
	}
	for {
		var request *jsonrpc.Request
		select {
		case request = <-c.written:
		case <-c.closed:
			return nil, io.EOF
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if !request.ID.IsValid() {
			continue // notifications need no scripted reply
		}
		if c.served >= len(c.script) {
			select {
			case <-c.closed:
				return nil, io.EOF
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		response := c.script[c.served](request)
		c.served++
		return response, nil
	}
}

func (c *eraConnection) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (*eraConnection) SessionID() string { return "" }

func resultFor(req *jsonrpc.Request, result string) jsonrpc.Message {
	return &jsonrpc.Response{ID: req.ID, Result: json.RawMessage(result)}
}

func discoverOK(req *jsonrpc.Request) jsonrpc.Message {
	return resultFor(req, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`)
}

// -32022 is the 2026-07-28 UnsupportedProtocolVersion code the pinned SDK
// negotiates on; the SDK's public jsonrpc package does not export it.
func discoverUnsupported(req *jsonrpc.Request) jsonrpc.Message {
	return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: -32022, Message: "unsupported protocol version", Data: json.RawMessage(`{"supported":["2026-07-28"],"requested":"2026-07-28"}`)}}
}

func discoverMethodNotFound(req *jsonrpc.Request) jsonrpc.Message {
	return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"}}
}

func initializeOK(version string) func(req *jsonrpc.Request) jsonrpc.Message {
	body, _ := json.Marshal(mcp.InitializeResult{ProtocolVersion: version, Capabilities: &mcp.ServerCapabilities{}, ServerInfo: &mcp.Implementation{Name: "fixture", Version: "1"}})
	return func(req *jsonrpc.Request) jsonrpc.Message { return resultFor(req, string(body)) }
}

func toolsOK(req *jsonrpc.Request) jsonrpc.Message {
	return resultFor(req, `{"tools":[{"name":"echo","description":"echo tool","inputSchema":{"type":"object"}}]}`)
}

func describeOverEra(t *testing.T, conn *eraConnection) wire.Reply {
	t.Helper()
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	exited := make(chan struct{})
	t.Cleanup(func() {
		_ = conn.Close()
		joinExited(t, exited, "describe worker did not exit")
	})
	describeAsync(t, r, context.Background(), exited, result)
	return awaitSignal(t, result, "describe did not return")
}

func seenRequests(conn *eraConnection) []*jsonrpc.Request {
	conn.seenMu.Lock()
	defer conn.seenMu.Unlock()
	return append([]*jsonrpc.Request(nil), conn.seen...)
}

func metaVersion(t *testing.T, req *jsonrpc.Request) string {
	t.Helper()
	var params struct {
		Meta struct {
			ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	}
	if json.Unmarshal(req.Params, &params) != nil {
		return ""
	}
	return params.Meta.ProtocolVersion
}

func toolsOf(t *testing.T, reply wire.Reply) []string {
	t.Helper()
	var envelope InventoryEnvelope
	if wire.Decode(reply.Data, &envelope) != nil {
		t.Fatal("inventory envelope was not decodable")
	}
	var out InventoryOutput
	if json.Unmarshal([]byte(envelope.Inventory), &out) != nil {
		t.Fatal("inventory was not decodable")
	}
	names := make([]string, 0, len(out.Tools))
	for _, tool := range out.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func hasEchoTool(names []string) bool {
	for _, name := range names {
		if strings.HasSuffix(name, "echo") {
			return true
		}
	}
	return false
}

// TestUpstreamHandshakeNegotiatesStatelessPeer proves acceptance 1: a peer
// that supports only 2026-07-28 is discovered probed and served through
// tools/list without any initialize request.
func TestUpstreamHandshakeNegotiatesStatelessPeer(t *testing.T) {
	conn := newEraConnection(discoverOK, toolsOK)
	reply := describeOverEra(t, conn)
	if !reply.OK {
		t.Fatalf("stateless peer describe failed: %s", reply.Error)
	}
	if !hasEchoTool(toolsOf(t, reply)) {
		t.Fatal("stateless inventory was missing the echo tool")
	}
	seen := seenRequests(conn)
	if len(seen) != 2 {
		t.Fatalf("stateless handshake wrote %d requests, want discover, tools/list", len(seen))
	}
	if seen[0].Method != "server/discover" {
		t.Fatalf("upstream handshake opened with %q, want the stateless server/discover probe", seen[0].Method)
	}
	if metaVersion(t, seen[0]) != modernProtocolVersion {
		t.Fatalf("probe offered %q, want %q", metaVersion(t, seen[0]), modernProtocolVersion)
	}
	for _, request := range seen {
		if request.Method == "initialize" {
			t.Fatal("stateless peer received an initialize request")
		}
	}
}

// TestUpstreamHandshakeFallsBackToPinnedInitializeEra proves acceptance 2: a
// discover refusal drives exactly one pinned initialize-era handshake on the
// same connection, offering upstreamProtocolVersion.
func TestUpstreamHandshakeFallsBackToPinnedInitializeEra(t *testing.T) {
	conn := newEraConnection(discoverMethodNotFound, initializeOK(upstreamProtocolVersion), toolsOK)
	reply := describeOverEra(t, conn)
	if !reply.OK {
		t.Fatalf("initialize-era peer describe failed: %s", reply.Error)
	}
	if !hasEchoTool(toolsOf(t, reply)) {
		t.Fatal("initialize-era inventory was missing the echo tool")
	}
	seen := seenRequests(conn)
	if len(seen) != 4 {
		t.Fatalf("fallback handshake wrote %d requests, want discover refusal, initialize, notifications/initialized, tools/list", len(seen))
	}
	discoveries, initializations := 0, 0
	var initialize *jsonrpc.Request
	for _, request := range seen {
		switch request.Method {
		case "server/discover":
			discoveries++
		case "initialize":
			initializations++
			initialize = request
		}
	}
	if discoveries != 1 || initializations != 1 || initialize == nil {
		t.Fatalf("fallback wrote discovers=%d initializes=%d, want one probe refusal then one initialize", discoveries, initializations)
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(initialize.Params, &params); err != nil || params.ProtocolVersion != upstreamProtocolVersion {
		t.Fatalf("fallback initialize offered %q (%v), want the pinned %q", params.ProtocolVersion, err, upstreamProtocolVersion)
	}
}

// TestUpstreamHandshakeRecoversFromUnsupportedProtocolVersion proves
// acceptance 3: a -32022 discover answer with supported versions drives one
// bounded stateless retry, never a loop and never an initialize.
func TestUpstreamHandshakeRecoversFromUnsupportedProtocolVersion(t *testing.T) {
	conn := newEraConnection(discoverUnsupported, discoverOK, toolsOK)
	reply := describeOverEra(t, conn)
	if !reply.OK {
		t.Fatalf("unsupported-version peer describe failed: %s", reply.Error)
	}
	if !hasEchoTool(toolsOf(t, reply)) {
		t.Fatal("retried inventory was missing the echo tool")
	}
	discoveries, initializations := 0, 0
	for _, request := range seenRequests(conn) {
		switch request.Method {
		case "server/discover":
			discoveries++
		case "initialize":
			initializations++
		}
	}
	if discoveries != 2 || initializations != 0 {
		t.Fatalf("retry wrote discovers=%d initializes=%d, want two discovers, no initialize, no loop", discoveries, initializations)
	}
	if got := len(seenRequests(conn)); got != 3 {
		t.Fatalf("retry handshake wrote %d requests, want discover, retry discover, tools/list", got)
	}
}
