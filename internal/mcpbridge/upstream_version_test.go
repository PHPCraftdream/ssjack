package mcpbridge

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// pinnedHandshakeConnection answers the first upstream call with a valid
// initialize result and records that call; it never answers anything else.
type pinnedHandshakeConnection struct {
	once   sync.Once
	first  chan *jsonrpc.Request
	reqs   chan *jsonrpc.Request
	closed chan struct{}
	stop   sync.Once
	served bool
}

func newPinnedHandshakeConnection() *pinnedHandshakeConnection {
	return &pinnedHandshakeConnection{first: make(chan *jsonrpc.Request, 1), reqs: make(chan *jsonrpc.Request, 1), closed: make(chan struct{})}
}

func (c *pinnedHandshakeConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	if !c.served {
		select {
		case request := <-c.reqs:
			c.served = true
			body, _ := json.Marshal(mcp.InitializeResult{ProtocolVersion: upstreamProtocolVersion, Capabilities: &mcp.ServerCapabilities{}, ServerInfo: &mcp.Implementation{Name: "fixture", Version: "1"}})
			return &jsonrpc.Response{ID: request.ID, Result: body}, nil
		case <-c.closed:
			return nil, io.EOF
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case <-c.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *pinnedHandshakeConnection) Write(_ context.Context, m jsonrpc.Message) error {
	if request, ok := m.(*jsonrpc.Request); ok && request.ID.IsValid() {
		c.once.Do(func() { c.first <- request; c.reqs <- request })
	}
	return nil
}

func (c *pinnedHandshakeConnection) Close() error {
	c.stop.Do(func() { close(c.closed) })
	return nil
}

func (*pinnedHandshakeConnection) SessionID() string { return "pinned" }

// Regression for the go-sdk v1.8.0 bump: its client opens with server/discover
// and offers 2026-07-28, which the one-shot upstream exchange refuses. The
// upstream handshake must stay an initialize at the pinned 2025-06-18.
func TestUpstreamHandshakeOpensWithPinnedInitialize(t *testing.T) {
	conn := newPinnedHandshakeConnection()
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	exited := make(chan struct{})
	t.Cleanup(func() {
		_ = conn.Close()
		joinExited(t, exited, "describe worker did not exit")
	})
	describeAsync(t, r, context.Background(), exited, result)
	first := awaitSignal(t, conn.first, "no upstream call was written")
	if first.Method != "initialize" {
		t.Fatalf("upstream handshake opened with %q, want initialize", first.Method)
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(first.Params, &params); err != nil || params.ProtocolVersion != "2025-06-18" {
		t.Fatalf("upstream handshake offered %q, want the pinned 2025-06-18 (%v)", params.ProtocolVersion, err)
	}
}
