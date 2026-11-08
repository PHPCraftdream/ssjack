package mcpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const secretLiteral = "synthetic-bridge-secret"

type testHandle struct {
	takes      atomic.Int32
	transport  mcp.Transport
	beforeTake func() error
}

func (h *testHandle) TakeTransport() (mcp.Transport, error) {
	if h.takes.Add(1) != 1 {
		return nil, errors.New("transport already taken")
	}
	if h.beforeTake != nil {
		if err := h.beforeTake(); err != nil {
			return nil, err
		}
	}
	return h.transport, nil
}

type testTransport struct{ conn mcp.Connection }

func (t *testTransport) Connect(context.Context) (mcp.Connection, error) { return t.conn, nil }

type testConnection struct {
	started  chan struct{}
	closed   chan struct{}
	ids      chan jsonrpc.ID
	request  chan struct{}
	response chan struct{}
	version  string
	once     atomic.Bool
}

func newTestConnection(version string) *testConnection {
	return &testConnection{started: make(chan struct{}), closed: make(chan struct{}), ids: make(chan jsonrpc.ID, 1), request: make(chan struct{}), response: make(chan struct{}), version: version}
}
func (c *testConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-c.started:
	default:
		close(c.started)
	}
	if c.version != "" {
		select {
		case id := <-c.ids:
			close(c.request)
			<-c.response
			body, _ := json.Marshal(mcp.InitializeResult{ProtocolVersion: c.version, Capabilities: &mcp.ServerCapabilities{}, ServerInfo: &mcp.Implementation{Name: "fixture", Version: "1"}})
			return &jsonrpc.Response{ID: id, Result: body}, nil
		case <-c.closed:
			return nil, errors.New("closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case <-c.closed:
		return nil, errors.New("closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *testConnection) Write(_ context.Context, m jsonrpc.Message) error {
	if r, ok := m.(*jsonrpc.Request); ok && r.ID.IsValid() {
		select {
		case c.ids <- r.ID:
		default:
		}
	}
	return nil
}
func (c *testConnection) Close() error {
	if c.once.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return nil
}
func (*testConnection) SessionID() string { return "test" }

func testRuntime(t *testing.T, parent context.Context, h UpstreamHandle, closeLaunch func(context.Context) error) *Runtime {
	t.Helper()
	guard, err := outputguard.New([][]byte{[]byte(secretLiteral)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(parent, []UpstreamHandle{h}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return r
}
func closeBounded(t *testing.T, r *Runtime, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return r.Close(ctx)
}
func describeRequest(t *testing.T, r *Runtime) wire.Reply {
	t.Helper()
	data, _ := wire.Encode(ordinalInput{})
	reply, ok := r.Handle(context.Background(), wire.Request{Operation: OpDescribe, Data: data})
	if !ok {
		t.Fatal("Describe not handled")
	}
	return reply
}

func TestMissingInitializationCanceledOperationDoesNotTakeTransport(t *testing.T) {
	conn := newTestConnection("")
	h := &testHandle{transport: &testTransport{conn}}
	r := testRuntime(t, context.Background(), h, func(context.Context) error { return nil })
	op, cancel := context.WithCancel(context.Background())
	cancel()
	data, _ := wire.Encode(ordinalInput{})
	reply, ok := r.Handle(op, wire.Request{Operation: OpDescribe, Data: data})
	if !ok || reply.OK || h.takes.Load() != 0 {
		t.Fatalf("canceled operation consumed transport: %+v takes=%d", reply, h.takes.Load())
	}
}

func TestCanceledInitializationClosesAndJoinsConnection(t *testing.T) {
	conn := newTestConnection("")
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil })
	data, _ := wire.Encode(ordinalInput{})
	op, cancel := context.WithCancel(context.Background())
	result := make(chan wire.Reply, 1)
	go func() { reply, _ := r.Handle(op, wire.Request{Operation: OpDescribe, Data: data}); result <- reply }()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("Connect read did not start")
	}
	cancel()
	select {
	case reply := <-result:
		if reply.OK {
			t.Fatalf("canceled initialization succeeded: %+v", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("operation did not return")
	}
	if err := closeBounded(t, r, time.Second); err != nil {
		t.Fatal(err)
	}
	if !conn.once.Load() {
		t.Fatal("captured connection leaked")
	}
}

func TestLateHandshakeResponseCannotInstallSessionAfterClose(t *testing.T) {
	conn := newTestConnection("2025-06-18")
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil })
	data, err := wire.Encode(ordinalInput{})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan wire.Reply, 1)
	go func() {
		reply, _ := r.Handle(context.Background(), wire.Request{Operation: OpDescribe, Data: data})
		result <- reply
	}()
	select {
	case <-conn.request:
	case <-time.After(time.Second):
		t.Fatal("initialize request was not written")
	}
	closed := make(chan error, 1)
	go func() { closed <- closeBounded(t, r, time.Second) }()
	select {
	case <-r.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the pending handshake")
	}
	close(conn.response)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join handshake")
	}
	select {
	case reply := <-result:
		if reply.OK {
			t.Fatalf("late handshake succeeded: %+v", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("operation outlived Close")
	}
	s := r.slots[0]
	s.mu.Lock()
	session, failed, done := s.session, s.failed, s.closeDone
	s.mu.Unlock()
	if !failed {
		t.Fatalf("late handshake was not marked failed: session=%v failed=%v", session != nil, failed)
	}
	if !conn.once.Load() {
		t.Fatal("late handshake connection did not close")
	}
	select {
	case <-done:
	default:
		t.Fatal("binding cleanup not joined")
	}
}

func TestUnknownProtocolFailureClosesCapturedConnection(t *testing.T) {
	conn := newTestConnection("unsupported-version")
	close(conn.response)
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil })
	if reply := describeRequest(t, r); reply.OK {
		t.Fatalf("unsupported version accepted: %+v", reply)
	}
	if err := closeBounded(t, r, time.Second); err != nil {
		t.Fatalf("close after unsupported handshake: %v", err)
	}
	if !conn.once.Load() {
		t.Fatal("unsupported handshake leaked connection")
	}
}
