package mcpruntimetest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// fakeHandle counts transport takes and hands out one fake transport.
type fakeHandle struct {
	takes     atomic.Int32
	transport mcp.Transport
}

func (h *fakeHandle) TakeTransport() (mcp.Transport, error) {
	if h.takes.Add(1) != 1 {
		return nil, errors.New("transport already taken")
	}
	return h.transport, nil
}

// fakeTransport connects to one prebuilt fake connection.
type fakeTransport struct{ conn mcp.Connection }

func (t *fakeTransport) Connect(context.Context) (mcp.Connection, error) { return t.conn, nil }

// fakeConnection is a hand-driven JSON-RPC connection: the first Read marks
// started, a configured version echoes one initialize reply after response is
// closed, and Close is single-shot.
type fakeConnection struct {
	started  chan struct{}
	closed   chan struct{}
	ids      chan jsonrpc.ID
	response chan struct{}
	version  string
	once     atomic.Bool
}

func newFakeConnection(version string) *fakeConnection {
	return &fakeConnection{started: make(chan struct{}), closed: make(chan struct{}), ids: make(chan jsonrpc.ID, 1), response: make(chan struct{}), version: version}
}

func (c *fakeConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-c.started:
	default:
		close(c.started)
	}
	if c.version != "" {
		select {
		case id := <-c.ids:
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

func (c *fakeConnection) Write(_ context.Context, m jsonrpc.Message) error {
	if r, ok := m.(*jsonrpc.Request); ok && r.ID.IsValid() {
		select {
		case c.ids <- r.ID:
		default:
		}
	}
	return nil
}

func (c *fakeConnection) Close() error {
	if c.once.CompareAndSwap(false, true) {
		close(c.closed)
	}
	return nil
}

func (*fakeConnection) SessionID() string { return "test" }

type diagnosticTestTransport struct {
	connect func(context.Context) (mcp.Connection, error)
}

func (t *diagnosticTestTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	return t.connect(ctx)
}

type diagnosticTestConnection struct {
	read      func(context.Context) (jsonrpc.Message, error)
	write     func(context.Context, jsonrpc.Message) error
	close     func() error
	sessionID string
}

func (c *diagnosticTestConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	return c.read(ctx)
}
func (c *diagnosticTestConnection) Write(ctx context.Context, message jsonrpc.Message) error {
	return c.write(ctx, message)
}
func (c *diagnosticTestConnection) Close() error      { return c.close() }
func (c *diagnosticTestConnection) SessionID() string { return c.sessionID }

type diagnosticResult struct {
	message jsonrpc.Message
	err     error
}

type diagnosticCall struct {
	release chan struct{}
	done    chan struct{}
	result  chan diagnosticResult
	once    sync.Once
}

func startDiagnosticCall(t *testing.T, run func(<-chan struct{}) diagnosticResult) *diagnosticCall {
	t.Helper()
	call := &diagnosticCall{release: make(chan struct{}), done: make(chan struct{}), result: make(chan diagnosticResult, 1)}
	go func() { defer close(call.done); call.result <- run(call.release) }()
	t.Cleanup(func() {
		call.once.Do(func() { close(call.release) })
		awaitDiagnostic(t, call.done, "diagnostic operation did not join")
	})
	return call
}

func awaitDiagnostic(t *testing.T, ch <-chan struct{}, message string) bool {
	t.Helper()
	select {
	case <-ch:
		return true
	case <-time.After(time.Second):
		t.Error(message)
		return false
	}
}

func finishDiagnostic(t *testing.T, call *diagnosticCall) (diagnosticResult, bool) {
	t.Helper()
	call.once.Do(func() { close(call.release) })
	if !awaitDiagnostic(t, call.done, "diagnostic operation did not return and join") {
		return diagnosticResult{}, false
	}
	select {
	case result := <-call.result:
		return result, true
	case <-time.After(time.Second):
		t.Error("diagnostic operation result was not returned")
		return diagnosticResult{}, false
	}
}

func openFakeRuntime(t *testing.T, handle mcpbridge.UpstreamHandle, closeLaunch func(context.Context) error) *mcpbridge.Runtime {
	t.Helper()
	r, err := mcpbridge.Open(context.Background(), []mcpbridge.UpstreamHandle{handle}, mustGuard(t, secretLiteral), closeLaunch, bindings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeFakeRuntime(t, r, time.Second); err != nil {
			t.Errorf("fake runtime cleanup did not join: %v", err)
		}
	})
	return r
}

func closeFakeRuntime(t *testing.T, r *mcpbridge.Runtime, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return r.Close(ctx)
}

func TestMissingInitializationCanceledOperationDoesNotTakeTransport(t *testing.T) {
	handle := &fakeHandle{}
	r := openFakeRuntime(t, handle, func(context.Context) error { return nil })
	op, cancel := context.WithCancel(context.Background())
	cancel()
	data, err := wire.Encode(struct {
		Ordinal int `json:"ordinal"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	reply, ok := r.Handle(op, wire.Request{Operation: mcpbridge.OpDescribe, Data: data})
	if !ok || reply.OK || handle.takes.Load() != 0 {
		t.Fatalf("canceled operation consumed transport: ok=%v reply=%+v takes=%d", ok, reply, handle.takes.Load())
	}
}

func TestCanceledInitializationClosesAndJoinsConnection(t *testing.T) {
	conn := newFakeConnection("")
	r := openFakeRuntime(t, &fakeHandle{transport: &fakeTransport{conn}}, func(context.Context) error { return nil })
	op, cancel := context.WithCancel(context.Background())
	defer cancel()
	data, err := wire.Encode(struct {
		Ordinal int `json:"ordinal"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	result := make(chan wire.Reply, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Error("operation worker did not exit after cancel")
		}
	})
	go func() {
		defer close(exited)
		reply, _ := r.Handle(op, wire.Request{Operation: mcpbridge.OpDescribe, Data: data})
		result <- reply
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initialize read did not start")
	}
	cancel()
	select {
	case reply := <-result:
		if reply.OK {
			t.Fatal("canceled initialization succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled operation did not return")
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("operation worker did not exit")
	}
	if err := closeFakeRuntime(t, r, time.Second); err != nil {
		t.Fatalf("close after canceled initialization: %v", err)
	}
	if !conn.once.Load() {
		t.Fatal("captured connection leaked")
	}
}

func TestUnknownProtocolFailureClosesCapturedConnection(t *testing.T) {
	conn := newFakeConnection("unsupported-version")
	close(conn.response)
	r := openFakeRuntime(t, &fakeHandle{transport: &fakeTransport{conn}}, func(context.Context) error { return nil })
	data, err := wire.Encode(struct {
		Ordinal int `json:"ordinal"`
	}{})
	if err != nil {
		t.Fatal(err)
	}
	reply, ok := r.Handle(context.Background(), wire.Request{Operation: mcpbridge.OpDescribe, Data: data})
	if !ok || reply.OK {
		t.Fatalf("unsupported version accepted or not handled: ok=%v reply=%+v", ok, reply)
	}
	if err := closeFakeRuntime(t, r, time.Second); err != nil {
		t.Fatalf("close after unsupported handshake: %v", err)
	}
	if !conn.once.Load() {
		t.Fatal("unsupported handshake leaked connection")
	}
}
