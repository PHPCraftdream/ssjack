package mcpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
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
	closeErr error
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
	first := c.once.CompareAndSwap(false, true)
	if first {
		close(c.closed)
	}
	if first && c.closeErr != nil {
		return c.closeErr
	}
	return nil
}
func (*testConnection) SessionID() string { return "test" }

func testRuntime(t *testing.T, parent context.Context, h UpstreamHandle, closeLaunch func(context.Context) error, wantSticky bool) *Runtime {
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
		if err := r.Close(ctx); wantSticky != errors.Is(err, ErrBridge) {
			t.Errorf("sticky close mismatch: %v", err)
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

// canceledDescribeReply drives one canceled describe and joins its worker.
func canceledDescribeReply(t *testing.T, r *Runtime, conn *testConnection) wire.Reply {
	t.Helper()
	op, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan wire.Reply, 1)
	exited := make(chan struct{})
	describeAsync(t, r, op, exited, result)
	t.Cleanup(func() {
		joinExited(t, exited, "operation worker did not exit after cancel")
	})
	awaitSignal(t, conn.started, "Connect read did not start")
	cancel()
	reply := awaitSignal(t, result, "operation did not return")
	awaitSignal(t, exited, "operation worker did not exit")
	if reply.OK {
		t.Fatal("canceled initialization succeeded")
	}
	return reply
}

func TestLateHandshakeResponseCannotInstallSessionAfterClose(t *testing.T) {
	conn := newTestConnection("2025-06-18")
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	operationExited := make(chan struct{})
	closed := make(chan error, 1)
	closeExited := make(chan struct{})
	startClose := make(chan struct{})
	var startCloseOnce sync.Once
	startCloseNow := func() { startCloseOnce.Do(func() { close(startClose) }) }
	var responseOnce sync.Once
	responseNow := func() { responseOnce.Do(func() { close(conn.response) }) }
	t.Cleanup(func() {
		responseNow()
		startCloseNow()
		joinExited(t, closeExited, "close worker did not exit after gates released")
		joinExited(t, operationExited, "operation worker did not exit after gates released")
	})
	describeAsync(t, r, context.Background(), operationExited, result)
	launchGatedClose(t, r, startClose, closed, closeExited)
	awaitSignal(t, conn.request, "initialize request was not written")
	startCloseNow()
	awaitSignal(t, r.ctx.Done(), "Close did not cancel the pending handshake")
	responseNow()
	if err := awaitSignal(t, closed, "Close did not join handshake"); err != nil {
		t.Fatal(err)
	}
	if reply := awaitSignal(t, result, "operation outlived Close"); reply.OK {
		t.Fatalf("late handshake succeeded: %+v", reply)
	}
	awaitSignal(t, closeExited, "close worker did not exit")
	awaitSignal(t, operationExited, "operation worker did not exit")
	if !r.slots[0].failed {
		t.Fatal("late handshake was not marked failed")
	}
	if !conn.once.Load() {
		t.Fatal("late handshake connection did not close")
	}
	select {
	case <-r.slots[0].closeDone:
	default:
		t.Fatal("binding cleanup not joined")
	}
}

func TestShutdownJoinsLateCapturedConnection(t *testing.T) {
	conn := newTestConnection("")
	entered, release := make(chan struct{}), make(chan struct{})
	h := &testHandle{transport: &testTransport{conn}, beforeTake: func() error {
		close(entered)
		<-release
		return nil
	}}
	r := testRuntime(t, context.Background(), h, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	operationExited := make(chan struct{})
	closeExited := make(chan struct{})
	startClose := make(chan struct{})
	var releaseOnce sync.Once
	releaseNow := func() { releaseOnce.Do(func() { close(release) }) }
	var startCloseOnce sync.Once
	startCloseNow := func() { startCloseOnce.Do(func() { close(startClose) }) }
	t.Cleanup(func() {
		startCloseNow()
		releaseNow()
		joinExited(t, closeExited, "close worker did not exit after gates released")
		joinExited(t, operationExited, "operation worker did not exit after gates released")
	})
	describeAsync(t, r, context.Background(), operationExited, result)
	go func() {
		defer close(closeExited)
		<-startClose
		if err := closeBounded(t, r, time.Second); err != nil {
			t.Error(err)
		}
	}()
	awaitSignal(t, entered, "blocked take did not enter before shutdown")
	startCloseNow()
	awaitSignal(t, r.slots[0].closeStarted, "close did not begin before late capture")
	releaseNow()
	awaitSignal(t, closeExited, "close worker did not exit")
	if reply := awaitSignal(t, result, "operation did not return after late capture"); reply.OK {
		t.Fatal("late captured initialization succeeded")
	}
	awaitSignal(t, operationExited, "operation worker did not exit")
	if !conn.once.Load() {
		t.Fatal("late captured connection was not closed")
	}
}

func TestFirstCapturedCloseErrorIsRetained(t *testing.T) {
	conn := newTestConnection("")
	conn.closeErr = errors.New("synthetic first close refusal")
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, true)
	canceledDescribeReply(t, r, conn)
	if err := closeBounded(t, r, time.Second); !errors.Is(err, ErrBridge) {
		t.Fatal("genuine first captured close error did not keep cleanup sticky")
	}
	r.slots[0].mu.Lock()
	joined := r.slots[0].closeErr
	r.slots[0].mu.Unlock()
	if joined == nil || !strings.Contains(joined.Error(), "synthetic first close refusal") {
		t.Fatalf("first captured close error was discarded: %v", joined)
	}
}

// TestInitialAttemptFinishesBeforeCreatorInterprets forces the creating Close to interpret a finished initial attempt.
func TestInitialAttemptFinishesBeforeCreatorInterprets(t *testing.T) {
	workerGate := make(chan struct{})
	creatorHold := make(chan struct{})
	cancelCalled := make(chan struct{})
	releaseWorker, releaseCreator, cancelSignal := gateClose(workerGate), gateClose(creatorHold), gateClose(cancelCalled)
	closeRuns := &atomic.Int32{}
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn: newTestConnection("")}}, func(context.Context) error {
		if closeRuns.Add(1) == 1 {
			<-workerGate
			return errors.New("synthetic initial close failure")
		}
		return nil
	}, false)
	callerExited, firstCloseErr := make(chan struct{}), make(chan error, 1)
	t.Cleanup(func() { joinExited(t, callerExited, "creating Close caller did not exit") })
	t.Cleanup(func() { releaseWorker(); releaseCreator() })
	slotCancel := r.slots[0].cancel
	r.slots[0].cancel = func() { slotCancel(); cancelSignal(); <-creatorHold }
	go func() { defer close(callerExited); firstCloseErr <- closeBounded(t, r, time.Second) }()
	awaitSignal(t, cancelCalled, "Close did not enter the slot cancel loop")
	r.mu.Lock()
	attempt := r.cleanupAttempt
	r.mu.Unlock()
	releaseWorker()
	awaitSignal(t, attempt, "initial attempt did not finish")
	releaseCreator()
	if err := awaitSignal(t, firstCloseErr, "creating Close did not return"); !errors.Is(err, ErrBridge) {
		t.Fatalf("creating Close did not retain its own failed attempt: %v", err)
	}
	if got := closeRuns.Load(); got != 1 {
		t.Fatalf("hidden automatic cleanup rerun: closeLaunch runs=%d", got)
	}
	if err := closeBounded(t, r, time.Second); err != nil {
		t.Fatalf("explicit retry close failed: %v", err)
	}
	if got := closeRuns.Load(); got != 2 {
		t.Fatalf("closeLaunch runs=%d, want one failed initial attempt then one explicit retry", got)
	}
}
