package mcpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	served   int // responses served, incremented in Read
	once     atomic.Bool
	closeErr error
}

func newTestConnection(version string) *testConnection {
	return &testConnection{started: make(chan struct{}), closed: make(chan struct{}), ids: make(chan jsonrpc.ID, 4), request: make(chan struct{}), response: make(chan struct{}), version: version}
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
			c.served++
			if c.served == 1 {
				return &jsonrpc.Response{ID: id, Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"}}, nil
			}
			close(c.request)
			<-c.response
			body, _ := json.Marshal(mcp.InitializeResult{ProtocolVersion: c.version, Capabilities: &mcp.ServerCapabilities{}, ServerInfo: &mcp.Implementation{Name: "fixture", Version: "1"}})
			return &jsonrpc.Response{ID: id, Result: body}, nil
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
	awaitSignal(t, r.slots[0].closeStarted, "binding cleanup did not start after cancellation")
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

func maskGuard(t *testing.T) *outputguard.Snapshot {
	t.Helper()
	guard, err := outputguard.New([][]byte{[]byte(secretLiteral)})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestOpenValidationRefuses(t *testing.T) {
	guard := maskGuard(t)
	closeLaunch := func(context.Context) error { return nil }
	live := context.Background()
	canceled, cancel := context.WithCancel(live)
	cancel()
	manyHandles := make([]UpstreamHandle, 17)
	manyBindings := make([]mcpdirectory.Binding, 17)
	zeroBinding := []mcpdirectory.Binding{{ServerID: "s", AccountID: "a"}}
	cases := map[string]func() (*Runtime, error){
		"nil parent": func() (*Runtime, error) {
			return Open(nil, []UpstreamHandle{&testHandle{}}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"canceled parent": func() (*Runtime, error) {
			return Open(canceled, []UpstreamHandle{&testHandle{}}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"nil guard": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{&testHandle{}}, nil, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"nil close": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{&testHandle{}}, guard, nil, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"length mismatch": func() (*Runtime, error) {
			return Open(live, nil, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"empty":    func() (*Runtime, error) { return Open(live, nil, guard, closeLaunch, nil) },
		"too many": func() (*Runtime, error) { return Open(live, manyHandles, guard, closeLaunch, manyBindings) },
		"nil handle": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{nil}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"zero binding": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{&testHandle{}}, guard, closeLaunch, zeroBinding)
		},
	}
	for name, open := range cases {
		if runtime, err := open(); runtime != nil || !errors.Is(err, ErrBridge) {
			t.Fatalf("%s: expected ErrBridge, got %+v, %v", name, runtime, err)
		}
	}
}

func TestMaskValueWalksStringsAndPreservesControlFields(t *testing.T) {
	guard := maskGuard(t)
	value := map[string]any{
		"secret": secretLiteral,
		"nested": []any{secretLiteral, 3, true, nil, map[string]any{"deep": secretLiteral}},
		"count":  12,
	}
	budget := MaxMaskNodes
	masked, err := maskValue(guard, value, &budget)
	if err != nil {
		t.Fatal(err)
	}
	maskedMap := masked.(map[string]any)
	if maskedMap["secret"] != outputguard.Marker || maskedMap["count"] != 12 {
		t.Fatalf("unexpected masking: %+v", maskedMap)
	}
	nested := maskedMap["nested"].([]any)
	if nested[0] != outputguard.Marker || nested[1] != 3 || nested[2] != true || nested[3] != nil {
		t.Fatalf("non-string leaves were changed: %+v", nested)
	}
	if nested[4].(map[string]any)["deep"] != outputguard.Marker {
		t.Fatalf("deep string was not masked: %+v", nested[4])
	}
	// Inputs are never mutated.
	if value["secret"] != secretLiteral {
		t.Fatal("input value was mutated")
	}
	tiny := 0
	if _, err := maskValue(guard, map[string]any{"a": "b"}, &tiny); err == nil {
		t.Fatal("exhausted budget did not error")
	}
}

func TestMaskResultCoversContentKindsAndBounds(t *testing.T) {
	guard := maskGuard(t)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "text " + secretLiteral},
			&mcp.ImageContent{},
		},
		StructuredContent: map[string]any{"secret": secretLiteral, "n": 7},
		IsError:           true,
	}
	data, err := maskResult(guard, result)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(data)
	if !strings.Contains(encoded, outputguard.Marker) || strings.Contains(encoded, secretLiteral) {
		t.Fatalf("secret leaked through maskResult: %s", encoded)
	}
	if !strings.Contains(encoded, omittedContent) {
		t.Fatalf("non-text content was not replaced: %s", encoded)
	}
	if !strings.Contains(encoded, `"n":7`) || !strings.Contains(encoded, `"isError":true`) {
		t.Fatalf("structured value or IsError was not preserved: %s", encoded)
	}
	oversized := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 70<<10)}}}
	if _, err := maskResult(guard, oversized); !errors.Is(err, errResultSize) {
		t.Fatalf("expected errResultSize, got %v", err)
	}
}

func TestMaskValueRefusesKnownKeysAndBoundsDepthAndLeaves(t *testing.T) {
	guard := maskGuard(t)
	budget := MaxMaskNodes
	if _, err := maskValue(guard, map[string]any{secretLiteral: "safe"}, &budget); !errors.Is(err, errResultSize) {
		t.Fatal("known literal key was renamed or leaked")
	}
	deep := any("leaf")
	for i := 0; i < maxGuardDepth+2; i++ {
		deep = []any{deep}
	}
	budget = MaxMaskNodes
	if _, err := maskValue(guard, deep, &budget); err == nil {
		t.Fatal("excessive recursion depth accepted")
	}
	budget = 1
	if _, err := maskValue(guard, []any{1, true, nil}, &budget); err == nil {
		t.Fatal("non-string leaf budget was not counted")
	}
}

func TestStructuredRawMessageAndNilContentAreSafe(t *testing.T) {
	guard := maskGuard(t)
	var nilText *mcp.TextContent
	data, err := maskResult(guard, &mcp.CallToolResult{Content: []mcp.Content{nil, nilText}, StructuredContent: json.RawMessage(`{"n":123456789012345678901234567890,"safe":true}`)})
	if err != nil || !strings.Contains(string(data), "123456789012345678901234567890") {
		t.Fatalf("raw structured content lost precision: %s, %v", data, err)
	}
	if strings.Count(string(data), omittedContent) != 2 {
		t.Fatalf("nil text content was not replaced: %s", data)
	}
	if _, err := maskResult(guard, &mcp.CallToolResult{StructuredContent: json.RawMessage(`{"a":1,"a":2}`)}); err == nil {
		t.Fatal("duplicate structured keys accepted")
	}
}

func TestJSONNormalizationPreservesNumbersAndBoundsTypedRawMessage(t *testing.T) {
	decoded, err := decodeJSONNoDuplicates([]byte(`{"n":9007199254740993}`), 128, maxGuardDepth, MaxMaskNodes)
	if err != nil || decoded.(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Fatalf("large integer was not preserved: %#v, %v", decoded, err)
	}
	if _, err := decodeJSONNoDuplicates([]byte(`{"n":1,"n":2}`), 128, maxGuardDepth, MaxMaskNodes); !errors.Is(err, errArguments) {
		t.Fatalf("duplicate-key error was not translated: %v", err)
	}
	deep := any("leaf")
	for i := 0; i < maxGuardDepth+2; i++ {
		deep = []any{deep}
	}
	if _, err := normalizeJSON(deep, MaxResultBytes); !errors.Is(err, errResultSize) {
		t.Fatalf("over-depth typed value was accepted: %v", err)
	}
	typed := struct {
		Payload json.RawMessage `json:"payload"`
	}{Payload: json.RawMessage(`{"n":9007199254740993}`)}
	normalized, err := normalizeJSON(typed, 128)
	if err != nil || normalized.(map[string]any)["payload"].(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Fatalf("typed RawMessage was not safely normalized: %#v, %v", normalized, err)
	}
}

func TestSchemaRefusesSecretsInAnyStringToPreserveControlSemantics(t *testing.T) {
	guard := maskGuard(t)
	for _, schema := range []map[string]any{
		{"type": secretLiteral},
		{"enum": []any{secretLiteral}},
		{"properties": map[string]any{secretLiteral: map[string]any{"type": "string"}}},
		{"required": []any{secretLiteral}},
		{"const": map[string]any{"description": secretLiteral}},
		{"enum": []any{map[string]any{"description": secretLiteral}}},
	} {
		if _, err := maskSchema(guard, schema); err == nil {
			t.Fatalf("schema string secret accepted: %#v", schema)
		}
	}
}

func TestMaskSchemaPreservesOrdinaryShapeAndRefusesSecretDescription(t *testing.T) {
	guard := maskGuard(t)
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"q": map[string]any{"type": "string", "description": "ordinary help text"}},
	}
	masked, err := maskSchema(guard, schema)
	if err != nil {
		t.Fatal(err)
	}
	if masked["type"] != "object" {
		t.Fatalf("top-level type was lost: %+v", masked)
	}
	property := masked["properties"].(map[string]any)["q"].(map[string]any)
	if property["type"] != "string" || property["description"] != "ordinary help text" {
		t.Fatalf("schema shape or prose changed: %+v", property)
	}
	secretDescription := map[string]any{"properties": map[string]any{"q": map[string]any{"description": "about " + secretLiteral}}}
	if _, err := maskSchema(guard, secretDescription); err == nil {
		t.Fatal("secret schema description was rewritten instead of refusing the schema")
	}
	tiny := map[string]any{"blob": strings.Repeat("y", MaxSchemaBytes+1)}
	if _, err := maskSchema(guard, tiny); err == nil {
		t.Fatal("oversized schema was accepted")
	}
}

func TestMaskResultBoundsEscapedOutput(t *testing.T) {
	guard := maskGuard(t)
	control := strings.Repeat("\x01", 12<<10)
	if _, err := maskResult(guard, &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: control}}}); !errors.Is(err, errResultSize) {
		t.Fatalf("escape-expanded output exceeded its bound without refusal: %v", err)
	}
}

// awaitSignal joins one owned worker or gate with the shared one-second budget.
func awaitSignal[T any](t *testing.T, signal <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
	}
	var zero T
	return zero
}

// describeAsync launches one describe operation worker that closes exited on
// return, used by runtime lifecycle tests.
func describeAsync(t *testing.T, r *Runtime, op context.Context, exited chan struct{}, result chan wire.Reply) {
	t.Helper()
	data, err := wire.Encode(ordinalInput{})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(exited)
		reply, _ := r.Handle(op, wire.Request{Operation: OpDescribe, Data: data})
		result <- reply
	}()
}

// joinExited bounded-asserts one worker exit; cleanup-safe because it uses
// t.Error instead of t.Fatal, so every joined worker is reported.
func joinExited(t *testing.T, exited <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Error(message)
	}
}

// launchGatedClose runs the single owned shutdown worker: it waits for the
// startClose gate, closes the runtime bounded, reports the result, and only
// then releases its exit signal.
func launchGatedClose(t *testing.T, r *Runtime, startClose <-chan struct{}, closed chan<- error, closeExited chan<- struct{}) {
	t.Helper()
	go func() {
		defer close(closeExited)
		<-startClose
		closed <- closeBounded(t, r, time.Second)
	}()
}

// gateClose returns a cleanup-safe func that closes one test gate exactly once.
func gateClose(ch chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// notifyingConnection signals the initialized notification, the last write of a
// successful handshake, so a test can cancel strictly after Connect has won.
type notifyingConnection struct {
	*testConnection
	notified chan struct{}
	signal   sync.Once
}

func (c *notifyingConnection) Write(ctx context.Context, m jsonrpc.Message) error {
	err := c.testConnection.Write(ctx, m)
	if req, ok := m.(*jsonrpc.Request); ok && !req.ID.IsValid() {
		c.signal.Do(func() { close(c.notified) })
	}
	return err
}

// TestSessionWonAfterShutdownIsJoinedCleanly forces the interleaving where
// Client.Connect completes while r.ctx is only canceled afterwards: the session
// is published on a failed slot and cleanup must join its owned close as clean
// (an owned close reports io.EOF, as the production exchange does).
func TestSessionWonAfterShutdownIsJoinedCleanly(t *testing.T) {
	conn := &notifyingConnection{testConnection: newTestConnection("2025-06-18"), notified: make(chan struct{})}
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	exited := make(chan struct{})
	var responseOnce sync.Once
	locked := false
	releaseResponse := func() { responseOnce.Do(func() { close(conn.response) }) }
	unlock := func() {
		if locked {
			locked = false
			r.mu.Unlock()
		}
	}
	describeAsync(t, r, context.Background(), exited, result)
	t.Cleanup(func() {
		releaseResponse()
		unlock()
		joinExited(t, exited, "operation worker did not exit")
	})
	awaitSignal(t, conn.request, "initialize request was not written")
	r.mu.Lock() // parks initialize before its validity check until cancellation is in place
	locked = true
	releaseResponse()
	awaitSignal(t, conn.notified, "handshake did not complete")
	r.cancel()
	unlock()
	if err := closeBounded(t, r, time.Second); err != nil {
		t.Fatalf("Close did not join the late session cleanly: %v", err)
	}
	if reply := awaitSignal(t, result, "operation outlived Close"); reply.OK {
		t.Fatalf("describe succeeded after shutdown: %+v", reply)
	}
	awaitSignal(t, exited, "operation worker did not exit")
	s := r.slots[0]
	s.mu.Lock()
	failed, installed := s.failed, s.session != nil
	s.mu.Unlock()
	if !failed || !installed {
		t.Fatalf("late session state failed=%v installed=%v, want failed session joined by cleanup", failed, installed)
	}
	if !conn.once.Load() {
		t.Fatal("late session connection did not close")
	}
}
