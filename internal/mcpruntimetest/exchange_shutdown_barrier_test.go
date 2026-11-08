package mcpruntimetest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpexchange"
	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// Close-side gate oracle. Read/Write/SessionID are pure delegation, so the
// describe handshake runs with no interference at all. The gate parks the
// session's Close: gatedConn.Close signals closeEntered, then blocks on
// release before delegating to base.Close. Trace: closeOwned (lifecycle.go:137-153)
// runs session.Close() then session.Wait() before closing closeDone (deferred :138);
// cleanupAttemptRun (:208-241) waits closeDone before closeLaunch (:234). ClientSession.Close invokes
// conn.Close → our closer (mcp/client.go:208-224; jsonrpc2/conn.go:133-137).
// While the gate holds, the exchange Read stays parked on the incoming
// select, so the reader goroutine never exits and closeDone never closes:
// closeOwned is blocked inside session.Close, meaning production structurally
// cannot reach closeLaunch during this phase. The closeLaunch callback itself
// records a violation whenever it runs while the gate is still held, so
// release-before-join is observed independently for the ENTIRE parked
// window, not just at one sampling instant. Counterfactual: an early or
// reordered closeLaunch during the parked interval ⇒ violations becomes true
// ⇒ the test fails deterministically; omitting the slot join so closeLaunch
// runs while parked ⇒ same violation ⇒ same failure. Caveat: the pinned SDK's
// session.Close itself joins the reader (conn.Close → wait(false), conn.go:523-528),
// so these tests prove closeLaunch and credential release are withheld until the
// session FULLY joins; runtime Wait only aggregates errors. On release, base.Close
// closes closedCh, the exchange Read gets io.EOF, the reader exits, Wait joins,
// closeDone closes, and closeLaunch runs once with credentials cleared. The violation-tracking paragraph applies
// only to the gated positive test; the genuine-peer test uses the UNGATED
// runtime because the SDK invokes its closer synchronously on idle-with-writeErr
// (conn.go:133-135) — a held gate would deadlock.

type gateState struct {
	released     chan struct{} // closed to free the parked Close
	closeEntered chan struct{} // buffered; wrapper Close entered exactly once
	releaseOnce  sync.Once     // release() is idempotent for cleanup paths
	violations   atomic.Bool   // set if closeLaunch ever runs while held
}

// held reports whether the gate is still parked (release not yet closed).
func (g *gateState) held() bool {
	select {
	case <-g.released:
		return false
	default:
		return true
	}
}

// release frees a parked Close; idempotent so LIFO cleanup always unblocks.
func (g *gateState) release() { g.releaseOnce.Do(func() { close(g.released) }) }

type gatedTransport struct {
	base *mcpexchange.Transport
	gate *gateState
}

func (t *gatedTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &gatedConn{base: conn, gate: t.gate}, nil
}

// gatedConn delegates Read/Write/SessionID untouched; only Close is gated.
type gatedConn struct {
	base mcp.Connection
	gate *gateState
}

func (c *gatedConn) Read(ctx context.Context) (jsonrpc.Message, error) { return c.base.Read(ctx) }

func (c *gatedConn) Write(ctx context.Context, msg jsonrpc.Message) error {
	return c.base.Write(ctx, msg)
}

func (c *gatedConn) SessionID() string { return c.base.SessionID() }

func (c *gatedConn) Close() error {
	select {
	case c.gate.closeEntered <- struct{}{}:
	default:
	}
	// Block until the test releases; gate.release cleanup guarantees progress.
	<-c.gate.released
	return c.base.Close()
}

// openGatedRuntime builds flow → client → exchange → gated transport →
// mcpbridge.Open, registers LIFO ownership cleanup (registrations: flow
// cleanup, then runtime close, then gate release; Go cleanup runs LIFO, so
// execution order is gate release → runtime close → flow close, a parked
// Close can always proceed, and no worker leaks); closeLaunch runs are counted
// and any launch while the gate is held records a violation.
func openGatedRuntime(t *testing.T, peer exchangePeer, gate *gateState, closeRuns *atomic.Int32) (*mcpbridge.Runtime, *mcpflow.Transport, *atomic.Bool) {
	t.Helper()
	clearFlag := &atomic.Bool{}
	flow, err := mcpflow.New(context.Background(), peer, func(r *http.Request) (*http.Request, error) { return r, nil }, func() { clearFlag.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { boundedCloseFlow(flow) })
	client := &http.Client{Transport: flow, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	exch, err := mcpexchange.New("https://exchange.fixture/mcp", client)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := mcpbridge.Open(context.Background(), []mcpbridge.UpstreamHandle{&stubHandle{transport: &gatedTransport{base: exch, gate: gate}}}, mustGuard(t), func(closeCtx context.Context) error {
		closeRuns.Add(1)
		if gate.held() {
			gate.violations.Store(true)
		}
		return flow.Close(closeCtx)
	}, bindings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { boundedClose(rt) })
	t.Cleanup(gate.release)
	return rt, flow, clearFlag
}

// boundedCloseFlow/boundedClose are failure-path janitors: discard results
// (an earlier failure may leave Close returning ErrBridge) and never report;
// both Close calls are repeatable.
func boundedCloseFlow(flow *mcpflow.Transport) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = flow.Close(ctx)
}

func boundedClose(rt *mcpbridge.Runtime) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = rt.Close(ctx)
}

// TestGatedReadWithholdsCloseLaunchUntilSessionWaitJoins proves closeLaunch
// and credential release are withheld while the session Close is parked
// inside the wrapper, and complete after release.
func TestGatedReadWithholdsCloseLaunchUntilSessionWaitJoins(t *testing.T) {
	ctx := testContext(t)
	closeRuns := &atomic.Int32{}
	gate := &gateState{released: make(chan struct{}), closeEntered: make(chan struct{}, 1)}
	rt, _, clearFlag := openGatedRuntime(t, exchangeRPCPeer(t, false, nil), gate, closeRuns)
	// No gate interference on traffic: real SDK initialize + tools/list.
	reply, name := describeAndToolName(t, rt, ctx)
	if !reply.OK {
		t.Fatal("describe failed")
	}
	if name == "" {
		t.Fatal("empty tool name")
	}

	// Parked phase: closeOwned is blocked inside session.Close behind the gate.
	closeErr := make(chan error, 1)
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { closeErr <- rt.Close(closeCtx) }()
	select {
	case <-gate.closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("session Close never entered the wrapper")
	}
	if got := closeRuns.Load(); got != 0 { // fast-fail aid only
		t.Fatalf("closeLaunch runs while session Close is parked = %d, want 0", got)
	}
	if clearFlag.Load() {
		t.Fatal("credentials must be retained while the session has not joined")
	}
	select {
	case err := <-closeErr:
		if !errors.Is(err, mcpbridge.ErrBridge) {
			t.Fatalf("parked close must be ErrBridge, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked close did not report ErrBridge in time")
	}
	// Release: base.Close fires, the reader exits, Wait joins, closeLaunch runs.
	gate.release()
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retryCancel()
	if err := rt.Close(retryCtx); err != nil {
		t.Fatalf("retry close after release must be nil, got %v", err)
	}
	if got := closeRuns.Load(); got != 1 {
		t.Fatalf("closeLaunch runs = %d, want 1", got)
	}
	if !clearFlag.Load() {
		t.Fatal("credential material not cleared after released shutdown")
	}
	if gate.violations.Load() {
		t.Fatal("closeLaunch ran while the gate held release-before-join violated")
	}
}

// refusalPeer answers a genuine initialized session, then refuses tools/call
// with a 500 text/plain body: a real peer protocol refusal, not a synthetic
// closeLaunch failure.
func refusalPeer() exchangePeer {
	return exchangePeer(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		var envelope struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &envelope)
		id := string(envelope.ID)
		switch {
		case strings.Contains(text, `"method":"initialize"`):
			payload := `{"jsonrpc":"2.0","id":` + id + `,"result":{"protocolVersion":"2025-06-18"}}`
			return jsonResponse(http.StatusOK, id, payload), nil
		case strings.Contains(text, `"method":"notifications/initialized"`):
			return emptyResponse(http.StatusAccepted), nil
		case strings.Contains(text, `"method":"tools/list"`):
			payload := `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[{"name":"echo","description":"echo tool","inputSchema":{"type":"object"}}]}}`
			return jsonResponse(http.StatusOK, id, payload), nil
		case strings.Contains(text, `"method":"tools/call"`):
			return &http.Response{
				StatusCode:    http.StatusInternalServerError,
				Status:        "Internal Server Error",
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				Body:          io.NopCloser(strings.NewReader("peer refused the call")),
				ContentLength: 21,
			}, nil
		}
		return emptyResponse(http.StatusMethodNotAllowed), nil
	})
}

// TestGenuinePeerProtocolErrorKeepsLaunchWithheldThroughWait: a peer that
// refuses tools/call (HTTP 500) must make Close return ErrBridge and keep
// closeLaunch/credential release withheld — because production calls session.Wait.
// Trace: the peer returns 500 → mcpflow's RoundTrip status check rejects it as a definite
// transport refusal BEFORE any exchange status branch → the exchange Write observes the
// client.Do transport error as its fixed errExchange (live connection, owned context not
// yet canceled); the SDK records writeErr with the live caller ctx (conn.go:781-792); Call
// retires the outgoing entry and updateInFlight synchronously runs the closer on idle-with-writeErr
// (conn.go:361-372, :133-135); done closes and cs.Close returns the closer's nil
// (mcp/client.go:208-224); production session.Wait returns the non-EOF writeErr (conn.go:497-506), so
// slot closeErr = errors.Join(nil, writeErr) is nonnil ONLY because production calls session.Wait
// (lifecycle.go:143-151); removing Wait makes closeErr nil, cleanup proceeds,
// closeLaunch runs, closeRuns==0 fails deterministically. Retrying Close returns ErrBridge:
// lifecycle.go:230-231 sets the sticky terminal error; :259 requires !cleanupTerminal. There is NO
// gate: the ungated exchange connection IS the closer, so the synchronous SDK close path completes
// and Handle returns; the callback never performs the Wait it observes; the failure is genuine.
func TestGenuinePeerProtocolErrorKeepsLaunchWithheldThroughWait(t *testing.T) {
	ctx := testContext(t)
	closeRuns := &atomic.Int32{}
	rt, _, clearFlag := newExchangeRuntime(t, refusalPeer(), func(f *mcpflow.Transport, closeCtx context.Context) error {
		closeRuns.Add(1)
		return f.Close(closeCtx)
	})
	reply, name := describeAndToolName(t, rt, ctx)
	if !reply.OK || name == "" {
		t.Fatal("describe failed or empty tool name")
	}
	data, err := wire.Encode(mcpbridge.CallInput{Ordinal: 0, Tool: name})
	if err != nil {
		t.Fatal(err)
	}
	callReply, _ := rt.Handle(ctx, wire.Request{Operation: mcpbridge.OpCall, Data: data})
	if callReply.OK {
		t.Fatal("tools/call must not be OK after a peer protocol refusal")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rt.Close(closeCtx); !errors.Is(err, mcpbridge.ErrBridge) {
		t.Fatalf("close with genuine write error must be ErrBridge, got %v", err)
	}
	if got := closeRuns.Load(); got != 0 {
		t.Fatalf("closeLaunch runs = %d, want 0: genuine failure retains credentials", got)
	}
	if clearFlag.Load() {
		t.Fatal("credential material must be retained when Wait reports a write error")
	}
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retryCancel()
	if err := rt.Close(retryCtx); !errors.Is(err, mcpbridge.ErrBridge) {
		t.Fatalf("retry close must stay ErrBridge (terminal, not retried), got %v", err)
	}
}
