package mcpruntimetest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpexchange"
	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// exchangePeer adapts a func into an http.RoundTripper for the owned exchange.
type exchangePeer func(*http.Request) (*http.Response, error)

func (f exchangePeer) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// newExchangeRuntime opens a real mcpbridge runtime over the owned mcpexchange
// transport, wrapping the peer with a real mcpflow transport whose clear
// callback records when HTTP credential material is released. closeLaunch
// receives the opened flow so it can release credentials without capturing a
// variable declared by its own initializer.
func newExchangeRuntime(t *testing.T, peer exchangePeer, closeLaunch func(*mcpflow.Transport, context.Context) error) (*mcpbridge.Runtime, *mcpflow.Transport, *atomic.Bool) {
	t.Helper()
	clearFlag := &atomic.Bool{}
	flow, err := mcpflow.New(context.Background(), peer, func(r *http.Request) (*http.Request, error) { return r, nil }, func() { clearFlag.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	// LIFO: registered flow-first then runtime-first, so cleanup closes the
	// runtime before the flow; both Close calls are repeatable, making this a
	// no-op after an explicit test Close and a safety net on failure paths.
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = flow.Close(cctx)
	})
	client := &http.Client{Transport: flow, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	exch, err := mcpexchange.New("https://exchange.fixture/mcp", client)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := mcpbridge.Open(context.Background(), []mcpbridge.UpstreamHandle{&stubHandle{transport: exch}}, mustGuard(t), func(closeCtx context.Context) error { return closeLaunch(flow, closeCtx) }, bindings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = rt.Close(cctx)
	})
	return rt, flow, clearFlag
}

// exchangeRPCPeer answers the streamable HTTP JSON-RPC exchange inline.
func exchangeRPCPeer(t *testing.T, callBlock bool, started chan struct{}) exchangePeer {
	t.Helper()
	return func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read peer body: %v", err)
			return nil, err
		}
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
			if callBlock {
				select {
				case <-started:
				default:
					close(started)
				}
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			payload := `{"jsonrpc":"2.0","id":` + id + `,"result":{"content":[{"type":"text","text":"ok"}]}}`
			return jsonResponse(http.StatusOK, id, payload), nil
		}
		return emptyResponse(http.StatusMethodNotAllowed), nil
	}
}

func jsonResponse(status int, _ string, payload string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
}

func emptyResponse(status int) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
	}
}

// describe opens the real SDK session over the owned exchange and returns the
// describe reply plus the upstream tool name from the inventory envelope.
func describeAndToolName(t *testing.T, rt *mcpbridge.Runtime, ctx context.Context) (wire.Reply, string) {
	t.Helper()
	data, err := wire.Encode(ordinalInput{})
	if err != nil {
		t.Fatal(err)
	}
	reply, handled := rt.Handle(ctx, wire.Request{Operation: mcpbridge.OpDescribe, Data: data})
	if !handled {
		t.Fatal("describe was not handled")
	}
	if !reply.OK {
		return reply, ""
	}
	var envelope mcpbridge.InventoryEnvelope
	if err := wire.Decode(reply.Data, &envelope); err != nil {
		t.Fatal(err)
	}
	var inv mcpbridge.InventoryOutput
	if err := json.Unmarshal([]byte(envelope.Inventory), &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Tools) == 0 {
		t.Fatal("inventory has no tools")
	}
	return reply, inv.Tools[0].Name
}

// TestInitializedIdleShutdownJoinsWaitThenReleasesCredentials: an idle session
// must join Wait during shutdown so Close returns nil and credentials clear.
func TestInitializedIdleShutdownJoinsWaitThenReleasesCredentials(t *testing.T) {
	ctx := testContext(t)
	closeRuns := &atomic.Int32{}
	rt, _, clearFlag := newExchangeRuntime(t, exchangeRPCPeer(t, false, nil), func(f *mcpflow.Transport, closeCtx context.Context) error { closeRuns.Add(1); return f.Close(closeCtx) })
	reply, name := describeAndToolName(t, rt, ctx)
	if !reply.OK || reply.Error != "" {
		t.Fatalf("describe failed: ok=%v err=%q", reply.OK, reply.Error)
	}
	if name == "" {
		t.Fatal("empty tool name")
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("close must be nil after joined Wait, got %v", err)
	}
	if got := closeRuns.Load(); got != 1 {
		t.Fatalf("closeLaunch runs = %d, want 1", got)
	}
	if !clearFlag.Load() {
		t.Fatal("credential material not cleared after joined shutdown")
	}
}

// TestActiveCancelShutdownJoinsAndFailsTheCall: Close must join the in-flight
// call, fail it, still return nil, and then release credentials.
func TestActiveCancelShutdownJoinsAndFailsTheCall(t *testing.T) {
	ctx := testContext(t)
	started := make(chan struct{})
	closeRuns := &atomic.Int32{}
	rt, _, clearFlag := newExchangeRuntime(t, exchangeRPCPeer(t, true, started), func(f *mcpflow.Transport, closeCtx context.Context) error { closeRuns.Add(1); return f.Close(closeCtx) })
	reply, name := describeAndToolName(t, rt, ctx)
	if !reply.OK {
		t.Fatal("describe failed")
	}
	data, err := wire.Encode(mcpbridge.CallInput{Ordinal: 0, Tool: name})
	if err != nil {
		t.Fatal(err)
	}
	callReply := make(chan wire.Reply, 1)
	go func() {
		reply, _ := rt.Handle(ctx, wire.Request{Operation: mcpbridge.OpCall, Data: data})
		callReply <- reply
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("call never started")
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("close must join the active call and return nil, got %v", err)
	}
	select {
	case reply := <-callReply:
		if reply.OK {
			t.Fatal("cancelled call must not be OK")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call never finished")
	}
	if got := closeRuns.Load(); got != 1 {
		t.Fatalf("closeLaunch runs = %d, want 1", got)
	}
	if !clearFlag.Load() {
		t.Fatal("credential material not cleared after joined shutdown")
	}
}

// TestCloseLaunchFailureRetainsAndRetriesInRealComposition: a failing
// closeLaunch must surface ErrBridge, retain credentials, and succeed on retry.
func TestCloseLaunchFailureRetainsAndRetriesInRealComposition(t *testing.T) {
	ctx := testContext(t)
	closeRuns := &atomic.Int32{}
	rt, _, clearFlag := newExchangeRuntime(t, exchangeRPCPeer(t, false, nil), func(f *mcpflow.Transport, closeCtx context.Context) error {
		if closeRuns.Add(1) == 1 {
			return errors.New("synthetic close failure")
		}
		return f.Close(closeCtx)
	})
	if reply, _ := describeAndToolName(t, rt, ctx); !reply.OK {
		t.Fatal("describe failed")
	}
	if err := rt.Close(ctx); !errors.Is(err, mcpbridge.ErrBridge) {
		t.Fatalf("first close must be ErrBridge, got %v", err)
	}
	if clearFlag.Load() {
		t.Fatal("credential material must be retained while closeLaunch fails")
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("retry close must be nil, got %v", err)
	}
	if got := closeRuns.Load(); got != 2 {
		t.Fatalf("closeLaunch runs = %d, want 2", got)
	}
	if !clearFlag.Load() {
		t.Fatal("credential material not cleared after successful retry")
	}
}

// TestInitializationFailureStillJoinsAndReleases: a failed binding must not
// withhold the launch close or the credential release.
func TestInitializationFailureStillJoinsAndReleases(t *testing.T) {
	ctx := testContext(t)
	closeRuns := &atomic.Int32{}
	peer := exchangePeer(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusInternalServerError,
			Status:        "Internal Server Error",
			Header:        http.Header{"Content-Type": []string{"text/plain"}},
			Body:          io.NopCloser(strings.NewReader("junk")),
			ContentLength: 4,
		}, nil
	})
	rt, _, clearFlag := newExchangeRuntime(t, peer, func(f *mcpflow.Transport, closeCtx context.Context) error { closeRuns.Add(1); return f.Close(closeCtx) })
	reply, _ := describeAndToolName(t, rt, ctx)
	if reply.OK {
		t.Fatal("describe must fail when initialize is rejected")
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("close must be nil even after failed initialization, got %v", err)
	}
	if got := closeRuns.Load(); got != 1 {
		t.Fatalf("closeLaunch runs = %d, want 1", got)
	}
	if !clearFlag.Load() {
		t.Fatal("credential material not released after failed binding")
	}
}
