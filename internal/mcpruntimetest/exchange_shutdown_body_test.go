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

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpexchange"
	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// Owned cancellation arriving after HTTP headers, while a JSON or SSE response
// body is still mid-read with the caller context live, must decode as io.EOF
// (connection.go decode stage maps owned termination to stopped()) so the
// pinned SDK Wait ignores it (conn.go:497–506); a sticky errExchange here
// would withhold closeLaunch. These tests pin that decode-stage boundary.

// stalledBody parks Read until the request context is cancelled, signalling
// the stalled channel exactly once on the first Read attempt. In SSE mode a
// keepalive prefix is consumed first so decodeSSEResponse is entered.
type stalledBody struct {
	done    <-chan struct{}
	stalled chan struct{}
	once    sync.Once
}

func (b *stalledBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.stalled) })
	<-b.done
	return 0, context.Canceled
}

func (b *stalledBody) Close() error { return nil }

// stalledBodyPeer mirrors exchangeRPCPeer's handshake, but parks every
// tools/call response body mid-read after headers are written. It returns the
// channel closed on the first parked Read.
func stalledBodyPeer(t *testing.T, sse bool) (exchangePeer, chan struct{}) {
	t.Helper()
	stalled := make(chan struct{})
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
			contentType := "application/json"
			body := io.ReadCloser(&stalledBody{done: r.Context().Done(), stalled: stalled})
			if sse {
				contentType = "text/event-stream"
				body = io.NopCloser(io.MultiReader(strings.NewReader(": keepalive\n"), body))
			}
			return &http.Response{
				StatusCode:    http.StatusOK,
				Status:        "OK",
				Header:        http.Header{"Content-Type": []string{contentType}},
				Body:          body,
				ContentLength: 4096,
			}, nil
		}
		return emptyResponse(http.StatusMethodNotAllowed), nil
	}, stalled
}

// runBodyStallShutdown drives a tools/call whose response body is parked
// mid-read, then shuts down via owned cancellation: rt.Close must be nil,
// closeLaunch exactly once, credentials cleared, and the call failed.
func runBodyStallShutdown(t *testing.T, sse bool) {
	t.Helper()
	ctx := testContext(t)
	closeRuns := &atomic.Int32{}
	peer, stalled := stalledBodyPeer(t, sse)
	clearFlag := &atomic.Bool{}
	flow, err := mcpflow.New(context.Background(), peer, func(r *http.Request) (*http.Request, error) { return r, nil }, func() { clearFlag.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup closes rt before flow, so a parked body read always unblocks.
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
	rt, err := mcpbridge.Open(context.Background(), []mcpbridge.UpstreamHandle{&stubHandle{transport: exch}}, mustGuard(t), func(closeCtx context.Context) error {
		closeRuns.Add(1)
		return flow.Close(closeCtx)
	}, bindings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = rt.Close(cctx)
	})
	reply, name := describeAndToolName(t, rt, ctx)
	if !reply.OK || name == "" {
		t.Fatalf("describe failed: ok=%v name=%q", reply.OK, name)
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
	case <-stalled:
	case <-time.After(2 * time.Second):
		t.Fatal("response body read never parked")
	}
	if err := rt.Close(ctx); err != nil {
		t.Fatalf("close must be nil while body read is parked, got %v", err)
	}
	select {
	case reply := <-callReply:
		if reply.OK {
			t.Fatal("call parked mid-body must not be OK after shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call never finished")
	}
	if got := closeRuns.Load(); got != 1 {
		t.Fatalf("closeLaunch runs = %d, want 1", got)
	}
	if !clearFlag.Load() {
		t.Fatal("credential material not cleared after body-stall shutdown")
	}
}

func TestOwnedCancelDuringJSONBodyReadJoinsShutdown(t *testing.T) {
	runBodyStallShutdown(t, false)
}

func TestOwnedCancelDuringSSEBodyReadJoinsShutdown(t *testing.T) {
	runBodyStallShutdown(t, true)
}
