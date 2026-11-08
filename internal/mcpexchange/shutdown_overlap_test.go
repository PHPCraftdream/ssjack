package mcpexchange

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// heldCloseBody parks mcpflow's rejection cleanup inside Close so the test can
// cancel the owned context while the rejected response is being torn down.
type heldCloseBody struct {
	entered chan struct{}
	release chan struct{}
}

func (b *heldCloseBody) Read([]byte) (int, error) { return 0, io.EOF }

func (b *heldCloseBody) Close() error {
	b.entered <- struct{}{}
	<-b.release
	return nil
}

// stagedBody serves a prefix, parks until its context is cancelled, then
// returns a final error.
type stagedBody struct {
	ctx   context.Context
	data  []byte
	off   int
	held  chan struct{}
	final error
}

func (b *stagedBody) Read(p []byte) (int, error) {
	if b.off < len(b.data) {
		n := copy(p, b.data[b.off:])
		b.off += n
		return n, nil
	}
	select {
	case b.held <- struct{}{}:
	default:
	}
	<-b.ctx.Done()
	return 0, b.final
}

func (b *stagedBody) Close() error { return nil }

// overlapFixture performs the real handshake (two peer POSTs) and delegates
// the next POST to next; each overlap test asserts three POSTs total (no replay).
func overlapFixture(t *testing.T, next roundTripFunc) (*connection, func() int32) {
	t.Helper()
	peer := &countingPeer{next: next}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	return conn, func() int32 { return peer.posts.Load() }
}

// awaitJoin waits for a signal with a timeout, failing the test on stall.
func awaitJoin(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(what)
	}
}

// assertExchangeOwnedStop asserts the joined write result is EXACTLY errExchange.
func assertExchangeOwnedStop(t *testing.T, err error) {
	t.Helper()
	if err != errExchange {
		t.Fatalf("in-flight owned-stop write must be errExchange: want %v, got %v", errExchange, err)
	}
}

// awaitOwnedStop blocks until the connection's owned cancellation has actually
// landed, proving shutdown precedes any subsequent gate release.
func awaitOwnedStop(t *testing.T, c *connection) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !c.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("owned stop never landed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOwnedStopKeepsFlowRejectedStatusDefinite(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusInternalServerError, "text/plain", "peer refused the call")
		resp.Body = &heldCloseBody{entered: entered, release: release}
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(context.Background(), call(t, "x", "tools/call")) }()
	awaitJoin(t, entered, "flow rejection teardown never parked in body Close")
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	// Owned cancellation has landed before the rejected-body cleanup is released.
	awaitOwnedStop(t, conn)
	releaseOnce.Do(func() { close(release) })
	awaitJoin(t, closeDone, "close did not return")
	select {
	case err := <-writeDone:
		assertExchangeOwnedStop(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("write was not joined")
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}

func TestOwnedStopKeepsDeclaredSizeRejectionDefinite(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "application/json", "")
		resp.ContentLength = maxResponse + 1
		resp.Body = &heldCloseBody{entered: entered, release: release}
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(context.Background(), call(t, "x", "tools/call")) }()
	awaitJoin(t, entered, "declared-size rejection teardown never parked in body Close")
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	// Owned cancellation has landed before the rejected-body cleanup is released.
	awaitOwnedStop(t, conn)
	releaseOnce.Do(func() { close(release) })
	awaitJoin(t, closeDone, "close did not return")
	select {
	case err := <-writeDone:
		assertExchangeOwnedStop(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("write was not joined")
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}

func TestLiveSSETokenLimitStaysDefinite(t *testing.T) {
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "text/event-stream", "data: "+strings.Repeat("a", maxResponse)+"\n\n")
		resp.ContentLength = -1
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Write(context.Background(), call(t, "x", "tools/list")); err != errExchange {
		t.Fatalf("live SSE token-limit overrun must be errExchange: want %v, got %v", errExchange, err)
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}

func TestOwnedStopKeepsWrongIDDecodeDefinite(t *testing.T) {
	// Counterfactual: the staged body returns a non-EOF unmarked read error
	// after the complete wrong-ID payload, so the exchange ALWAYS takes its
	// read-error branch. Under the old clear-before-validation ordering the
	// zeroed body failed json.Valid, classified interruption, and returned
	// io.EOF here under the landed owned stop; this test fails that. The
	// current fixed decoder classifies the complete syntactic evidence as
	// definite errExchange on every schedule.
	payload := `{"jsonrpc":"2.0","id":"wrong-id","result":{}}`
	held := make(chan struct{}, 1)
	conn, posts := overlapFixture(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "application/json", "")
		resp.ContentLength = int64(len(payload))
		resp.Body = &stagedBody{ctx: r.Context(), data: []byte(payload), held: held, final: context.Canceled}
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(context.Background(), call(t, "x", "tools/list")) }()
	awaitJoin(t, held, "decode body never parked past its served payload")
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	awaitJoin(t, closeDone, "close did not return")
	select {
	case err := <-writeDone:
		assertExchangeOwnedStop(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("write was not joined")
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}

// flow's marked overrun is pinned in internal/mcpflow/classification_test.go; this test
// pins the exchange-side oversize outcome through Write.
func TestLiveOversizedBodyStaysDefinite(t *testing.T) {
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "application/json", strings.Repeat("x", maxResponse+2))
		resp.ContentLength = -1
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Write(context.Background(), call(t, "x", "tools/list")); err != errExchange {
		t.Fatalf("live oversized body must be errExchange: want %v, got %v", errExchange, err)
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}
