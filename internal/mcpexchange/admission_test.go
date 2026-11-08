package mcpexchange

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// countingPeer counts EVERY POST, including handshake ones, serves the real
// handshake itself, and delegates all other bodies to the fallback transport.
type countingPeer struct {
	posts atomic.Int32
	next  roundTripFunc
}

func (p *countingPeer) serve(request *http.Request) (*http.Response, error) {
	p.posts.Add(1)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	if method := request.Method; method != http.MethodPost {
		return response(http.StatusMethodNotAllowed, "text/plain", "private"), nil
	}
	if len(body) == 0 || request.ContentLength <= 0 {
		return response(http.StatusBadRequest, "text/plain", "private"), nil
	}
	if bytes.Contains(body, []byte(`"method":"initialize"`)) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-06-18"}}`), nil
	}
	if bytes.Contains(body, []byte(`"method":"notifications/initialized"`)) {
		return response(http.StatusAccepted, "", ""), nil
	}
	return p.next(request)
}

func TestNotificationsUseOnlyEmptyAcceptedPost(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusAccepted, "", ""), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), call(t, "init", "initialize")), nil, "initialize failed")
	mustRead(t, conn)
	mustWrite(t, conn.Write(context.Background(), notify("notifications/initialized")), nil, "notification failed")
	if peer.posts.Load() != 2 {
		t.Fatal("initialize plus notification must be exactly two peer POSTs")
	}
	_ = conn.Close()
}

func TestRepeatedInitializeIsRefusedWithoutPeerContact(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	mustWrite(t, conn.Write(context.Background(), call(t, "init", "initialize")), errExchange, "repeated initialize accepted")
	if peer.posts.Load() != before {
		t.Fatal("refused initialize contacted the peer")
	}
	_ = conn.Close()
}

func TestRepeatedInitializedIsRefusedWithoutPeerContact(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	mustWrite(t, conn.Write(context.Background(), notify("notifications/initialized")), errExchange, "repeated notification accepted")
	if peer.posts.Load() != before {
		t.Fatal("refused notification contacted the peer")
	}
	_ = conn.Close()
}

func TestInitializedBeforeInitializeIsRefusedWithoutPeerContact(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusAccepted, "", ""), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), notify("notifications/initialized")), errExchange, "notification before initialize accepted")
	if peer.posts.Load() != 0 {
		t.Fatal("refused notification contacted the peer")
	}
	_ = conn.Close()
}

func TestOwnedStopAfterCloseWritesEOFWithoutPeerContact(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	_ = conn.Close()
	if err := conn.Write(context.Background(), call(t, "x", "tools/list")); err != io.EOF {
		t.Fatalf("owned stop after close must report io.EOF, got %v", err)
	}
	if peer.posts.Load() != before {
		t.Fatal("owned stop contacted the peer")
	}
}

func TestOwnedStopKeepsInvalidMethodsRefused(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	_ = conn.Close()
	if err := conn.Write(context.Background(), call(t, "x", "resources/read")); err != errExchange {
		t.Fatalf("invalid method after close must stay errExchange, got %v", err)
	}
	oversized := call(t, "x", "tools/list")
	oversized.Params = json.RawMessage(strings.Repeat("a", maxRequest-255))
	if err := conn.Write(context.Background(), oversized); err != errExchange {
		t.Fatalf("oversized params after close must stay errExchange, got %v", err)
	}
	if peer.posts.Load() != before {
		t.Fatal("refused writes contacted the peer")
	}
}

func TestCallerCancellationBeforeAdmissionStaysErrExchange(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := conn.Write(ctx, call(t, "x", "tools/list")); err != errExchange {
		t.Fatalf("caller cancellation must stay errExchange, got %v", err)
	}
	if peer.posts.Load() != before {
		t.Fatal("cancelled write contacted the peer")
	}
	_ = conn.Close()
}

// TestAdmitClassifiesOwnedStopAndStateFailuresAtomically pins the locked,
// single-decision classification: previously Write tested isClosed and then
// admitted separately, so cancellation between them misreported an owned stop
// as a sticky admission refusal; that interleaving can no longer occur.
func TestAdmitClassifiesOwnedStopAndStateFailuresAtomically(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	_ = conn.Close()
	admitted, ownedStop := conn.admit("tools/list", false)
	if admitted || !ownedStop {
		t.Fatalf("owned stop of admissible method: admitted=%v ownedStop=%v", admitted, ownedStop)
	}
	admitted, ownedStop = conn.admit("initialize", false)
	if admitted || ownedStop {
		t.Fatalf("repeated initialize is genuine state failure: admitted=%v ownedStop=%v", admitted, ownedStop)
	}
	admitted, ownedStop = conn.admit("resources/read", false)
	if admitted || ownedStop {
		t.Fatalf("unlisted method is genuine method failure: admitted=%v ownedStop=%v", admitted, ownedStop)
	}
}

// TestWriteKeepsStateFailuresStickyAfterOwnedStop pins that genuine state and
// method refusals stay errExchange after close while an admissible method
// reports io.EOF, with no peer contact in any case.
func TestWriteKeepsStateFailuresStickyAfterOwnedStop(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	_ = conn.Close()
	mustWrite(t, conn.Write(context.Background(), call(t, "init", "initialize")), errExchange, "state failure after close must stay errExchange")
	mustWrite(t, conn.Write(context.Background(), call(t, "x", "resources/read")), errExchange, "method failure after close must stay errExchange")
	mustWrite(t, conn.Write(context.Background(), call(t, "x", "tools/list")), io.EOF, "owned stop of admissible method must be io.EOF")
	if peer.posts.Load() != before {
		t.Fatal("refused writes contacted the peer")
	}
}

// Layer boundary: JSON complete-evidence overlap is pinned by
// TestOwnedStopKeepsWrongIDDecodeDefinite; SSE definite evidence surfaces under
// owned stop through Scanner's post-error split of buffered bytes and is pinned
// by TestOwnedStopDeliversBufferedSSEFieldAsDefinite in shutdown_evidence_test.go;
// a parked stream with nothing buffered stays clean interruption per the body
// test, which a blanket-definite conversion would fail. Blanket stopped()
// conversion fails the wrong-ID, buffered-SSE, and flow-rejection controls.

// TestDecodeClassifiesDefiniteEvidenceAndInterruption pins the decode-stage
// classification: complete evidence is definite (errExchange) and read
// failure without evidence is interruption (errTransportInterrupted).
func TestDecodeClassifiesDefiniteEvidenceAndInterruption(t *testing.T) {
	expected, err := expectedID([]byte(`{"id":"x","method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeJSONResponse(strings.NewReader(`{"jsonrpc":"2.0","id":"wrong-id","result":{}}`), expected); err != errExchange {
		t.Fatalf("complete wrong-ID evidence must be definite errExchange, got %v", err)
	}
	if _, err := decodeJSONResponse(strings.NewReader(""), expected); err != errExchange {
		t.Fatalf("empty body must be definite errExchange, got %v", err)
	}
	if _, err := decodeJSONResponse(failRead{}, expected); err != errTransportInterrupted {
		t.Fatalf("read failure must be interrupted, got %v", err)
	}
	if _, err := decodeSSEResponse(strings.NewReader("data: {}\n\n"), expected); err != errExchange {
		t.Fatalf("malformed SSE evidence must be definite errExchange, got %v", err)
	}
	if _, err := decodeSSEResponse(failRead{}, expected); err != errTransportInterrupted {
		t.Fatalf("stream read failure must be interrupted, got %v", err)
	}
	if err := consumeEmpty(strings.NewReader("x")); err != errExchange {
		t.Fatalf("non-empty notification body must be definite errExchange, got %v", err)
	}
	if err := consumeEmpty(failRead{}); err != errTransportInterrupted {
		t.Fatalf("notification read failure must be interrupted, got %v", err)
	}
}

type failRead struct{}

func (failRead) Read([]byte) (int, error) { return 0, context.Canceled }

// TestDefiniteResponseIDMismatchStaysErrExchangeOnLiveConnection pins that
// complete wrong-ID evidence on a live connection stays sticky errExchange;
// the definite branch never consults connection state.
func TestDefiniteResponseIDMismatchStaysErrExchangeOnLiveConnection(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"wrong-id","result":{}}`), nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	mustWrite(t, conn.Write(context.Background(), call(t, "x", "tools/list")), errExchange, "definite response-ID mismatch must stay errExchange")
	if peer.posts.Load() != before+1 {
		t.Fatal("unexpected peer POST count")
	}
	_ = conn.Close()
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, context.Canceled }

// TestLiveConnectionBodyReadFailureStaysErrExchange pins that the interruption
// sentinel never escapes Write: a body read failure on a live connection stays
// sticky errExchange, not io.EOF.
func TestLiveConnectionBodyReadFailureStaysErrExchange(t *testing.T) {
	peer := &countingPeer{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := response(http.StatusOK, "application/json", "{}")
		body.Body = io.NopCloser(failReader{})
		return body, nil
	})}
	transport, _ := testTransport(t, peer.serve)
	conn := negotiatedConnection(t, transport)
	before := peer.posts.Load()
	mustWrite(t, conn.Write(context.Background(), call(t, "x", "tools/call")), errExchange, "live-connection body read failure must stay errExchange")
	if peer.posts.Load() != before+1 {
		t.Fatal("unexpected peer POST count")
	}
	_ = conn.Close()
}
