package mcpexchange

import (
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// gatedByteBody serves nothing until its gate opens, then returns one byte and
// an error in the SAME read, independent of the request context. Its Close
// entry is a deterministic oracle: mcpflow's responseBody.Close stores the
// closed flag BEFORE calling source.Close (internal/mcpflow/bodies.go:109-112),
// so observing Close entry proves the bounded body is already closed.
type gatedByteBody struct {
	entered chan struct{}
	gate    chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (b *gatedByteBody) Read(p []byte) (int, error) {
	b.entered <- struct{}{}
	<-b.gate
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, context.Canceled
}

func (b *gatedByteBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// gatedSSEBody serves one unterminated invalid field line, then parks until its
// gate opens and fails the read.
type gatedSSEBody struct {
	entered chan struct{}
	gate    chan struct{}
	served  bool
}

func (b *gatedSSEBody) Read(p []byte) (int, error) {
	if !b.served {
		b.served = true
		return copy(p, []byte("event2: nope")), nil
	}
	b.entered <- struct{}{}
	<-b.gate
	return 0, context.Canceled
}

func (b *gatedSSEBody) Close() error { return nil }

type sameReadBody struct{}

func (sameReadBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, context.Canceled
}

func (sameReadBody) Close() error { return nil }

// TestConsumeEmptySameReadByteAndErrorIsDefinite pins the same-read ordering:
// one read delivering a nonempty byte plus an error is definite evidence, not
// interruption. The previous error-first implementation returned
// errTransportInterrupted here — under an owned stop that became io.EOF. This
// deterministic control is decoder-level because flow's closed conversion
// (internal/mcpflow/bodies.go:92-93) deterministically discards the bytes of any
// read still parked when cancellation lands, so once flow's closed flag is set — provable from the fixture's Close-entry signal — any read returning through the bounded body has its bytes discarded, and the same-read pair itself cannot traverse the real flow body; the Write-level counterpart below pins that end-to-end consequence.
func TestConsumeEmptySameReadByteAndErrorIsDefinite(t *testing.T) {
	if err := consumeEmpty(sameReadBody{}); err != errExchange {
		t.Fatalf("same-read byte+error must be definite errExchange: want %v, got %v", errExchange, err)
	}
}

// TestOwnedStopNotificationParkedReadJoinsAsInterruption pins the Write-level
// notification path under a landed owned stop: flow's closed conversion
// discards the served byte, so the parked read joins as clean interruption.
func TestOwnedStopNotificationParkedReadJoinsAsInterruption(t *testing.T) {
	entered := make(chan struct{}, 1)
	bodyClosed := make(chan struct{})
	gate := make(chan struct{})
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusAccepted, "", "")
		resp.ContentLength = -1
		resp.Body = &gatedByteBody{entered: entered, gate: gate, closed: bodyClosed}
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(gate) }) })
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(context.Background(), notify("notifications/cancelled")) }()
	awaitJoin(t, entered, "notification body never parked past its gate")
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	awaitOwnedStop(t, conn)
	awaitJoin(t, bodyClosed, "flow never entered the bounded body Close")
	// flow's closed flag is proven set (Close entry happens after closed.Store), so the read returns through the closed conversion and the served byte is discarded.
	releaseOnce.Do(func() { close(gate) })
	awaitJoin(t, closeDone, "close did not return")
	select {
	case err := <-writeDone:
		// A blanket-definite conversion would return errExchange here and fail; blanket stopped() passes this but is caught by the wrong-ID and buffered-SSE controls.
		if err != io.EOF {
			t.Fatalf("parked notification read under landed owned stop must join as io.EOF: want %v, got %v", io.EOF, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write was not joined")
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}

// TestOwnedStopDeliversBufferedSSEFieldAsDefinite pins that a buffered
// unterminated invalid field line surfaces as definite evidence even after a
// landed owned stop.
func TestOwnedStopDeliversBufferedSSEFieldAsDefinite(t *testing.T) {
	entered := make(chan struct{}, 1)
	gate := make(chan struct{})
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "text/event-stream", "")
		resp.ContentLength = -1
		resp.Body = &gatedSSEBody{entered: entered, gate: gate}
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(gate) }) })
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(context.Background(), call(t, "x", "tools/list")) }()
	awaitJoin(t, entered, "SSE body never parked past its served line")
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	awaitOwnedStop(t, conn)
	releaseOnce.Do(func() { close(gate) })
	awaitJoin(t, closeDone, "close did not return")
	select {
	case err := <-writeDone:
		// Scanner re-splits its buffered bytes after the read error (bufio post-error split; ScanLines returns the unterminated line), so the buffered invalid field is definite evidence despite the landed owned stop; a blanket stopped() conversion returns io.EOF and fails.
		assertExchangeOwnedStop(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("write was not joined")
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}

// overrunBody serves a complete ID-matching JSON response first, then
// whitespace up to exactly maxResponse served bytes, and only then — on a
// separate read that crosses the budget — returns one extra byte with an
// error. Every byte retained before the crossing read therefore already forms
// valid JSON plus trailing whitespace, independent of any caller read size.
type overrunBody struct {
	payload  []byte
	served   int
	crossing chan struct{}
	once     sync.Once
}

func (b *overrunBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.served < len(b.payload) {
		n := copy(p, b.payload[b.served:])
		b.served += n
		return n, nil
	}
	if b.served < maxResponse {
		n := min(len(p), maxResponse-b.served)
		for i := 0; i < n; i++ {
			p[i] = ' '
		}
		b.served += n
		return n, nil
	}
	b.once.Do(func() { b.crossing <- struct{}{} })
	return 1, context.Canceled
}

func (b *overrunBody) Close() error { return nil }

// The marked body overrun must refuse even when every byte retained before the
// crossing read forms a complete, ID-matching response followed only by
// whitespace: flow discards the entire crossing read (bodies.go:87-90), so
// decodeResponse must never run. All-"x" or suffix-at-limit bodies cannot
// catch the old fallthrough (the discarded crossing read removed the JSON
// suffix, leaving malformed retained bytes); whitespace padding past a short
// complete response makes the retained prefix fully valid, so only the marker
// stands between this body and a decoded success.
func TestLiveOverrunAfterValidPrefixStaysDefinite(t *testing.T) {
	payload := `{"jsonrpc":"2.0","id":"x","result":{"ok":true}}`
	body := &overrunBody{
		payload:  []byte(payload),
		crossing: make(chan struct{}, 1),
	}
	conn, posts := overlapFixture(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "application/json", "")
		resp.ContentLength = -1
		resp.Body = body
		return resp, nil
	}))
	t.Cleanup(func() { _ = conn.Close() })
	writeDone := make(chan error, 1)
	go func() { writeDone <- conn.Write(context.Background(), call(t, "x", "tools/list")) }()
	awaitJoin(t, body.crossing, "crossing overrun read never began")
	select {
	case err := <-writeDone:
		if err != errExchange {
			t.Fatalf("marked overrun over a fully valid retained prefix must stay errExchange: want %v, got %v", errExchange, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write was not joined")
	}
	if posts() != 3 {
		t.Fatal("expected exactly three peer POSTs, no replay")
	}
}
