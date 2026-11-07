package mcpflow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type heldBody struct {
	started, closed, release chan struct{}
	readOnce, closeOnce      sync.Once
	failClose                bool
}

func (b *heldBody) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.started) })
	<-b.release
	return 0, io.EOF
}
func (b *heldBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	if b.failClose {
		return errors.New("synthetic-private-close-error")
	}
	return nil
}

func wait(t *testing.T, event <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-event:
	case <-ctx.Done():
		t.Fatal("controlled I/O event did not arrive")
	}
}

func TestCloseWaitsForActiveReadAndRetainsMaterialOnIncompleteJoin(t *testing.T) {
	var cleared atomic.Int32
	body := &heldBody{started: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(body.release) })
	transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
		out := reply("unused")
		out.Body = body
		return out, nil
	}), &cleared)
	response, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan struct{})
	go func() { defer close(readDone); var byte [1]byte; response.Body.Read(byte[:]) }()
	wait(t, body.started)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if transport.Close(cancelled) != ErrExchange {
		t.Fatal("unfinished read reported a joined close")
	}
	wait(t, body.closed)
	if cleared.Load() != 0 || transport.Available() {
		t.Fatal("unfinished close cleared private material or permitted reuse")
	}
	release.Do(func() { close(body.release) })
	wait(t, readDone)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := transport.Close(ctx); err != nil || cleared.Load() != 1 {
		t.Fatal("completed join failed to clear material once")
	}
}

func TestCloseJoinsSourceReadBeforePeerEffects(t *testing.T) {
	var calls, cleared atomic.Int32
	body := &heldBody{started: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(body.release) })
	transport := flow(t, peer(func(*http.Request) (*http.Response, error) { calls.Add(1); return reply("unexpected"), nil }), &cleared)
	r := request(t, http.MethodPost, `{}`)
	r.Body = body
	finished := make(chan struct{})
	result := make(chan error, 1)
	go func() { defer close(finished); _, err := transport.RoundTrip(r); result <- err }()
	wait(t, body.started)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if transport.Close(cancelled) != ErrExchange {
		t.Fatal("unfinished source read reported a joined close")
	}
	wait(t, body.closed)
	if cleared.Load() != 0 || calls.Load() != 0 {
		t.Fatal("source cancellation cleared material or reached peer before join")
	}
	release.Do(func() { close(body.release) })
	wait(t, finished)
	if <-result != ErrExchange {
		t.Fatal("cancelled source did not return the fixed failure")
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if transport.Close(ctx) != nil || cleared.Load() != 1 || calls.Load() != 0 {
		t.Fatal("source join lost cleanup or allowed peer effects")
	}
}

func TestCloseFailureNeverClearsMaterialOrReportsSuccess(t *testing.T) {
	var cleared atomic.Int32
	body := &heldBody{started: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{}), failClose: true}
	transport := flow(t, peer(func(*http.Request) (*http.Response, error) { out := reply("unused"); out.Body = body; return out, nil }), &cleared)
	if _, err := transport.RoundTrip(request(t, http.MethodPost, `{}`)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if transport.Close(ctx) != ErrExchange || cleared.Load() != 0 || transport.Available() {
		t.Fatal("failed source close was presented as safe cleanup")
	}
}

func TestParentCancellationClosesUnconsumedSDKStyleResponse(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	var cleared atomic.Int32
	body := &heldBody{started: make(chan struct{}), closed: make(chan struct{}), release: make(chan struct{})}
	transport, err := New(parent, peer(func(*http.Request) (*http.Response, error) { out := reply("unused"); out.Body = body; return out, nil }), func(r *http.Request) (*http.Request, error) { return r, nil }, func() { cleared.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if _, err := transport.RoundTrip(request(t, http.MethodDelete, "")); err != nil {
		t.Fatal(err)
	}
	cancel()
	wait(t, body.closed)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if transport.Close(ctx) != nil || cleared.Load() != 1 {
		t.Fatal("unconsumed response prevented joined cleanup")
	}
}

func TestExactBodyBoundsAndUnsupportedListeningStatus(t *testing.T) {
	for _, size := range []int{MaxRequest, MaxRequest + 1} {
		var calls, cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return reply(strings.Repeat("x", MaxResponse)), nil
		}), &cleared)
		response, err := transport.RoundTrip(request(t, http.MethodPost, strings.Repeat("x", size)))
		if size > MaxRequest {
			if err != ErrExchange || calls.Load() != 0 {
				t.Fatal("oversized request reached peer")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		if err != nil || len(data) != MaxResponse {
			t.Fatal("exact body bounds were truncated")
		}
	}
	for _, status := range []int{404, 405} {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			out := reply("private error body")
			out.StatusCode = status
			return out, nil
		}), &cleared)
		response, err := transport.RoundTrip(request(t, http.MethodGet, ""))
		if err != nil || response.StatusCode != status || response.Body != http.NoBody {
			t.Fatal("optional listening status exposed a response body")
		}
	}
}

func TestLeaseAndConstructorRefusal(t *testing.T) {
	var cleared atomic.Int32
	transport := flow(t, peer(func(*http.Request) (*http.Response, error) { return reply("ok"), nil }), &cleared)
	deadline, ok := transport.ctx.Deadline()
	if !ok || time.Until(deadline) > MaxLease || time.Until(deadline) <= 0 {
		t.Fatal("exchange lifetime was not bounded")
	}
	if result, err := New(nil, nil, nil, nil); result != nil || err != ErrExchange {
		t.Fatal("invalid constructor granted a transport")
	}
}
