package mcpflow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// requestWithContext attaches ctx to a fresh fixture request so the peer
// observes exactly this test's cancellation.
func requestWithContext(t *testing.T, ctx context.Context, method, data string) *http.Request {
	t.Helper()
	return request(t, method, data).WithContext(ctx)
}

// TestDefiniteVsInterruptedRefusalClassification pins the machine-readable split
// between definite peer-response refusals and transport interruption, and keeps
// every returned error satisfying errors.Is(err, ErrExchange) unchanged.
func TestDefiniteVsInterruptedRefusalClassification(t *testing.T) {
	t.Run("invalid headers", func(t *testing.T) {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			out := reply("unused")
			out.Header["Content-Type"] = []string{"application/json", "application/json"}
			return out, nil
		}), &cleared)
		_, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if !errors.Is(err, ErrExchange) || !DefiniteResponse(err) || err.Error() != ErrExchange.Error() {
			t.Fatal("definite refusal was not classified as marked with unchanged fixed text")
		}
	})
	t.Run("declared size", func(t *testing.T) {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			out := reply("unused")
			out.ContentLength = MaxResponse + 1
			return out, nil
		}), &cleared)
		_, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if !errors.Is(err, ErrExchange) || !DefiniteResponse(err) || err.Error() != ErrExchange.Error() {
			t.Fatal("definite refusal was not classified as marked with unchanged fixed text")
		}
	})
	t.Run("non-2xx status", func(t *testing.T) {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			out := reply("unused")
			out.StatusCode = 500
			return out, nil
		}), &cleared)
		_, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if !errors.Is(err, ErrExchange) || !DefiniteResponse(err) || err.Error() != ErrExchange.Error() {
			t.Fatal("definite refusal was not classified as marked with unchanged fixed text")
		}
	})
	t.Run("valid exchange", func(t *testing.T) {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) { return reply(`{"ok":true}`), nil }), &cleared)
		response, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		if err != nil || string(data) != `{"ok":true}` || DefiniteResponse(err) {
			t.Fatal("valid exchange was misclassified or body changed")
		}
	})
	t.Run("cancellation only", func(t *testing.T) {
		var cleared atomic.Int32
		blocked := make(chan struct{})
		transport := flow(t, peer(func(r *http.Request) (*http.Response, error) {
			close(blocked)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}), &cleared)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel) // registered first, so cleanup LIFO runs the join cleanup below before this cancel
		done := make(chan error, 1)
		finished := make(chan struct{})
		t.Cleanup(func() {
			select { // bounded join (cleanup LIFO: this runs before the registered cancel cleanup; the failure paths below cancel explicitly before Fatal)
			case <-finished:
			case <-time.After(2 * time.Second):
				t.Errorf("owned RoundTrip goroutine did not exit after cancellation")
			}
		})
		go func() {
			defer close(finished)
			_, err := transport.RoundTrip(requestWithContext(t, ctx, http.MethodPost, `{}`))
			// the result send precedes the deferred close(finished): receiving done does not prove the close ran; the cleanup join waits for finished itself.
			done <- err
		}()
		select {
		case <-blocked:
		case <-time.After(2 * time.Second):
			cancel() // unblock the parked peer before failing; the join cleanup then waits for the goroutine
			t.Fatal("peer never entered; cancellation ownership cannot be tested")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, ErrExchange) || DefiniteResponse(err) || err.Error() != ErrExchange.Error() {
				t.Fatal("cancellation-only failure was not classified as an unmarked interruption with unchanged text")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled exchange did not return")
		}
	})
	t.Run("body overrun", func(t *testing.T) {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			return reply(strings.Repeat("x", MaxResponse+2)), nil
		}), &cleared)
		response, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(response.Body)
		if !errors.Is(err, ErrExchange) || !DefiniteResponse(err) || err.Error() != ErrExchange.Error() {
			t.Fatal("definite refusal was not classified as marked with unchanged fixed text")
		}
	})
	t.Run("interrupted body", func(t *testing.T) {
		var cleared atomic.Int32
		transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
			out := reply("")
			out.Body = io.NopCloser(io.MultiReader(strings.NewReader("partial"), errReader{}))
			return out, nil
		}), &cleared)
		response, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(response.Body)
		if !errors.Is(err, ErrExchange) || DefiniteResponse(err) || err.Error() != ErrExchange.Error() {
			t.Fatal("interrupted body read was not classified as an unmarked interruption with unchanged fixed text")
		}
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, context.Canceled }
