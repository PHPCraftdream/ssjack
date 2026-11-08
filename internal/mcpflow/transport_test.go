package mcpflow

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type peer func(*http.Request) (*http.Response, error)

func (p peer) RoundTrip(request *http.Request) (*http.Response, error) { return p(request) }

func request(t *testing.T, method, data string) *http.Request {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(data)
	}
	r, err := http.NewRequest(method, "https://fixed.invalid/mcp", body)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func flow(t *testing.T, base http.RoundTripper, cleared *atomic.Int32) *Transport {
	t.Helper()
	transport, err := New(context.Background(), base, func(r *http.Request) (*http.Request, error) {
		owned := r.Clone(r.Context())
		owned.Header.Set("Authorization", "synthetic-private-auth")
		return owned, nil
	}, func() { cleared.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		transport.Close(ctx)
	})
	return transport
}

func reply(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}
}

func TestExchangeOwnsPayloadAndStripsPrivateResponseMetadata(t *testing.T) {
	var cleared atomic.Int32
	original := request(t, http.MethodPost, `{"value":1}`)
	var owned []byte
	transport := flow(t, peer(func(r *http.Request) (*http.Response, error) {
		if r == original || r.GetBody != nil || r.Header.Get("Authorization") != "synthetic-private-auth" {
			t.Fatal("unsafe prepared request")
		}
		owned = r.Body.(*requestBody).data
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != `{"value":1}` {
			t.Fatal("request payload changed")
		}
		out := reply(`{"ok":true}`)
		out.Request, out.Status = r, "200 synthetic-private-reason"
		out.Header.Set("Set-Cookie", "synthetic-private-cookie")
		return out, nil
	}), &cleared)
	response, err := transport.RoundTrip(original)
	if err != nil {
		t.Fatal(err)
	}
	if original.Header.Get("Authorization") != "" || original.GetBody == nil || response.Request != nil || response.Header.Get("Set-Cookie") != "" || response.Status != "200 OK" || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("exchange retained caller/private response state")
	}
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatal("response bytes changed")
	}
	if err := transport.Close(context.Background()); err != nil || cleared.Load() != 1 || transport.Available() {
		t.Fatal("joined close failed")
	}
	if err := transport.Close(context.Background()); err != nil || cleared.Load() != 1 {
		t.Fatal("close was not idempotent")
	}
}

func TestInvalidRequestsNeverReachPeer(t *testing.T) {
	var calls, cleared atomic.Int32
	transport := flow(t, peer(func(*http.Request) (*http.Response, error) { calls.Add(1); return reply("ok"), nil }), &cleared)
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "value") },
		func(r *http.Request) { r.Header.Set("Last-Event-ID", "value") },
		func(r *http.Request) { r.Header["accept"] = []string{"a"}; r.Header["Accept"] = []string{"b"} },
		func(r *http.Request) { r.Header.Set("Accept", strings.Repeat("x", MaxHeaders+1)) },
		func(r *http.Request) { r.ContentLength = MaxRequest + 1 },
		func(r *http.Request) { r.ContentLength = -1 },
		func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.Method = http.MethodPut },
		func(r *http.Request) { r.Trailer = http.Header{"Extra": {"x"}} },
	} {
		r := request(t, http.MethodPost, `{}`)
		change(r)
		if response, err := transport.RoundTrip(r); response != nil || err != ErrExchange {
			t.Fatal("unsafe request was admitted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("refused request reached peer")
	}
	if (&Transport{}).Available() {
		t.Fatal("zero transport was available")
	}
	if _, err := (&Transport{}).RoundTrip(request(t, http.MethodPost, `{}`)); err != ErrExchange {
		t.Fatal("zero transport was used")
	}
}

func TestResponseFailuresNeverExposeDiagnosticsOrRedirect(t *testing.T) {
	for _, mode := range []string{"error", "redirect", "headers", "known-size", "stream-size", "read-error", "status"} {
		t.Run(mode, func(t *testing.T) {
			var calls, cleared atomic.Int32
			transport := flow(t, peer(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				out := reply("synthetic-private-body")
				switch mode {
				case "error":
					return nil, errors.New("synthetic-private-peer-error")
				case "redirect":
					out.StatusCode = 307
					out.Header.Set("Location", "https://other.invalid")
				case "headers":
					out.Header.Set("Mcp-Session-Id", strings.Repeat("x", MaxHeaders+1))
				case "known-size":
					out.ContentLength = MaxResponse + 1
				case "stream-size":
					out.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", MaxResponse+1)))
				case "read-error":
					out.Body = io.NopCloser(errorReader{})
				case "status":
					out.StatusCode = 401
				}
				return out, nil
			}), &cleared)
			response, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
			if mode == "stream-size" || mode == "read-error" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.ReadAll(response.Body)
			}
			if !errors.Is(err, ErrExchange) || err.Error() != ErrExchange.Error() || calls.Load() != 1 {
				t.Fatal("failure leaked diagnostics, redirected or replayed")
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("synthetic private read error") }

func TestActiveMessageAndStreamAdmissionBounds(t *testing.T) {
	var calls, cleared atomic.Int32
	transport := flow(t, peer(func(*http.Request) (*http.Response, error) { calls.Add(1); return reply("ok"), nil }), &cleared)
	var bodies []io.ReadCloser
	for range MaxActive {
		response, err := transport.RoundTrip(request(t, http.MethodPost, `{}`))
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, response.Body)
	}
	if _, err := transport.RoundTrip(request(t, http.MethodPost, `{}`)); err != ErrExchange || calls.Load() != MaxActive {
		t.Fatal("active bound was exceeded")
	}
	for _, body := range bodies {
		body.Close()
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		response, err := transport.RoundTrip(request(t, method, ""))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if _, err := transport.RoundTrip(request(t, method, "")); err != ErrExchange {
			t.Fatal("listening stream or cleanup was replayed")
		}
	}
	transport.mu.Lock()
	transport.messages = MaxMessages
	transport.mu.Unlock()
	if _, err := transport.RoundTrip(request(t, http.MethodPost, `{}`)); err != ErrExchange {
		t.Fatal("message budget was exceeded")
	}
}
