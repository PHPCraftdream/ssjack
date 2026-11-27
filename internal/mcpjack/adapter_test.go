package mcpjack

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

type signer struct {
	private ed25519.PrivateKey
	public  []byte
	calls   int
}

func (s *signer) Sign(m []byte) ([]byte, error) { s.calls++; return ed25519.Sign(s.private, m), nil }
func (s *signer) PublicKey() []byte             { return append([]byte(nil), s.public...) }
func (s *signer) KID() string                   { return jack.KeyID(s.public) }

type routeFunc func(*http.Request) (*http.Response, error)

func (f routeFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fixture(t *testing.T, route http.RoundTripper) (*Adapter, *signer) {
	t.Helper()
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	ad, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return ad, s
}

func TestCallVerifiesAndRefusesJackToolsBeforeNetwork(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	var calls int
	var requestAuth string
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		requestAuth = req.Header.Get("Jack-Auth")
		body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ok":true}}}`)
		auth, _ := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
		ts := time.Now().Unix()
		sig := ed25519.Sign(serverPriv, []byte(jack.ResponseSigningString(200, auth.Sig, jack.KeyID(serverPub), ts, body)))
		h := make(http.Header)
		h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(serverPub), TS: ts, Sig: jack.EncodeBase64URL(sig)}))
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err = a.Call(context.Background(), "svc.run", nil, &out); err != nil || !out.OK || s.calls != 1 || requestAuth == "" {
		t.Fatalf("valid call failed: err=%v out=%+v signer calls=%d request auth present=%t", err, out, s.calls, requestAuth != "")
	}
	typ := reflect.TypeOf(*a)
	exportedFields := 0
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).PkgPath == "" {
			exportedFields++
		}
	}
	if exportedFields != 0 {
		t.Fatalf("Adapter has %d exported fields", exportedFields)
	}
	for _, name := range []string{"jack.enroll", "jack.whoami", "jack.key.rotate", "jack.server.key", "jack.admin.x", "jack.other"} {
		if err = a.Call(context.Background(), name, nil, nil); err != ErrForbiddenTool {
			t.Fatalf("%s err %v", name, err)
		}
	}
	if calls != 1 {
		t.Fatalf("route calls %d", calls)
	}
}
func TestCallClassifiesSignedRejection(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		body := []byte(`{"error":{"message":"sensitive server message"}}`)
		auth, _ := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
		ts := time.Now().Unix()
		sig := ed25519.Sign(serverPriv, []byte(jack.ResponseSigningString(403, auth.Sig, jack.KeyID(serverPub), ts, body)))
		h := make(http.Header)
		h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(serverPub), TS: ts, Sig: jack.EncodeBase64URL(sig)}))
		return &http.Response{StatusCode: 403, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Call(context.Background(), "svc.run", nil, nil)
	if err != ErrSignedRejection || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("err %v", err)
	}
}
func TestRouteFailureOneAttemptAndNilRoute(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	count := 0
	route := routeFunc(func(*http.Request) (*http.Response, error) { count++; return nil, errors.New("secret route detail") })
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: pub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrRoute || count != 1 || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err=%v count=%d", err, count)
	}
	if _, err = New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: pub, Signer: &signer{private: priv, public: pub}, Route: nil, Timeout: time.Second}); err != ErrInvalidConfig {
		t.Fatalf("nil route accepted: %v", err)
	}
}
func TestHTTPPolicyAndRedirectRefusal(t *testing.T) {
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	loopbackCalls := 0
	loopback := routeFunc(func(req *http.Request) (*http.Response, error) {
		loopbackCalls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://elsewhere.invalid"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: req}, nil
	})
	if _, err := New(Config{Endpoint: "http://127.0.0.1:2345/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: loopback, Timeout: time.Second}); err != nil {
		t.Fatalf("literal loopback HTTP refused: %v", err)
	}
	if _, err := New(Config{Endpoint: "http://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: loopback, Timeout: time.Second}); err != ErrInvalidConfig {
		t.Fatalf("non-loopback HTTP accepted: %v", err)
	}
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: loopback, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrRoute || loopbackCalls != 1 {
		t.Fatalf("redirect class = %v, route calls = %d", err, loopbackCalls)
	}
}

func TestUnsigned401AndNilTypedRoute(t *testing.T) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	var nilRoute *routePointer
	if _, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: &signer{private: userPriv, public: userPub}, Route: nilRoute, Timeout: time.Second}); err != ErrInvalidConfig {
		t.Fatalf("typed nil route accepted: %v", err)
	}
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("secret")), Request: req}, nil
	})
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrUnsigned401 {
		t.Fatalf("401 class = %v", err)
	}
}

func TestMissingResponseSignatureIsUnverified(t *testing.T) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ok":true}}}`)), Request: req}, nil
	})
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrUnverified {
		t.Fatalf("missing response signature class = %v, want %v", err, ErrUnverified)
	}
}

type routePointer struct{}

func (*routePointer) RoundTrip(*http.Request) (*http.Response, error) { panic("typed nil route used") }

func TestValidSignedResponseFromUnpinnedKeyIsRejected(t *testing.T) {
	pinnedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ok":true}}}`)
		auth, _ := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
		ts := time.Now().Unix()
		sig := ed25519.Sign(otherPriv, []byte(jack.ResponseSigningString(200, auth.Sig, jack.KeyID(otherPub), ts, body)))
		h := make(http.Header)
		h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(otherPub), TS: ts, Sig: jack.EncodeBase64URL(sig)}))
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	})
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: pinnedPub, Signer: s, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrUntrustedSigner {
		t.Fatalf("unpinned signer class = %v", err)
	}
}

func TestBadSignatureAndOversizeAreFixed(t *testing.T) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	for _, tc := range []struct {
		name     string
		response func(*http.Request) (*http.Response, error)
		want     error
	}{
		{"bad signature", func(req *http.Request) (*http.Response, error) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ok":true}}}`)
			auth, _ := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
			ts := time.Now().Unix()
			sig := ed25519.Sign(wrongPriv, []byte(jack.ResponseSigningString(200, auth.Sig, jack.KeyID(serverPub), ts, body)))
			h := make(http.Header)
			h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: jack.KeyID(serverPub), TS: ts, Sig: jack.EncodeBase64URL(sig)}))
			return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
		}, ErrUnverified},
		{"oversize", func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+20))), Request: req}, nil
		}, ErrOversize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: routeFunc(tc.response), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			err = a.Call(context.Background(), "svc.run", nil, nil)
			if err != tc.want {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestLimitedBodyExactResponseLimitBoundary(t *testing.T) {
	wrap := func(size int) io.ReadCloser {
		t.Helper()
		limiter := &responseLimit{next: routeFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size))), Request: req}, nil
		})}
		resp, err := limiter.RoundTrip(&http.Request{})
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		body, ok := resp.Body.(*limitedBody)
		if !ok {
			t.Fatalf("body type = %T, want adapter limitedBody", resp.Body)
		}
		return body
	}

	body := wrap(maxResponseBytes)
	data, err := io.ReadAll(body)
	if err != nil || len(data) != maxResponseBytes {
		t.Fatalf("exact limit read: bytes=%d err=%v", len(data), err)
	}

	body = wrap(maxResponseBytes + 1)
	data, err = io.ReadAll(body)
	if len(data) != maxResponseBytes+1 || !errors.Is(err, errResponseLimit) {
		t.Fatalf("over limit read: bytes=%d err=%v", len(data), err)
	}
}

func TestCallTimeoutCancelsCallerRouteContext(t *testing.T) {
	observed := make(chan error, 1)
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		observed <- req.Context().Err()
		return nil, errors.New("fixed route error")
	})
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: pub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Call(context.Background(), "svc.run", nil, nil) }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	select {
	case ctxErr := <-observed:
		if ctxErr != context.DeadlineExceeded {
			t.Fatalf("route context error = %v", ctxErr)
		}
	case <-deadline.C:
		t.Fatal("route did not observe context cancellation")
	}
	select {
	case callErr := <-done:
		if callErr != ErrRoute {
			t.Fatalf("call error = %v, want %v", callErr, ErrRoute)
		}
	case <-deadline.C:
		t.Fatal("call did not return after route cancellation")
	}
}

func TestSeedSignerInputOwnershipCloseAndPublicKeyCopy(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	original := append([]byte(nil), seed...)
	s, err := NewSeedSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(seed, original) {
		t.Fatal("constructor changed caller-owned seed")
	}
	pub := s.PublicKey()
	pub[0] ^= 0xff
	if equalBytes(pub, s.public) {
		t.Fatal("PublicKey returned signer-owned storage")
	}
	privateStorage := s.private
	s.Close()
	if !allZero(privateStorage) {
		t.Fatal("Close did not clear signer private-key bytes")
	}
	if !equalBytes(seed, original) {
		t.Fatal("Close changed caller-owned seed")
	}
}

func signedRoute(kid string, signWith ed25519.PrivateKey, status int, body []byte) routeFunc {
	return func(req *http.Request) (*http.Response, error) {
		auth, _ := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
		ts := time.Now().Unix()
		sig := ed25519.Sign(signWith, []byte(jack.ResponseSigningString(status, auth.Sig, kid, ts, body)))
		h := make(http.Header)
		h.Set("Jack-Auth", jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: ts, Sig: jack.EncodeBase64URL(sig)}))
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
	}
}

func TestEveryCallSignsAgain(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	s := &signer{private: userPriv, public: userPub}
	route := signedRoute(jack.KeyID(serverPub), serverPriv, 200, []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ok":true}}}`))
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: s, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		var out struct {
			OK bool `json:"ok"`
		}
		if err = a.Call(context.Background(), "svc.run", nil, &out); err != nil || !out.OK || s.calls != i {
			t.Fatalf("call %d: err=%v ok=%t signer calls=%d", i, err, out.OK, s.calls)
		}
	}
}

func TestUnauthorizedWithBadSignatureIsUnverifiedResponse(t *testing.T) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	route := signedRoute(jack.KeyID(serverPub), wrongPriv, 401, []byte(`{"error":{"message":"unauthorized"}}`))
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrUnverified {
		t.Fatalf("401 with a bad signature class = %v, want %v", err, ErrUnverified)
	}
}

type failingBody struct{ err error }

func (b failingBody) Read([]byte) (int, error) { return 0, b.err }
func (failingBody) Close() error               { return nil }

func TestRouteBodyErrorCannotImpersonateSignedRejection(t *testing.T) {
	serverPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	route := routeFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: failingBody{&client.HTTPError{Status: 403, Message: "sensitive"}}, Request: req}, nil
	})
	a, err := New(Config{Endpoint: "https://gateway.example/mcp", Audience: "aud", ServerKey: serverPub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Call(context.Background(), "svc.run", nil, nil); err != ErrRoute || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("route body error class = %v, want %v", err, ErrRoute)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
