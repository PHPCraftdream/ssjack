package appstoreanchortls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
)

func readContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestReadOwnershipAndFreshConnections(t *testing.T) {
	f := fixture(t, 10)
	var mu sync.Mutex
	var ids [][16]byte
	var addresses []string
	s := server(t, f, tls.RequireAndVerifyClientCert, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/anchor" || r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Accept") != "application/octet-stream" || r.ContentLength != 48 || len(r.TLS.PeerCertificates) == 0 || r.TLS.DidResume {
			t.Error("wrong request/transport profile")
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 49))
		if err != nil {
			t.Error(err)
			return
		}
		reply := signedReply(t, b, f.signer)
		if reply == nil {
			return
		}
		mu.Lock()
		ids = append(ids, [16]byte(b[32:48]))
		addresses = append(addresses, r.RemoteAddr)
		mu.Unlock()
		_, _ = w.Write(reply)
	})
	cfg := config(s.URL+"/anchor", f)
	cfg.ServiceKey = append(ed25519.PublicKey(nil), cfg.ServiceKey...)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	clear(cfg.ServiceKey)
	clear(cfg.Certificate.Certificate[0])
	clear(cfg.Certificate.PrivateKey.(ed25519.PrivateKey))
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	for i := 0; i < 2; i++ {
		reply, err := c.Read(readContext(t))
		if err != nil {
			t.Fatal(err)
		}
		if !reply.SignatureValid() || reply.Operation() != appstoreanchorreply.Read || reply.Outcome() != appstoreanchorreply.ReadState || reply.StoreID() != cfg.StoreID {
			t.Fatal("wrong verified reply")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 2 || ids[0] == ids[1] || addresses[0] == addresses[1] {
		t.Fatal("request ID or connection reused")
	}
}

func TestClientLifecycleAndCancellation(t *testing.T) {
	f := fixture(t, 20)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	s := server(t, f, tls.RequireAndVerifyClientCert, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	c, err := New(config(s.URL, f))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	alias := *c
	for _, ctx := range []context.Context{nil, context.Background()} {
		if r, err := c.Read(ctx); !errors.Is(err, ErrUnavailable) || r.SignatureValid() {
			t.Fatal("missing deadline accepted")
		}
	}
	ctx, cancel := context.WithCancel(readContext(t))
	cancel()
	if _, err := c.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	ctx, cancel = context.WithCancel(readContext(t))
	defer cancel()
	defer close(release)
	result := make(chan error, 1)
	go func() { _, err := c.Read(ctx); result <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("handler not reached")
	}
	if _, err := alias.Read(readContext(t)); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("read did not cancel")
	}
	owned := c.state.privateDER
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	if !zero(owned) || len(c.state.privateDER) != 0 {
		t.Fatal("owned DER retained")
	}
	if _, err := c.Read(readContext(t)); !errors.Is(err, ErrClosed) {
		t.Fatal("alias close not shared")
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected request or retry")
	}
	var empty Client
	for _, client := range []*Client{nil, &empty} {
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Read(readContext(t)); !errors.Is(err, ErrClosed) {
			t.Fatal("zero client accepted")
		}
	}
}

func TestInvalidConfiguration(t *testing.T) {
	f := fixture(t, 30)
	for _, endpoint := range []string{"", "http://example.test", "https://user@example.test", "https://example.test?", "https://example.test?q=x", "https://example.test#", "https://example.test#x", "https://example.test:0", "https://example.test:65536", "https://example.test:bad", "https://é.test", "https://[fe80::1%25eth0]"} {
		if c, err := New(config(endpoint, f)); !errors.Is(err, ErrInvalid) || c != nil {
			t.Fatalf("accepted %q", endpoint)
		}
	}
	cases := []func(*Config){
		func(c *Config) { c.RootCAs = nil },
		func(c *Config) { c.RootCAs = x509.NewCertPool() },
		func(c *Config) { c.StoreID = [16]byte{} },
		func(c *Config) { c.ServiceKey = make([]byte, 32) },
		func(c *Config) { c.ServiceKey = []byte{1} },
		func(c *Config) { c.Certificate.Certificate = nil },
		func(c *Config) { c.Certificate.Certificate = [][]byte{{1}} },
		func(c *Config) { c.Certificate.PrivateKey = nil },
		func(c *Config) { c.Certificate.PrivateKey = f.server.PrivateKey },
		func(c *Config) { c.Certificate.PrivateKey = struct{}{} },
		func(c *Config) { c.Certificate.Certificate = make([][]byte, 9) },
		func(c *Config) { c.Certificate.Certificate = [][]byte{bytes.Repeat([]byte{1}, 16385)} },
	}
	for i, mutate := range cases {
		cfg := config("https://example.test/anchor", f)
		mutate(&cfg)
		if c, err := New(cfg); !errors.Is(err, ErrInvalid) || c != nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}
