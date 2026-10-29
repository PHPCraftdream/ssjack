package appstoreanchortls

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSRejectsBeforeHTTP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		auth      tls.ClientAuthType
		version   uint16
		untrusted bool
	}{
		{"no-client-auth", tls.NoClientCert, tls.VersionTLS13, false},
		{"TLS12", tls.RequireAndVerifyClientCert, tls.VersionTLS12, false},
		{"untrusted-server", tls.RequireAndVerifyClientCert, tls.VersionTLS13, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t, 40)
			var calls atomic.Int32
			s := server(t, f, tc.auth, tc.version, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
			cfg := config(s.URL, f)
			if tc.untrusted {
				cfg.RootCAs = fixture(t, 50).roots
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if reply, err := c.Read(readContext(t)); !errors.Is(err, ErrUnavailable) || reply.SignatureValid() {
				t.Fatalf("accepted: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("HTTP sent before required TLS checks")
			}
		})
	}
}

func TestRootPoolIsOwned(t *testing.T) {
	f := fixture(t, 60)
	other := fixture(t, 70)
	mixed := f
	mixed.server = other.server
	var calls atomic.Int32
	s := server(t, mixed, tls.RequireAndVerifyClientCert, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	cfg := config(s.URL, f)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	root, err := x509.ParseCertificate(other.server.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	cfg.RootCAs.AddCert(root)
	if _, err := c.Read(readContext(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("caller root mutation trusted: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("untrusted server reached")
	}
}

func TestInvalidRepliesAndNoRedirect(t *testing.T) {
	for _, name := range []string{"status", "redirect", "oversize", "truncated", "request", "store", "key", "signature"} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t, 80)
			var calls, redirectCalls atomic.Int32
			target := server(t, f, tls.RequireAndVerifyClientCert, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) { redirectCalls.Add(1) })
			s := server(t, f, tls.RequireAndVerifyClientCert, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				b, err := io.ReadAll(io.LimitReader(r.Body, 49))
				if err != nil {
					t.Error(err)
					return
				}
				reply := signedReply(t, b, f.signer)
				if reply == nil {
					return
				}
				switch name {
				case "status":
					w.WriteHeader(http.StatusInternalServerError)
				case "redirect":
					w.Header().Set("Location", target.URL)
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "oversize":
					reply = append(reply, 0)
				case "truncated":
					reply = reply[:351]
				case "request":
					reply[16] ^= 1
					copy(reply[288:], ed25519.Sign(f.signer, reply[:288]))
				case "store":
					reply[32] ^= 1
					copy(reply[288:], ed25519.Sign(f.signer, reply[:288]))
				case "key":
					copy(reply[288:], ed25519.Sign(f.server.PrivateKey.(ed25519.PrivateKey), reply[:288]))
				case "signature":
					reply[351] ^= 1
				}
				_, _ = w.Write(reply)
			})
			c, err := New(config(s.URL, f))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			reply, err := c.Read(readContext(t))
			if err != ErrUnavailable || reply.SignatureValid() {
				t.Fatalf("backend failure leaked or accepted: %v", err)
			}
			if calls.Load() != 1 || redirectCalls.Load() != 0 {
				t.Fatal("retry or redirect")
			}
		})
	}
}

func TestHandshakeCancellationClosesConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	c, err := New(config("https://"+listener.Addr().String(), fixture(t, 110)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(readContext(t))
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := c.Read(ctx); result <- err }()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-ctx.Done():
		t.Fatal("connection not accepted")
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handshake cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not cancel")
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("cancelled TLS connection not closed: %v", err)
	}
}

func TestBodyDeadline(t *testing.T) {
	f := fixture(t, 100)
	entered := make(chan struct{})
	release := make(chan struct{})
	s := server(t, f, tls.RequireAndVerifyClientCert, tls.VersionTLS13, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	c, err := New(config(s.URL, f))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := c.Read(ctx); result <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("body not reached")
	}
	select {
	case err := <-result:
		deadline, _ := ctx.Deadline()
		if (!errors.Is(err, context.DeadlineExceeded) && err != ErrUnavailable) || time.Now().Before(deadline) {
			t.Fatalf("deadline: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("body read unbounded")
	}
}
