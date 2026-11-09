package sshproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/tests/fixtures/proxyserver"
)

func TestTunnelsPreserveBytesAndResolveTargetsAtTheProxy(t *testing.T) {
	for _, kind := range []string{SOCKS5, HTTP} {
		for _, target := range []string{"unresolved.invalid:22", "192.0.2.10:22", "[2001:db8::1]:22"} {
			for _, authenticated := range []bool{false, true} {
				t.Run(kind+target+map[bool]string{false: "anonymous", true: "authenticated"}[authenticated], func(t *testing.T) {
					options := proxyserver.Options{Protocol: kind, Target: target, Upstream: echoTarget(t)}
					if authenticated {
						options.Username, options.Password = "operator", []byte("synthetic proxy password")
					}
					server, err := proxyserver.Start(options)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(server.Close)
					route := &Config{Type: kind, Address: server.Address(), Username: options.Username, Password: options.Password}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					conn, err := DialContext(ctx, target, route)
					if err != nil {
						t.Fatal("valid proxy tunnel refused")
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					if err := writeAll(conn, []byte("probe")); err != nil {
						t.Fatal(err)
					}
					var received [5]byte
					if _, err := io.ReadFull(conn, received[:]); err != nil || string(received[:]) != "probe" {
						t.Fatal("proxy changed tunneled bytes")
					}
					if accepts, forwards := server.Counts(); accepts != 1 || forwards != 1 {
						t.Fatal("proxy route or target resolution was bypassed")
					}
				})
			}
		}
	}
}

func TestProxyAuthenticationFailureNeverFallsBackToDirect(t *testing.T) {
	for _, kind := range []string{SOCKS5, HTTP} {
		target := echoTarget(t)
		server, err := proxyserver.Start(proxyserver.Options{Protocol: kind, Target: target, Upstream: target, Username: "operator", Password: []byte("correct synthetic password")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(server.Close)
		route := &Config{Type: kind, Address: server.Address(), Username: "operator", Password: []byte("wrong synthetic password")}
		conn, err := DialContext(context.Background(), target, route)
		if conn != nil {
			conn.Close()
			t.Fatal("proxy authentication failure fell back to direct")
		}
		if !errors.Is(err, ErrProxy) || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("proxy failure disclosed data or wrong status")
		}
		if _, forwards := server.Counts(); forwards != 0 {
			t.Fatal("failed proxy authentication opened the upstream")
		}
	}
}

func TestDirectRouteIgnoresProxyEnvironment(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}
	conn, err := DialContext(context.Background(), echoTarget(t), nil)
	if err != nil {
		t.Fatal("direct route consulted proxy environment")
	}
	conn.Close()
}

func TestHTTPBannerReadAheadAndRejectedResponses(t *testing.T) {
	client := pipePair(t, func(server net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
			io.WriteString(server, "HTTP/1.1 200 Connected\r\n\r\nSSH-2.0-synthetic\r\n")
		}
	})
	conn, err := httpTunnel(client, "target.invalid:22", &Config{Type: HTTP})
	if err != nil {
		t.Fatal("CONNECT handshake refused")
	}
	banner := make([]byte, len("SSH-2.0-synthetic\r\n"))
	if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "SSH-2.0-synthetic\r\n" {
		t.Fatal("CONNECT consumed the SSH banner")
	}
	for _, reply := range []string{
		"HTTP/1.1 407 Denied\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 302 Redirect\r\nLocation: http://127.0.0.1:1\r\n\r\n",
		"HTTP/1.1 200 OK\n\n", "not HTTP\r\n\r\n", "HTTP/1.1 200 OK\r\nTruncated:",
		"HTTP/1.1 200 OK\r\nX-Header: " + strings.Repeat("x", maxHTTPHeader) + "\r\n\r\n",
	} {
		route := &Config{Type: HTTP, Address: httpReply(t, reply)}
		if conn, err := DialContext(context.Background(), "target.invalid:22", route); err == nil || conn != nil {
			if conn != nil {
				conn.Close()
			}
			t.Fatal("invalid CONNECT reply accepted")
		}
	}
}

func TestSOCKSRejectsMalformedNegotiationAndReply(t *testing.T) {
	for _, response := range [][]byte{{4, 0}, {5, 255}, {5, 2}, {5}} {
		client := pipePair(t, func(server net.Conn) { var hello [3]byte; io.ReadFull(server, hello[:]); server.Write(response) })
		if socksTunnel(client, "192.0.2.10:22", &Config{Type: SOCKS5}) == nil {
			t.Fatal("invalid SOCKS method accepted")
		}
		client.Close()
	}
	for _, response := range [][]byte{{5, 1, 0, 1}, {5, 0, 1, 1}, {5, 0, 0, 8}, {5, 0, 0, 3, 0}, {5, 0, 0, 1, 127}} {
		client := pipePair(t, func(server net.Conn) {
			var hello [3]byte
			io.ReadFull(server, hello[:])
			server.Write([]byte{5, 0})
			var request [10]byte
			io.ReadFull(server, request[:])
			server.Write(response)
		})
		if socksTunnel(client, "192.0.2.10:22", &Config{Type: SOCKS5}) == nil {
			t.Fatal("invalid SOCKS connect reply accepted")
		}
		client.Close()
	}
}

func TestProxyHandshakeDeadlineClosesWithoutFallback(t *testing.T) {
	for _, kind := range []string{SOCKS5, HTTP} {
		t.Run(kind, func(t *testing.T) {
			ready, closed := make(chan struct{}), make(chan struct{})
			address := rawProxy(t, func(conn net.Conn) {
				if kind == HTTP {
					if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
						return
					}
				} else {
					var hello [3]byte
					if _, err := io.ReadFull(conn, hello[:]); err != nil {
						return
					}
				}
				close(ready)
				var data [1]byte
				conn.Read(data[:])
				close(closed)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := DialContext(ctx, "target.invalid:22", &Config{Type: kind, Address: address})
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("deadline fixture never reached the proxy handshake")
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("proxy handshake did not honor the caller deadline")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("proxy handshake did not time out")
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("timed-out proxy connection remained open")
			}
		})
	}
}

func TestTunnelCancellationClosesThePendingHandshake(t *testing.T) {
	for _, kind := range []string{SOCKS5, HTTP} {
		t.Run(kind, func(t *testing.T) { cancelPendingTunnel(t, kind) })
	}
}

func cancelPendingTunnel(t *testing.T, kind string) {
	t.Helper()
	ready, closed := make(chan struct{}), make(chan struct{})
	address := rawProxy(t, func(conn net.Conn) {
		if kind == HTTP {
			if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
				return
			}
		} else {
			var hello [3]byte
			if _, err := io.ReadFull(conn, hello[:]); err != nil {
				return
			}
		}
		close(ready)
		var extra [1]byte
		conn.Read(extra[:])
		close(closed)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := DialContext(ctx, "target.invalid:22", &Config{Type: kind, Address: address})
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy handshake did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("proxy cancellation was lost")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy dial did not cancel")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled proxy connection remained open")
	}
}
