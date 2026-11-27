package mcpjack

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
)

func TestNewLoopbackRouteRejectsInvalidTargets(t *testing.T) {
	for _, target := range []string{"", "localhost:80", "192.0.2.1:80", "127.0.0.1:0", "127.0.0.1:65536"} {
		if _, err := NewLoopbackRoute(target, func(context.Context, string, string) (net.Conn, error) { return nil, nil }); err != errLoopbackInvalid {
			t.Fatalf("target %q error = %v", target, err)
		}
	}
}

func TestLoopbackRejectsAuthoritiesBeforeDial(t *testing.T) {
	calls := 0
	route, err := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) { calls++; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ url, host string }{{"http://127.0.0.1:8081/x", ""}, {"https://127.0.0.1:8080/x", ""}, {"http://127.0.0.1:8080/x", "other.invalid"}} {
		req, _ := http.NewRequest("POST", tc.url, nil)
		req.Host = tc.host
		if _, err := route.RoundTrip(req); err != errLoopbackInvalid {
			t.Fatalf("error = %v", err)
		}
	}
	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{"canonical", http.Header{"Host": []string{"attacker.invalid"}}},
		{"lowercase", http.Header{"host": []string{"attacker.invalid"}}},
		{"duplicate mixed-case", http.Header{"Host": []string{"127.0.0.1:8080"}, "hOsT": []string{"attacker.invalid"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/", nil)
			req.Header = tc.header
			if _, err := route.RoundTrip(req); err != errLoopbackInvalid {
				t.Fatalf("Host header error = %v, want %v", err, errLoopbackInvalid)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("dial calls = %d", calls)
	}
}

func TestLoopbackRoundTripRemovesAllHostHeaderSpellings(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	route, _ := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
	serverDone := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(serverConn))
		if err == nil {
			if values := req.Header.Values("Host"); len(values) != 0 {
				err = fmt.Errorf("unexpected Host headers: %v", values)
			}
		}
		if err == nil {
			_, err = io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
		serverDone <- err
	}()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	req.Header = http.Header{"Host": []string{"127.0.0.1:8080"}, "hOsT": []string{"127.0.0.1:8080"}}
	resp, err := route.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackRoundTripFixedDialAndBody(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	calls := 0
	var network, address string
	route, _ := NewLoopbackRoute("127.0.0.1:8080", func(_ context.Context, n, a string) (net.Conn, error) {
		calls++
		network, address = n, a
		return clientConn, nil
	})
	serverDone := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(serverConn))
		if err != nil {
			serverDone <- err
			return
		}
		if req.Host != "127.0.0.1:8080" || req.URL.Host != "" {
			serverDone <- fmt.Errorf("wire authority/target: %q %q", req.Host, req.URL)
			return
		}
		_, err = io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
		serverDone <- err
	}()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/path", nil)
	resp, err := route.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "body" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	_ = resp.Body.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if calls != 1 || network != "tcp" || address != "127.0.0.1:8080" {
		t.Fatalf("dial calls=%d network=%q address=%q", calls, network, address)
	}
}

func TestLoopbackHeaderLimit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	route, _ := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
	serverDone := make(chan error, 1)
	go func() {
		_, err := http.ReadRequest(bufio.NewReader(serverConn))
		if err == nil {
			_, err = io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nX-Large: "+strings.Repeat("x", maxLoopbackResponseHeaderBytes)+"\r\n\r\n")
		}
		serverDone <- err
	}()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	if _, err := route.RoundTrip(req); err != errLoopbackUncertain {
		t.Fatalf("error=%v, want %v", err, errLoopbackUncertain)
	}
	if err := <-serverDone; err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatalf("server write: %v", err)
	}
}

func TestLoopbackResponseBodyCannotChangeDialTarget(t *testing.T) {
	calls := 0
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	route, err := NewLoopbackRoute("127.0.0.1:8080", func(_ context.Context, network, address string) (net.Conn, error) {
		calls++
		if network != "tcp" || address != "127.0.0.1:8080" {
			t.Errorf("dial target changed: %q %q", network, address)
		}
		return clientConn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(serverConn))
		_, _ = io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\ntcp:attacker.invalid:9")
	}()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	resp, err := route.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "tcp:attacker.invalid:9" {
		t.Fatalf("response body=%q", body)
	}
	if calls != 1 {
		t.Fatalf("dial calls=%d", calls)
	}
}
func TestLoopbackRedirectReturnedUnchanged(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	route, _ := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(serverConn))
		_, _ = io.WriteString(serverConn, "HTTP/1.1 302 Found\r\nLocation: http://evil.invalid/\r\nContent-Length: 3\r\n\r\nred")
	}()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	resp, err := route.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "http://evil.invalid/" {
		t.Fatalf("status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAdapterSignedResponseAndRedirectFailClosed(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	for _, redirect := range []bool{false, true} {
		calls := 0
		route, _ := NewLoopbackRoute("127.0.0.1:8080", func(_ context.Context, network, address string) (net.Conn, error) {
			calls++
			if network != "tcp" || address != "127.0.0.1:8080" {
				t.Errorf("dial %q %q", network, address)
			}
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				req, err := http.ReadRequest(bufio.NewReader(serverConn))
				if err != nil {
					return
				}
				if req.Host != "127.0.0.1:8080" {
					t.Errorf("wire Host=%q", req.Host)
				}
				if _, err := io.Copy(io.Discard, req.Body); err != nil {
					t.Errorf("request body: %v", err)
					return
				}
				if redirect {
					_, _ = io.WriteString(serverConn, "HTTP/1.1 302 Found\r\nLocation: http://attacker.invalid/\r\nContent-Length: 0\r\n\r\n")
					return
				}
				body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"ok":true}}}`)
				auth, err := jack.ParseRequestAuth(req.Header.Values("Jack-Auth"))
				if err != nil {
					t.Errorf("auth: %v", err)
					return
				}
				ts := time.Now().Unix()
				kid := jack.KeyID(serverPub)
				sig := ed25519.Sign(serverPriv, []byte(jack.ResponseSigningString(200, auth.Sig, kid, ts, body)))
				responseAuth := jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: ts, Sig: jack.EncodeBase64URL(sig)})
				wire := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nJack-Auth: " + responseAuth + "\r\nLocation: http://attacker.invalid/\r\nX-Route: tcp:attacker.invalid:9\r\n\r\n" + string(body)
				_, _ = io.WriteString(serverConn, wire)
			}()
			return clientConn, nil
		})
		a, err := New(Config{Endpoint: "http://127.0.0.1:8080/mcp", Audience: "aud", ServerKey: serverPub, Signer: &signer{private: userPriv, public: userPub}, Route: route, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			OK bool `json:"ok"`
		}
		err = a.Call(context.Background(), "svc.run", nil, &out)
		if redirect {
			if err != ErrRoute {
				t.Fatalf("redirect error=%v", err)
			}
		} else if err != nil || !out.OK {
			t.Fatalf("signed call err=%v out=%+v", err, out)
		}
		if calls != 1 {
			t.Fatalf("dial count=%d", calls)
		}
	}
}

func TestLoopbackRoundTripCancellationWhileWaitingForHeaders(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer clientConn.Close()
	defer serverConn.Close()

	route, err := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	requestReceived := make(chan error, 1)
	peerObservedClose := make(chan error, 1)
	go func() {
		_, err := http.ReadRequest(bufio.NewReader(serverConn))
		requestReceived <- err
		if err != nil {
			return
		}
		var b [1]byte
		_, err = serverConn.Read(b[:])
		peerObservedClose <- err
	}()

	roundTripDone := make(chan error, 1)
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:8080/", nil)
	go func() {
		_, err := route.RoundTrip(req)
		roundTripDone <- err
	}()

	select {
	case err := <-requestReceived:
		if err != nil {
			t.Fatalf("read request: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for request")
	}
	cancel()

	select {
	case err := <-roundTripDone:
		if err != errLoopbackUncertain {
			t.Fatalf("RoundTrip error = %v, want %v", err, errLoopbackUncertain)
		}
	case <-time.After(time.Second):
		t.Fatal("RoundTrip did not return promptly after cancellation")
	}
	select {
	case err := <-peerObservedClose:
		if err == nil {
			t.Fatal("peer read succeeded; connection remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not observe connection close")
	}
}

func TestLoopbackCloseAndCancellationCloseConnection(t *testing.T) {
	for _, cancelBody := range []bool{false, true} {
		clientConn, serverConn := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		route, _ := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
		go func() {
			_, _ = http.ReadRequest(bufio.NewReader(serverConn))
			_, _ = io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\npartial")
			var b [1]byte
			_, _ = serverConn.Read(b[:])
		}()
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:8080/", nil)
		resp, err := route.RoundTrip(req)
		if err != nil {
			cancel()
			serverConn.Close()
			t.Fatal(err)
		}
		if cancelBody {
			cancel()
		} else {
			_ = resp.Body.Close()
		}
		_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err := clientConn.Read(b[:]); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("connection not closed: read error = %v", err)
		}
		cancel()
		_ = serverConn.Close()
	}
}

func TestLoopbackDialAndWriteFailuresAreFixedAndNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name string
		dial func() (net.Conn, net.Conn)
		want error
	}{
		{name: "dial", dial: func() (net.Conn, net.Conn) { return nil, nil }, want: errLoopbackRoute},
		{name: "write", dial: func() (net.Conn, net.Conn) {
			client, peer := net.Pipe()
			go peer.Close()
			return client, peer
		}, want: errLoopbackUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var server net.Conn
			route, err := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) {
				calls++
				client, peer := tc.dial()
				server = peer
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if server != nil {
				defer server.Close()
			}
			req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/", strings.NewReader(strings.Repeat("x", 1024)))
			if _, err := route.RoundTrip(req); err != tc.want {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
			if calls != 1 {
				t.Fatalf("dial calls=%d", calls)
			}
		})
	}
}

func TestConnectionBodyMapsInjectedErrors(t *testing.T) {
	boom := fmt.Errorf("sensitive injected failure")
	for _, tc := range []struct {
		name                string
		readErr, closeErr   error
		wantRead, wantClose error
	}{
		{name: "read", readErr: boom, wantRead: errLoopbackRoute},
		{name: "close", closeErr: boom, wantClose: errLoopbackRoute},
		{name: "eof", readErr: io.EOF, wantRead: io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer client.Close()
			defer peer.Close()
			stopped := false
			body := &connectionBody{ReadCloser: injectedBody{readErr: tc.readErr, closeErr: tc.closeErr}, conn: client, stop: func() bool { stopped = true; return true }}
			_, readErr := body.Read(make([]byte, 1))
			if readErr != tc.wantRead {
				t.Fatalf("read error=%v want %v", readErr, tc.wantRead)
			}
			if tc.readErr != nil && tc.readErr != io.EOF {
				if !stopped {
					t.Fatal("read failure did not stop cancellation callback")
				}
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if _, err := peer.Read(b[:]); err != io.EOF {
					t.Fatalf("read failure left connection open: peer read error = %v", err)
				}
			}
			if closeErr := body.Close(); closeErr != tc.wantClose {
				t.Fatalf("close error=%v want %v", closeErr, tc.wantClose)
			}
		})
	}
}

type injectedBody struct{ readErr, closeErr error }

func (b injectedBody) Read([]byte) (int, error) { return 0, b.readErr }
func (b injectedBody) Close() error             { return b.closeErr }
func TestLoopbackBodyEOFClosesConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	route, _ := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) { return clientConn, nil })
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(serverConn))
		_, _ = io.WriteString(serverConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	resp, err := route.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := clientConn.Read(b[:]); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("EOF did not close connection: read error = %v", err)
	}
}

type closeCounter struct {
	io.Reader
	closed int
}

func (c *closeCounter) Close() error { c.closed++; return nil }

func TestLoopbackRefusalsAndDialFailuresCloseRequestBody(t *testing.T) {
	boom := errors.New("sensitive dial failure")
	for _, tc := range []struct {
		name     string
		mutate   func(*http.Request)
		withConn bool
		dialErr  error
		want     error
		dials    int
	}{
		{name: "opaque", mutate: func(r *http.Request) { r.URL.Opaque = "//attacker.invalid/x" }, want: errLoopbackInvalid},
		{name: "authority", mutate: func(r *http.Request) { r.URL.Host = "127.0.0.1:9" }, want: errLoopbackInvalid},
		{name: "dial error", dialErr: boom, want: errLoopbackRoute, dials: 1},
		{name: "conn with error", withConn: true, dialErr: boom, want: errLoopbackRoute, dials: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var peer net.Conn
			dials := 0
			route, err := NewLoopbackRoute("127.0.0.1:8080", func(context.Context, string, string) (net.Conn, error) {
				dials++
				if tc.withConn {
					var client net.Conn
					client, peer = net.Pipe()
					return client, tc.dialErr
				}
				return nil, tc.dialErr
			})
			if err != nil {
				t.Fatal(err)
			}
			body := &closeCounter{Reader: strings.NewReader("x")}
			req, _ := http.NewRequest("POST", "http://127.0.0.1:8080/", body)
			if tc.mutate != nil {
				tc.mutate(req)
			}
			_, err = route.RoundTrip(req)
			if err != tc.want {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("error leaks dial text: %v", err)
			}
			if dials != tc.dials || body.closed != 1 {
				t.Fatalf("dials = %d, request body closes = %d", dials, body.closed)
			}
			if peer != nil {
				defer peer.Close()
				_ = peer.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if _, err := peer.Read(b[:]); err != io.EOF {
					t.Fatalf("dialed connection not closed: peer read error = %v", err)
				}
			}
		})
	}
}
