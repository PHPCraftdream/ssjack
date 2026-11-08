package mcpexchange

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
func testTransport(t *testing.T, peer roundTripFunc) (*Transport, *mcpflow.Transport) {
	t.Helper()
	flow, err := mcpflow.New(context.Background(), peer, func(request *http.Request) (*http.Request, error) { return request, nil }, func() {})
	if err != nil {
		t.Fatal("could not create owned fixture flow")
	}
	client := &http.Client{Transport: flow, CheckRedirect: func(*http.Request, []*http.Request) error { return errExchange }}
	transport, err := New("https://mcp.example.test/endpoint", client)
	if err != nil {
		t.Fatal("could not create transport")
	}
	t.Cleanup(func() { _ = flow.Close(context.Background()) })
	return transport, flow
}
func response(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}
func mustID(t *testing.T, v any) jsonrpc.ID {
	t.Helper()
	id, err := jsonrpc.MakeID(v)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func call(t *testing.T, id string, method string) *jsonrpc.Request {
	t.Helper()
	return &jsonrpc.Request{ID: mustID(t, id), Method: method, Params: json.RawMessage(`{}`)}
}
func notify(method string) *jsonrpc.Request {
	return &jsonrpc.Request{Method: method, Params: json.RawMessage(`{}`)}
}
func startUnnegotiatedConnection(t *testing.T, transport *Transport) *connection {
	t.Helper()
	conn, err := transport.Connect(context.Background())
	if err != nil {
		t.Fatal("connect rejected")
	}
	return conn.(*connection)
}
func mustWrite(t *testing.T, got error, want error, msg string) {
	t.Helper()
	if got != want {
		t.Fatal(msg)
	}
}
func mustRead(t *testing.T, c *connection) jsonrpc.Message {
	t.Helper()
	message, err := c.Read(context.Background())
	if err != nil {
		t.Fatal("response missing")
	}
	return message
}

// negotiatedConnection performs the real initialize/notifications-initialized
// handshake over the wire; the peer handler must serve both handshake POSTs.
func negotiatedConnection(t *testing.T, transport *Transport) *connection {
	t.Helper()
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), call(t, "init", "initialize")), nil, "initialize rejected")
	mustRead(t, conn)
	mustWrite(t, conn.Write(context.Background(), notify("notifications/initialized")), nil, "announcement rejected")
	return conn
}

// serveHandshake answers initialize and notifications/initialized POSTs with
// valid handshake responses and defers every other request to next.
func serveHandshake(request *http.Request, body []byte, next roundTripFunc) (*http.Response, error) {
	if bytes.Contains(body, []byte(`"method":"initialize"`)) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-06-18"}}`), nil
	}
	if bytes.Contains(body, []byte(`"method":"notifications/initialized"`)) {
		return response(http.StatusAccepted, "", ""), nil
	}
	return next(request)
}
func sseExchange() *http.Response {
	return response(http.StatusOK, "text/event-stream", ": keepalive\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n")
}
func TestInitializeNegotiationIsRequiredBeforeOtherMethods(t *testing.T) {
	transport, _ := testTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"1","result":{}}`), nil
	}))
	conn := startUnnegotiatedConnection(t, transport)
	if err := conn.Write(context.Background(), call(t, "x", "tools/list")); err == nil {
		t.Fatal("request before initialize was admitted")
	}
	_ = conn.Close()
}
func TestCorrelatesExactStringIDAndRejectsUnlistedMethods(t *testing.T) {
	var requests atomic.Int32
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		body, _ := io.ReadAll(request.Body)
		return serveHandshake(request, body, func(*http.Request) (*http.Response, error) {
			if !bytes.Contains(body, []byte(`"id":"opaque-id"`)) || request.Method != http.MethodPost {
				return response(http.StatusBadRequest, "text/plain", "secret-peer-body"), nil
			}
			return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"opaque-id","result":{"ok":true}}`), nil
		})
	})
	conn := negotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), call(t, "opaque-id", "tools/list")), nil, "valid request failed")
	message, err := conn.Read(context.Background())
	if err != nil {
		t.Fatal("response not delivered")
	}
	got := message.(*jsonrpc.Response)
	if got.ID.Raw() != "opaque-id" {
		t.Fatal("response ID changed")
	}
	// Two handshake POSTs plus exactly one tools/list exchange.
	mustWrite(t, conn.Write(context.Background(), call(t, "second", "resources/read")), errExchange, "unlisted method reached peer")
	// The refused call caused no additional peer contact.
	if requests.Load() != 3 {
		t.Fatal("exchange count changed")
	}
	_ = conn.Close()
}
func TestSSEResponseMustMatchOriginalID(t *testing.T) {
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		return serveHandshake(request, body, roundTripFunc(func(*http.Request) (*http.Response, error) { return sseExchange(), nil }))
	})
	conn := negotiatedConnection(t, transport)
	request := &jsonrpc.Request{ID: mustID(t, float64(8)), Method: "ping", Params: json.RawMessage(`{}`)}
	mustWrite(t, conn.Write(context.Background(), request), errExchange, "mismatched SSE response was accepted")
	_ = conn.Close()
}
func TestSSEMessageResponseIsDelivered(t *testing.T) {
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		return serveHandshake(request, body, roundTripFunc(func(*http.Request) (*http.Response, error) { return sseExchange(), nil }))
	})
	conn := negotiatedConnection(t, transport)
	request := &jsonrpc.Request{ID: mustID(t, float64(7)), Method: "ping", Params: json.RawMessage(`{}`)}
	mustWrite(t, conn.Write(context.Background(), request), nil, "matching SSE response failed")
	mustRead(t, conn)
	_ = conn.Close()
}
func TestNegotiatesVersionAndKeepsSessionIDBounded(t *testing.T) {
	var calls atomic.Int32
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		count := calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		if count == 1 {
			result := response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"1","result":{"protocolVersion":"2025-06-18"}}`)
			result.Header.Set("Mcp-Session-Id", "session-1")
			return result, nil
		}
		if request.Header.Get("Mcp-Session-Id") != "session-1" || request.Header.Get("Mcp-Protocol-Version") != "2025-06-18" {
			return response(http.StatusBadRequest, "text/plain", "private"), nil
		}
		if bytes.Contains(body, []byte(`"id"`)) {
			return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"2","result":{}}`), nil
		}
		return response(http.StatusAccepted, "", ""), nil
	})
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), call(t, "1", "initialize")), nil, "initialize failed")
	mustRead(t, conn)
	if conn.SessionID() != "session-1" {
		t.Fatal("session identifier not retained")
	}
	mustWrite(t, conn.Write(context.Background(), notify("notifications/initialized")), nil, "announcement rejected")
	mustWrite(t, conn.Write(context.Background(), call(t, "2", "tools/list")), nil, "negotiated exchange failed")
	_ = conn.Close()
}
func TestPeerBodyAndDiagnosticsNeverEscape(t *testing.T) {
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		return serveHandshake(request, body, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusForbidden, "text/plain", "secret-peer-body"), nil
		}))
	})
	conn := negotiatedConnection(t, transport)
	err := conn.Write(context.Background(), call(t, "1", "tools/call"))
	if err == nil || err != errExchange || strings.Contains(err.Error(), "secret-peer-body") {
		t.Fatal("peer diagnostic escaped fixed error boundary")
	}
	_ = conn.Close()
}
func TestCloseCancelsAndJoinsBlockedHTTP(t *testing.T) {
	started := make(chan struct{})
	joined := make(chan struct{})
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		return serveHandshake(request, body, func(*http.Request) (*http.Response, error) {
			close(started)
			<-request.Context().Done()
			close(joined)
			return nil, request.Context().Err()
		})
	})
	conn := negotiatedConnection(t, transport)
	writeDone := make(chan struct{})
	go func() { _ = conn.Write(context.Background(), call(t, "1", "tools/call")); close(writeDone) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("exchange did not start")
	}
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("connection close did not cancel HTTP")
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("write was not joined")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("close returned before exchange joined")
	}
}
func TestConnectIsOneUseAndNeverDefaultsClient(t *testing.T) {
	if _, err := New("https://mcp.example.test", nil); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := New("https://mcp.example.test", http.DefaultClient); err == nil {
		t.Fatal("default client accepted")
	}
	transport, _ := testTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(http.StatusAccepted, "", ""), nil }))
	if _, err := transport.Connect(context.Background()); err != nil {
		t.Fatal("first connect failed")
	}
	if _, err := transport.Connect(context.Background()); err == nil {
		t.Fatal("second connect accepted")
	}
}
func TestRejectsUnsupportedNegotiatedVersion(t *testing.T) {
	transport, _ := testTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2099-01-01"}}`), nil
	}))
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), call(t, "init", "initialize")), errExchange, "unsupported version accepted")
	mustWrite(t, conn.Write(context.Background(), call(t, "2", "tools/list")), errExchange, "tools/list admitted without successful initialize")
	_ = conn.Close()
}
func TestRejectsUpstreamRequestAndResponseIDMismatch(t *testing.T) {
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		return serveHandshake(request, body, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, "application/json", `{"jsonrpc":"2.0","id":"x","method":"sampling/createMessage","params":{}}`), nil
		}))
	})
	conn := negotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), call(t, "x", "tools/list")), errExchange, "upstream request was forwarded")
	_ = conn.Close()
}
