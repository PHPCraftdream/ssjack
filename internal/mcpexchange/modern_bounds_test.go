package mcpexchange

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const modernParams = `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}`

func modernConn(t *testing.T, peer roundTripFunc) (*connection, context.Context) {
	t.Helper()
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		if wire.Method == "server/discover" {
			return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
		}
		return peer(request)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	connected, err := transport.Connect(ctx)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	conn := connected.(*connection)
	t.Cleanup(func() { _ = conn.Close(); cancel() })
	mustWrite(t, conn.Write(ctx, rawModernCall(t, "server/discover", "discover", modernParams)), nil, "modern discover failed")
	message, err := conn.Read(ctx)
	result, ok := message.(*jsonrpc.Response)
	if err != nil || !ok || result.Error != nil || string(result.Result) != `{"supportedVersions":["2026-07-28"],"capabilities":{}}` {
		t.Fatalf("modern discover result = (%T, %v), err=%v", message, result, err)
	}
	return conn, ctx
}

func TestModernBoundsSSEMessageFieldsAndID(t *testing.T) {
	for _, tc := range []struct {
		name string
		want error
		body func(string) string
	}{
		{"valid message", nil, func(data string) string { return "event: message\ndata: " + data + "\n\n" }},
		{"wrong ID", errExchange, func(string) string {
			return "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"other\",\"result\":{\"tools\":[]}}\n\n"
		}},
		{"id field", errExchange, func(data string) string { return "id: x\nevent: message\ndata: " + data + "\n\n" }},
		{"retry field", errExchange, func(data string) string { return "retry: 1\nevent: message\ndata: " + data + "\n\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
				wire, err := readModernRequest(request)
				if err != nil {
					t.Errorf("decode request: %v", err)
					return response(http.StatusBadRequest, "text/plain", ""), nil
				}
				if wire.Method == "server/discover" {
					return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
				}
				return response(http.StatusOK, "text/event-stream", tc.body(`{"jsonrpc":"2.0","id":"list","result":{"tools":[]}}`)), nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			conn, err := transport.Connect(ctx)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			c := conn.(*connection)
			t.Cleanup(func() { _ = c.Close(); cancel() })
			mustWrite(t, c.Write(ctx, rawModernCall(t, "server/discover", "discover", modernParams)), nil, "discover failed")
			if _, err := c.Read(ctx); err != nil {
				t.Fatalf("consume discover: %v", err)
			}
			mustWrite(t, c.Write(ctx, rawModernCall(t, "tools/list", "list", `{}`)), tc.want, "unexpected tools/list result")
			if tc.want == nil {
				message, err := c.Read(ctx)
				result, ok := message.(*jsonrpc.Response)
				if err != nil || !ok || string(result.Result) != `{"tools":[]}` {
					t.Fatalf("valid SSE result = (%T, %v), err=%v", message, result, err)
				}
			}
		})
	}
}

func TestModernBoundsResponseSizes(t *testing.T) {
	for _, tc := range []struct {
		name          string
		targetSize    int
		declaredLarge bool
		malformed     bool
		want          error
	}{
		{name: "valid at limit", targetSize: maxResponse},
		{name: "actual over limit", targetSize: maxResponse + 1, want: errExchange},
		{name: "declared over limit", targetSize: 64, declaredLarge: true, want: errExchange},
		{name: "small malformed JSON", malformed: true, want: errExchange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, ctx := modernConn(t, func(request *http.Request) (*http.Response, error) {
				wire, err := readModernRequest(request)
				if err != nil {
					t.Errorf("decode request: %v", err)
					return response(http.StatusBadRequest, "text/plain", ""), nil
				}
				if wire.Method == "server/discover" {
					return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
				}
				wantID := `"list"`
				if tc.malformed {
					wantID = `"malformed"`
				}
				if string(wire.ID) != wantID {
					t.Errorf("request ID=%s, want %s", wire.ID, wantID)
				}
				body := `not-json`
				if !tc.malformed {
					prefix := `{"jsonrpc":"2.0","id":` + string(wire.ID) + `,"result":{"padding":"`
					suffix := `"}}`
					body = prefix + strings.Repeat("x", tc.targetSize-len(prefix)-len(suffix)) + suffix
				}
				if !tc.malformed && !json.Valid([]byte(body)) {
					t.Errorf("test response is invalid JSON at size %d", len(body))
				}
				res := response(http.StatusOK, "application/json", body)
				if tc.declaredLarge {
					res.ContentLength = maxResponse + 1
				} else if tc.targetSize > 0 {
					res.ContentLength = -1
				}
				return res, nil
			})
			requestID := "list"
			if tc.malformed {
				requestID = "malformed"
			}
			got := conn.Write(ctx, rawModernCall(t, "tools/list", requestID, `{}`))
			if got != tc.want {
				t.Fatalf("tools/list write error=%v, want %v", got, tc.want)
			}
			if tc.want == nil {
				message := mustRead(t, conn)
				result, ok := message.(*jsonrpc.Response)
				if !ok || result.Error != nil || result.ID.Raw() != "list" {
					t.Fatalf("response=%T %#v, want successful response id list", message, message)
				}
			}
		})
	}
}

func TestModernBoundsEncodedRequestAndQueuedResults(t *testing.T) {
	t.Run("encoded request includes metadata overhead", func(t *testing.T) {
		var lists atomic.Int32
		conn, ctx := modernConn(t, func(request *http.Request) (*http.Response, error) {
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			if wire.Method == "server/discover" {
				return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
			}
			lists.Add(1)
			return responseForID(wire.ID, `{"tools":[]}`), nil
		})
		prefix := `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"padding":"`
		suffix := `"}`
		params := prefix + strings.Repeat("x", maxRequest-1-len(prefix)-len(suffix)) + suffix
		if len(params) != maxRequest-1 {
			t.Fatalf("params size = %d, want %d", len(params), maxRequest-1)
		}
		request := rawModernCall(t, "tools/list", "oversized", params)
		encoded, err := jsonrpc.EncodeMessage(request)
		if err != nil || len(encoded) <= maxRequest {
			t.Fatalf("encoded request size = %d, err=%v; want > %d", len(encoded), err, maxRequest)
		}
		mustWrite(t, conn.Write(ctx, request), errExchange, "oversized encoded request accepted")
		if lists.Load() != 0 {
			t.Fatal("oversized request reached peer")
		}
	})

	t.Run("four queued results", func(t *testing.T) {
		var lists atomic.Int32
		conn, ctx := modernConn(t, func(request *http.Request) (*http.Response, error) {
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			if wire.Method == "server/discover" {
				return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
			}
			lists.Add(1)
			return responseForID(wire.ID, `{"tools":[]}`), nil
		})
		for i := 0; i < maxActive; i++ {
			mustWrite(t, conn.Write(ctx, rawModernCall(t, "tools/list", fmt.Sprint(i), `{}`)), nil, "queued list failed")
		}
		mustWrite(t, conn.Write(ctx, rawModernCall(t, "tools/list", "fifth", `{}`)), errExchange, "fifth queued result accepted")
		if lists.Load() != maxActive {
			t.Fatalf("peer saw %d list requests, want %d", lists.Load(), maxActive)
		}
		for i := 0; i < maxActive; i++ {
			if _, err := conn.Read(ctx); err != nil {
				t.Fatalf("drain result %d: %v", i, err)
			}
		}
	})
}

func TestModernBoundsMessageCount(t *testing.T) {
	var lists atomic.Int32
	conn, ctx := modernConn(t, func(request *http.Request) (*http.Response, error) {
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		if wire.Method == "server/discover" {
			return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
		}
		lists.Add(1)
		return responseForID(wire.ID, `{"tools":[]}`), nil
	})
	if maxMessages != 4096 {
		t.Fatalf("message cap = %d, want 4096", maxMessages)
	}
	conn.mu.Lock()
	if conn.messages != 1 {
		conn.mu.Unlock()
		t.Fatalf("discover consumed %d messages, want 1", conn.messages)
	}
	conn.messages = maxMessages - 1
	conn.mu.Unlock()
	mustWrite(t, conn.Write(ctx, rawModernCall(t, "tools/list", "last", `{}`)), nil, "last permitted message refused")
	mustWrite(t, conn.Write(ctx, rawModernCall(t, "tools/list", "over", `{}`)), errExchange, "message over cap accepted")
	if lists.Load() != 1 {
		t.Fatalf("peer saw %d list requests, want 1", lists.Load())
	}
	if _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read permitted result: %v", err)
	}
}

func TestModernDiscoverLegacyFallbackAndSessionRefusals(t *testing.T) {
	t.Run("legacy-only discovery permits initialize", func(t *testing.T) {
		var initializes atomic.Int32
		transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			switch wire.Method {
			case "server/discover":
				return responseForID(wire.ID, `{"supportedVersions":["2025-06-18"]}`), nil
			case "initialize":
				initializes.Add(1)
				return responseForID(wire.ID, `{"protocolVersion":"2025-06-18"}`), nil
			default:
				t.Errorf("unexpected method %q", wire.Method)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		connected, err := transport.Connect(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		conn := connected.(*connection)
		t.Cleanup(func() { _ = conn.Close(); cancel() })
		mustWrite(t, conn.Write(ctx, rawModernCall(t, "server/discover", "discover", modernParams)), nil, "legacy-only discover failed")
		if _, err := conn.Read(ctx); err != nil {
			t.Fatalf("consume legacy-only discover: %v", err)
		}
		mustWrite(t, conn.Write(ctx, rawModernCall(t, "initialize", "init", `{"protocolVersion":"2025-06-18"}`)), nil, "legacy fallback initialize refused")
		message, err := conn.Read(ctx)
		if result, ok := message.(*jsonrpc.Response); err != nil || !ok || result.Error != nil {
			t.Fatalf("fallback initialize result = (%T, %v), err=%v", message, result, err)
		}
		if initializes.Load() != 1 {
			t.Fatalf("initialize reached peer %d times", initializes.Load())
		}
	})

	t.Run("error discover session header refused", func(t *testing.T) {
		transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"missing"}}`, wire.ID)
			res := response(http.StatusOK, "application/json", body)
			res.Header.Set("Mcp-Session-Id", "s1")
			return res, nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		connected, err := transport.Connect(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		conn := connected.(*connection)
		t.Cleanup(func() { _ = conn.Close(); cancel() })
		mustWrite(t, conn.Write(ctx, rawModernCall(t, "server/discover", "discover", modernParams)), errExchange, "session-bearing error discover accepted")
		if conn.SessionID() != "" {
			t.Fatalf("refused discovery stored session %q", conn.SessionID())
		}
	})

	t.Run("modern tools response session header refused", func(t *testing.T) {
		conn, ctx := modernConn(t, func(request *http.Request) (*http.Response, error) {
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			if wire.Method == "server/discover" {
				return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
			}
			res := responseForID(wire.ID, `{"tools":[]}`)
			res.Header.Set("Mcp-Session-Id", "s1")
			return res, nil
		})
		mustWrite(t, conn.Write(ctx, rawModernCall(t, "tools/list", "list", `{}`)), errExchange, "session-bearing tools response accepted")
		if conn.SessionID() != "" {
			t.Fatalf("refused modern response stored session %q", conn.SessionID())
		}
	})
}
