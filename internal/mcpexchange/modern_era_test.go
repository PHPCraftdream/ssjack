package mcpexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type modernWireRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Meta   struct {
		ProtocolVersion string          `json:"io.modelcontextprotocol/protocolVersion"`
		Caps            json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
	} `json:"_meta"`
}

func readModernRequest(request *http.Request) (modernWireRequest, error) {
	var wire modernWireRequest
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return wire, err
	}
	err = json.Unmarshal(body, &wire)
	if err != nil {
		return wire, err
	}
	var params struct {
		Meta struct {
			ProtocolVersion string          `json:"io.modelcontextprotocol/protocolVersion"`
			Caps            json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(wire.Params, &params); err != nil {
		return wire, err
	}
	wire.Meta = params.Meta
	return wire, nil
}

func responseForID(id json.RawMessage, result string) *http.Response {
	body := `{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`
	return response(http.StatusOK, "application/json", body)
}

func rawModernCall(t *testing.T, method, id, params string) *jsonrpc.Request {
	t.Helper()
	return &jsonrpc.Request{ID: mustID(t, id), Method: method, Params: json.RawMessage(params)}
}

func TestModernCallNameHeadersAreDerivedAndEncoded(t *testing.T) {
	tests := []struct {
		name       string
		wantHeader string
	}{
		{name: "echo", wantHeader: "echo"},
		{name: "internal space", wantHeader: "internal space"},
		{name: "echo_日本語", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte("echo_日本語")) + "?="},
		{name: strings.Repeat("é", 128), wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("é", 128))) + "?="},
		{name: " leading", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte(" leading")) + "?="},
		{name: "trailing ", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte("trailing ")) + "?="},
		{name: "bad\r\nX-Injected: yes", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte("bad\r\nX-Injected: yes")) + "?="},
		{name: "=?base64?YWJj?=", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte("=?base64?YWJj?=")) + "?="},
		{name: "=?base64?literal?=", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte("=?base64?literal?=")) + "?="},
		{name: "=?base64??=", wantHeader: "=?base64?" + base64.StdEncoding.EncodeToString([]byte("=?base64??=")) + "?="},
	}
	for index, tc := range tests {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
				wire, err := readModernRequest(request)
				if err != nil {
					t.Errorf("decode request: %v", err)
					return response(http.StatusBadRequest, "text/plain", ""), nil
				}
				switch wire.Method {
				case "server/discover":
					if request.Header.Get("Mcp-Method") != wire.Method {
						t.Errorf("discover header method=%q, body=%q", request.Header.Get("Mcp-Method"), wire.Method)
					}
					return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
				case "tools/call":
					if string(wire.ID) != `"call-id"` {
						t.Errorf("call request ID=%s, want \"call-id\"", wire.ID)
					}
					var params struct {
						Name      string         `json:"name"`
						Arguments map[string]any `json:"arguments"`
					}
					if err := json.Unmarshal(wire.Params, &params); err != nil {
						t.Errorf("decode call params: %v", err)
					}
					methodHeader := request.Header.Get("Mcp-Method")
					nameHeader := request.Header.Get("Mcp-Name")
					decodedName := nameHeader
					if strings.HasPrefix(nameHeader, "=?base64?") && strings.HasSuffix(nameHeader, "?=") {
						encoded := nameHeader[len("=?base64?") : len(nameHeader)-2]
						decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
						if err != nil {
							t.Errorf("decode name header %q: %v", nameHeader, err)
						} else {
							decodedName = string(decoded)
						}
					}
					if methodHeader != wire.Method || methodHeader != "tools/call" || params.Name != tc.name || decodedName != tc.name || nameHeader != tc.wantHeader {
						t.Errorf("headers/body method=%q/%q name=%q/%q decoded=%q, want header=%q name=%q", methodHeader, wire.Method, nameHeader, params.Name, decodedName, tc.wantHeader, tc.name)
					}
					if params.Arguments["method"] != "spoof/method" || params.Arguments["name"] != "spoof/name" {
						t.Errorf("spoof fields missing from arguments: %#v", params.Arguments)
					}
					if len(request.Header.Values("X-Injected")) != 0 {
						t.Errorf("injected header present: %q", request.Header.Values("X-Injected"))
					}
					return responseForID(wire.ID, `{"content":[]}`), nil
				default:
					t.Errorf("peer saw method %q", wire.Method)
					return response(http.StatusBadRequest, "text/plain", ""), nil
				}
			})
			conn := startUnnegotiatedConnection(t, transport)
			t.Cleanup(func() { _ = conn.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			mustWrite(t, conn.Write(ctx, rawModernCall(t, "server/discover", "discover", modernParams)), nil, "discover failed")
			if _, err := conn.Read(ctx); err != nil {
				t.Fatalf("read discover response: %v", err)
			}
			params, err := json.Marshal(map[string]any{
				"_meta": map[string]any{
					"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
					"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				},
				"name":      tc.name,
				"arguments": map[string]any{"method": "spoof/method", "name": "spoof/name"},
			})
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, conn.Write(ctx, rawModernCall(t, "tools/call", "call-id", string(params))), nil, "tools/call failed")
			message, err := conn.Read(ctx)
			if err != nil {
				t.Fatalf("read tools/call response: %v", err)
			}
			result, ok := message.(*jsonrpc.Response)
			if !ok || result.Error != nil || result.ID.Raw() != "call-id" {
				t.Fatalf("call response=%T %#v, want id call-id", message, message)
			}
		})
	}
}

func TestStatelessPeerSpeaks20260728WithoutInitialize(t *testing.T) {
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		if request.Header.Get("Mcp-Session-Id") != "" {
			t.Errorf("stateless request carried session id %q", request.Header.Get("Mcp-Session-Id"))
		}
		switch wire.Method {
		case "server/discover":
			if request.Header.Get("Mcp-Method") != "server/discover" || request.Header.Get("Mcp-Protocol-Version") != "2026-07-28" || wire.Meta.ProtocolVersion != "2026-07-28" || len(wire.Meta.Caps) == 0 {
				t.Errorf("invalid discover headers/meta: method=%q version=%q meta=%q caps=%q", request.Header.Get("Mcp-Method"), request.Header.Get("Mcp-Protocol-Version"), wire.Meta.ProtocolVersion, wire.Meta.Caps)
			}
			return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
		case "tools/list":
			if request.Header.Get("Mcp-Method") != "tools/list" || request.Header.Get("Mcp-Name") != "" || request.Header.Get("Mcp-Protocol-Version") != "2026-07-28" || wire.Meta.ProtocolVersion != "2026-07-28" {
				t.Errorf("invalid tools/list headers/meta")
			}
			return responseForID(wire.ID, `{"tools":[{"name":"echo","description":"e","inputSchema":{"type":"object"}}]}`), nil
		case "tools/call":
			if request.Header.Get("Mcp-Method") != "tools/call" || request.Header.Get("Mcp-Name") != "echo" || request.Header.Get("Mcp-Protocol-Version") != "2026-07-28" || wire.Meta.ProtocolVersion != "2026-07-28" {
				t.Errorf("invalid tools/call headers/meta")
			}
			return responseForID(wire.ID, `{"content":[{"type":"text","text":"ok"}]}`), nil
		default:
			t.Errorf("peer saw %q", wire.Method)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	ctx := context.Background()
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	listing, err := session.ListTools(ctx, nil)
	if err != nil || len(listing.Tools) != 1 || listing.Tools[0].Name != "echo" {
		t.Fatalf("ListTools got (%v, %v), want exactly echo", listing, err)
	}
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
}

func TestDiscoverRefusalReopensInitializeEra(t *testing.T) {
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		switch wire.Method {
		case "server/discover":
			body := `{"jsonrpc":"2.0","id":` + string(wire.ID) + `,"error":{"code":-32601,"message":"m"}}`
			return response(http.StatusOK, "application/json", body), nil
		case "initialize":
			if request.Header.Get("Mcp-Method") != "" {
				t.Errorf("initialize carried Mcp-Method %q", request.Header.Get("Mcp-Method"))
			}
			result := responseForID(wire.ID, `{"protocolVersion":"2025-06-18"}`)
			result.Header.Set("Mcp-Session-Id", "s1")
			return result, nil
		case "notifications/initialized":
			return response(http.StatusAccepted, "", ""), nil
		case "tools/list":
			if request.Header.Get("Mcp-Method") != "" || request.Header.Get("Mcp-Session-Id") != "s1" || request.Header.Get("Mcp-Protocol-Version") != "2025-06-18" {
				t.Errorf("legacy tools/list headers changed")
			}
			return responseForID(wire.ID, `{}`), nil
		default:
			t.Errorf("peer saw %q", wire.Method)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
	})
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", "probe", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)), nil, "discover refusal write failed")
	if result, ok := mustRead(t, conn).(*jsonrpc.Response); !ok || result.Error == nil {
		t.Fatal("discover refusal was not delivered")
	}
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "initialize", "init", `{"protocolVersion":"2025-06-18"}`)), nil, "fallback initialize failed")
	mustRead(t, conn)
	if conn.SessionID() != "s1" {
		t.Fatal("fallback initialize session id was not captured")
	}
	mustWrite(t, conn.Write(context.Background(), notify("notifications/initialized")), nil, "fallback notification failed")
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "tools/list", "list", `{}`)), nil, "fallback tools/list failed")
	mustRead(t, conn)
	_ = conn.Close()
}

func TestDiscoverErrorUsesFixedLocalText(t *testing.T) {
	const synthetic = "synthetic-peer-secret"
	tests := []struct {
		code     int
		wantCode int
	}{
		{code: -32601, wantCode: -32601},
		{code: -32022, wantCode: -32022},
		{code: -32004, wantCode: -32022},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.code), func(t *testing.T) {
			transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
				wire, err := readModernRequest(request)
				if err != nil {
					return nil, err
				}
				if wire.Method != "server/discover" {
					t.Errorf("peer saw method %q, want server/discover", wire.Method)
				}
				body := `{"jsonrpc":"2.0","id":` + string(wire.ID) + `,"error":{"code":` + strconv.Itoa(tt.code) + `,"message":"` + synthetic + `","data":{"supported":["2026-07-28","` + synthetic + `"],"requested":"` + synthetic + `","extra":"` + synthetic + `"}}}`
				return response(http.StatusOK, "application/json", body), nil
			})
			conn := startUnnegotiatedConnection(t, transport)
			t.Cleanup(func() { _ = conn.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			mustWrite(t, conn.Write(ctx, rawModernCall(t, "server/discover", "discover", modernParams)), nil, "discover write failed")
			message, err := conn.Read(ctx)
			if err != nil {
				t.Fatalf("read discover response: %v", err)
			}
			result, ok := message.(*jsonrpc.Response)
			if !ok || result.Error == nil {
				t.Fatalf("discover response = %T (%v), want JSON-RPC error", message, message)
			}
			rpcError, ok := result.Error.(*jsonrpc.Error)
			if !ok {
				t.Fatalf("discover error type = %T, want *jsonrpc.Error", result.Error)
			}
			if rpcError.Code != int64(tt.wantCode) {
				t.Errorf("error code = %d, want %d", rpcError.Code, tt.wantCode)
			}
			if rpcError.Message != "remote MCP discovery refused" {
				t.Errorf("error message = %q, want fixed local text", rpcError.Message)
			}
			if strings.Contains(rpcError.Error(), synthetic) || strings.Contains(string(rpcError.Data), synthetic) {
				t.Errorf("peer-controlled text leaked: error=%q data=%s", rpcError.Error(), rpcError.Data)
			}
			var data struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			}
			if err := json.Unmarshal(rpcError.Data, &data); err != nil {
				t.Fatalf("decode sanitized error data %s: %v", rpcError.Data, err)
			}
			if len(data.Supported) != 1 || data.Supported[0] != "2026-07-28" {
				t.Errorf("supported = %q, want only [2026-07-28]", data.Supported)
			}
			if data.Requested != "2026-07-28" {
				t.Errorf("requested = %q, want 2026-07-28", data.Requested)
			}
		})
	}
}

func TestModernLockRefusesLegacyMethodsAndSessionHeader(t *testing.T) {
	t.Run("successful discover locks modern era", func(t *testing.T) {
		var posts atomic.Int32
		transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
			posts.Add(1)
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			if wire.Method == "server/discover" {
				return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"]}`), nil
			}
			if wire.Method == "tools/list" {
				if request.Header.Get("Mcp-Method") != "tools/list" {
					t.Errorf("missing tools/list Mcp-Method")
				}
				return responseForID(wire.ID, `{}`), nil
			}
			if wire.Method == "notifications/cancelled" {
				if request.Header.Get("Mcp-Method") != "notifications/cancelled" || request.Header.Get("Mcp-Protocol-Version") != "2026-07-28" || request.Header.Get("Mcp-Session-Id") != "" {
					t.Errorf("invalid cancelled notification headers")
				}
				return response(http.StatusAccepted, "", ""), nil
			}
			t.Errorf("peer saw %q", wire.Method)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		})
		conn := startUnnegotiatedConnection(t, transport)
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", "disc", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)), nil, "discover failed")
		mustRead(t, conn)
		before := posts.Load()
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", "repeat", `{}`)), errExchange, "repeat discover was accepted")
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "initialize", "init", `{}`)), errExchange, "modern initialize was accepted")
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "ping", "ping", `{}`)), errExchange, "modern ping was accepted")
		if posts.Load() != before {
			t.Fatal("refused legacy methods contacted peer")
		}
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "tools/list", "list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)), nil, "modern tools/list failed")
		mustRead(t, conn)
		if posts.Load() != 2 {
			t.Fatal("discover and tools/list did not produce exactly two POSTs")
		}
		cancelled := &jsonrpc.Request{Method: "notifications/cancelled", Params: json.RawMessage(`{"requestId":"r"}`)}
		mustWrite(t, conn.Write(context.Background(), cancelled), nil, "cancelled notification failed")
		if posts.Load() != 3 {
			t.Fatal("cancelled notification did not produce a POST")
		}
		_ = conn.Close()
	})

	t.Run("session on successful discover is refused", func(t *testing.T) {
		var posts atomic.Int32
		transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
			posts.Add(1)
			wire, err := readModernRequest(request)
			if err != nil {
				t.Errorf("decode request: %v", err)
				return response(http.StatusBadRequest, "text/plain", ""), nil
			}
			result := responseForID(wire.ID, `{"supportedVersions":["2026-07-28"]}`)
			result.Header.Set("Mcp-Session-Id", "s9")
			return result, nil
		})
		conn := startUnnegotiatedConnection(t, transport)
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", "disc", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)), errExchange, "session-bearing discover was accepted")
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := conn.Read(ctx); err == nil {
			t.Fatal("refused discover response was delivered")
		}
		if conn.SessionID() != "" {
			t.Fatal("session id was stored")
		}
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "tools/list", "list", `{}`)), errExchange, "tools/list admitted before successful discover")
		if posts.Load() != 1 {
			t.Fatal("refused follow-up contacted peer")
		}
		_ = conn.Close()
	})
}

func TestDiscoverAttemptsAreBoundedBeforeSuccess(t *testing.T) {
	var posts atomic.Int32
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		posts.Add(1)
		switch wire.Method {
		case "server/discover":
			body := `{"jsonrpc":"2.0","id":` + string(wire.ID) + `,"error":{"code":-32022,"message":"unsupported"}}`
			return response(http.StatusOK, "application/json", body), nil
		case "initialize":
			return responseForID(wire.ID, `{"protocolVersion":"2025-06-18"}`), nil
		default:
			t.Errorf("peer saw %q", wire.Method)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
	})
	conn := startUnnegotiatedConnection(t, transport)
	for _, id := range []string{"discover-1", "discover-2"} {
		mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", id, `{}`)), nil, "discover failed")
		mustRead(t, conn)
	}
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", "discover-3", `{}`)), errExchange, "third discover was accepted")
	if posts.Load() != 2 {
		t.Fatalf("discover refusal contacted peer: POSTs=%d, want 2", posts.Load())
	}
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "initialize", "initialize", `{}`)), nil, "initialize after refused discovers failed")
	mustRead(t, conn)
	if posts.Load() != 3 {
		t.Fatalf("initialize POST count = %d, want 3", posts.Load())
	}
	_ = conn.Close()
}

func TestUnsupportedVersionDataRetriesStayStateless(t *testing.T) {
	var discovers, lists, initializes atomic.Int32
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		switch wire.Method {
		case "server/discover":
			if discovers.Add(1) == 1 {
				body := `{"jsonrpc":"2.0","id":` + string(wire.ID) + `,"error":{"code":-32022,"message":"m","data":{"supported":["2026-07-28"],"requested":"2026-07-28"}}}`
				return response(http.StatusOK, "application/json", body), nil
			}
			return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`), nil
		case "tools/list":
			lists.Add(1)
			return responseForID(wire.ID, `{"tools":[{"name":"echo","description":"e","inputSchema":{"type":"object"}}]}`), nil
		case "initialize":
			initializes.Add(1)
			t.Errorf("peer saw initialize")
			return response(http.StatusBadRequest, "text/plain", ""), nil
		default:
			t.Errorf("peer saw %q", wire.Method)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), transport, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	listing, err := session.ListTools(context.Background(), nil)
	if err != nil || len(listing.Tools) != 1 {
		t.Fatalf("ListTools failed: listing=%v err=%v", listing, err)
	}
	if discovers.Load() != 2 || lists.Load() != 1 || initializes.Load() != 0 {
		t.Fatalf("unexpected requests: discover=%d tools/list=%d initialize=%d", discovers.Load(), lists.Load(), initializes.Load())
	}
}

func TestModernRequestsRejectMissingNameAndUnsafeVersion(t *testing.T) {
	var posts atomic.Int32
	transport, _ := testTransport(t, func(request *http.Request) (*http.Response, error) {
		posts.Add(1)
		wire, err := readModernRequest(request)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return response(http.StatusBadRequest, "text/plain", ""), nil
		}
		return responseForID(wire.ID, `{"supportedVersions":["2026-07-28"]}`), nil
	})
	conn := startUnnegotiatedConnection(t, transport)
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "server/discover", "disc", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)), nil, "discover failed")
	mustRead(t, conn)
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "tools/list", "list", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)), nil, "tools/list failed")
	mustRead(t, conn)
	if posts.Load() != 2 {
		t.Fatal("discover and tools/list did not produce exactly two POSTs")
	}
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "tools/call", "missing", `{}`)), errExchange, "tools/call without name accepted")
	mustWrite(t, conn.Write(context.Background(), rawModernCall(t, "tools/list", "unsafe", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28\r\nX: y"}}`)), errExchange, "unsafe protocol-version header accepted")
	if posts.Load() != 2 {
		t.Fatal("locally refused modern requests contacted peer")
	}
	_ = conn.Close()
}
