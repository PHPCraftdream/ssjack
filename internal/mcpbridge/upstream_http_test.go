package mcpbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpexchange"
	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
)

const upstreamHTTPModernVersion = "2026-07-28"

type upstreamHTTPRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		ProtocolVersion string `json:"protocolVersion"`
		Name            string `json:"name"`
		Meta            struct {
			ProtocolVersion string          `json:"io.modelcontextprotocol/protocolVersion"`
			Capabilities    json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
		} `json:"_meta"`
	} `json:"params"`
}

type upstreamHTTPObserved struct {
	Method string
	Meta   upstreamHTTPRequest
	Header http.Header
}

type upstreamHTTPPeer struct {
	t            *testing.T
	refusal      string
	version      string
	mode         string
	parkDiscover bool
	parkStarted  chan struct{}
	parkDone     chan struct{}
	mu           sync.Mutex
	seen         []upstreamHTTPObserved
	discovers    int
	callCount    int
	cleared      atomic.Bool
}

func (p *upstreamHTTPPeer) RoundTrip(request *http.Request) (*http.Response, error) {
	p.t.Helper()
	body, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		p.t.Errorf("request body decode exceeded bound or failed: %v", err)
		return nil, fmt.Errorf("bounded request decode failed")
	}
	var wire upstreamHTTPRequest
	err = json.Unmarshal(body, &wire)
	if err != nil || wire.Method == "" || wire.Method != "notifications/initialized" && (len(wire.ID) == 0 || string(wire.ID) == "null") {
		p.t.Errorf("invalid JSON-RPC request: %v", err)
		return nil, fmt.Errorf("invalid request")
	}
	p.mu.Lock()
	p.seen = append(p.seen, upstreamHTTPObserved{Method: wire.Method, Meta: wire, Header: request.Header.Clone()})
	if wire.Method == "server/discover" {
		p.discovers++
	}
	if wire.Method == "tools/call" {
		p.callCount++
	}
	discoverCount := p.discovers
	p.mu.Unlock()

	if wire.Method == "notifications/initialized" {
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: http.NoBody, ContentLength: 0}, nil
	}
	if wire.Method == "server/discover" {
		if p.parkDiscover {
			body := &upstreamHTTPParkedBody{ctx: request.Context(), started: p.parkStarted, done: p.parkDone}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, ContentLength: 4096}, nil
		}
		if p.refusal != "" {
			switch p.refusal {
			case "rpc-method":
				return upstreamHTTPRPCError(wire.ID, -32601, "method not found", ""), nil
			case "rpc-method-secret":
				return upstreamHTTPRPCError(wire.ID, -32601, "synthetic-peer-marker method refusal", ""), nil
			case "rpc-version":
				data := fmt.Sprintf(`,"data":{"supported":[%q],"requested":%q}`, p.version, upstreamHTTPModernVersion)
				return upstreamHTTPRPCError(wire.ID, -32022, "unsupported", data), nil
			case "retry-modern", "retry-exhausted":
				if p.refusal == "retry-exhausted" || discoverCount == 1 {
					data := `,"data":{"supported":["2026-07-28"],"requested":"2026-07-28","secret":"synthetic-secret-extra"}`
					return upstreamHTTPRPCError(wire.ID, -32022, "synthetic-secret-message", data), nil
				}
			case "draft-version":
				data := fmt.Sprintf(`,"data":{"supported":[%q],"requested":%q}`, p.version, upstreamHTTPModernVersion)
				return upstreamHTTPRPCError(wire.ID, -32004, "draft protocol version", data), nil
			case "http-405":
				return upstreamHTTPResponse(http.StatusMethodNotAllowed, "text/plain", "not supported"), nil
			case "legacy-only":
				return upstreamHTTPRPCResult(wire.ID, fmt.Sprintf(`{"supportedVersions":[%q],"capabilities":{}}`, p.version)), nil
			}
		}
		response := upstreamHTTPRPCResult(wire.ID, `{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"resultType":"complete","ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"fixture","version":"1"}}}`)
		response.Header.Set("Mcp-Protocol-Version", upstreamHTTPModernVersion)
		return response, nil
	}
	switch wire.Method {
	case "initialize":
		if p.refusal == "rpc-method-secret" {
			return upstreamHTTPResponse(http.StatusInternalServerError, "text/plain", "synthetic-peer-marker initialize failure"), nil
		}
		response := upstreamHTTPRPCResult(wire.ID, fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}`, p.version))
		response.Header.Set("Mcp-Session-Id", "s1")
		return response, nil
	case "tools/list":
		if p.refusal == "" || p.refusal == "retry-modern" {
			return upstreamHTTPRPCResult(wire.ID, `{"tools":[{"name":"echo","description":"echo tool","inputSchema":{"type":"object"}}],"resultType":"complete","ttlMs":0,"cacheScope":"private"}`), nil
		}
		return upstreamHTTPRPCResult(wire.ID, `{"tools":[{"name":"echo","description":"echo tool","inputSchema":{"type":"object"}}]}`), nil
	case "tools/call":
		if p.mode == "input-required" {
			return upstreamHTTPRPCResult(wire.ID, `{"resultType":"input_required","inputRequests":{},"requestState":"synthetic"}`), nil
		}
		if p.refusal == "" || p.refusal == "retry-modern" {
			return upstreamHTTPRPCResult(wire.ID, `{"resultType":"complete","ttlMs":0,"cacheScope":"private","content":[{"type":"text","text":"ok"}]}`), nil
		}
		return upstreamHTTPRPCResult(wire.ID, `{"content":[{"type":"text","text":"ok"}]}`), nil
	default:
		p.t.Errorf("unexpected upstream method %q", wire.Method)
		return upstreamHTTPResponse(http.StatusBadRequest, "text/plain", "unexpected method"), nil
	}
}

func upstreamHTTPResponse(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func upstreamHTTPRPCResult(id json.RawMessage, result string) *http.Response {
	body, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{"2.0", id, json.RawMessage(result)})
	if err != nil {
		panic(err)
	}
	return upstreamHTTPResponse(http.StatusOK, "application/json", string(body))
}

func upstreamHTTPRPCError(id json.RawMessage, code int, message, extra string) *http.Response {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q%s}}`, id, code, message, extra)
	return upstreamHTTPResponse(http.StatusOK, "application/json", body)
}

func newUpstreamHTTPHarness(t *testing.T, peer *upstreamHTTPPeer) (*Runtime, *testHandle) {
	t.Helper()
	lifetime, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	flow, err := mcpflow.New(lifetime, peer, func(request *http.Request) (*http.Request, error) {
		return request, nil
	}, func() { peer.cleared.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := flow.Close(ctx); err != nil {
			t.Errorf("flow cleanup: %v", err)
		}
	})
	client := &http.Client{Transport: flow, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	transport, err := mcpexchange.New("https://upstream.invalid/mcp", client)
	if err != nil {
		t.Fatal(err)
	}
	handle := &testHandle{transport: transport}
	runtime := testRuntime(t, lifetime, handle, func(ctx context.Context) error { return flow.Close(ctx) }, false)
	return runtime, handle
}

func upstreamHTTPSnapshot(peer *upstreamHTTPPeer) []upstreamHTTPObserved {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return append([]upstreamHTTPObserved(nil), peer.seen...)
}

func upstreamHTTPCounts(peer *upstreamHTTPPeer) (discovers, calls int) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return peer.discovers, peer.callCount
}

func upstreamHTTPDescribeAndCall(t *testing.T, runtime *Runtime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	inventory, err := runtime.describe(ctx, 0)
	if err != nil {
		if err.Error() != errInventory.Error() {
			t.Fatalf("describe exposed a non-fixed error: %q", err.Error())
		}
		t.Fatalf("describe returned fixed error %q", err.Error())
	}
	if len(inventory.Tools) != 1 || !strings.HasSuffix(inventory.Tools[0].Name, "echo") || inventory.Tools[0].Schema["type"] != "object" {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
	call, err := runtime.call(ctx, CallInput{Ordinal: 0, Tool: inventory.Tools[0].Name, Arguments: `{"value":"hello"}`})
	if err != nil {
		if err.Error() != errCallFailed.Error() {
			t.Fatalf("call exposed a non-fixed error: %q", err.Error())
		}
		t.Fatalf("call returned fixed error %q", err.Error())
	}
	var result struct {
		ResultType string `json:"resultType"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal([]byte(call.Result), &result); err != nil || len(result.Content) != 1 || result.Content[0].Type != "text" || result.Content[0].Text != "ok" || result.IsError {
		t.Fatalf("unexpected call content %s (decode error %v)", call.Result, err)
	}
}

func assertUpstreamHTTPTakenOnce(t *testing.T, handle *testHandle) {
	t.Helper()
	if got := handle.takes.Load(); got != 1 {
		t.Fatalf("TakeTransport called %d times, want once", got)
	}
}

func TestUpstreamHTTPModernOnlyListAndCall(t *testing.T) {
	peer := &upstreamHTTPPeer{t: t}
	runtime, handle := newUpstreamHTTPHarness(t, peer)
	upstreamHTTPDescribeAndCall(t, runtime)

	session := runtime.slots[0].session
	if session == nil || session.InitializeResult() == nil || session.InitializeResult().ServerInfo == nil || session.InitializeResult().ServerInfo.Name != "fixture" {
		t.Fatalf("installed session InitializeResult=%+v, want server info name fixture", session)
	}

	assertUpstreamHTTPTakenOnce(t, handle)
	seen := upstreamHTTPSnapshot(peer)
	if len(seen) != 3 || seen[0].Method != "server/discover" || seen[1].Method != "tools/list" || seen[2].Method != "tools/call" {
		t.Fatalf("modern peer saw requests %+v, want discover, list, call exactly once", seen)
	}
	for _, request := range seen {
		if request.Header.Get("Mcp-Method") != request.Method || request.Header.Get("Mcp-Protocol-Version") != upstreamHTTPModernVersion || request.Header.Get("Mcp-Session-Id") != "" || request.Meta.Params.Meta.ProtocolVersion != upstreamHTTPModernVersion {
			t.Errorf("invalid modern request %q headers/meta: %v / %+v", request.Method, request.Header, request.Meta.Params.Meta)
		}
		var capabilities map[string]json.RawMessage
		if json.Unmarshal(request.Meta.Params.Meta.Capabilities, &capabilities) != nil || capabilities == nil {
			t.Errorf("modern %s request lacks a client capabilities object: %s", request.Method, request.Meta.Params.Meta.Capabilities)
		}
		wantName := ""
		if request.Method == "tools/call" {
			wantName = "echo"
		}
		if request.Header.Get("Mcp-Name") != wantName || request.Meta.Params.Name != wantName {
			t.Errorf("modern %s name header/param=%q/%q, want %q", request.Method, request.Header.Get("Mcp-Name"), request.Meta.Params.Name, wantName)
		}
		if request.Method == "initialize" {
			t.Error("modern peer received initialize")
		}
	}
}

func TestUpstreamHTTPPinnedFallback(t *testing.T) {
	for _, refusal := range []string{"rpc-method", "rpc-version", "http-405", "legacy-only", "draft-version"} {
		for _, version := range []string{"2024-11-05", "2025-03-26", "2025-06-18"} {
			t.Run(refusal+"/"+version, func(t *testing.T) {
				peer := &upstreamHTTPPeer{t: t, refusal: refusal, version: version}
				runtime, handle := newUpstreamHTTPHarness(t, peer)
				upstreamHTTPDescribeAndCall(t, runtime)
				assertUpstreamHTTPTakenOnce(t, handle)
				seen := upstreamHTTPSnapshot(peer)
				want := []string{"server/discover", "initialize", "notifications/initialized", "tools/list", "tools/call"}
				if len(seen) != len(want) {
					t.Fatalf("fallback peer saw %d POSTs, want five: %+v", len(seen), seen)
				}
				for i, request := range seen {
					if request.Method != want[i] {
						t.Errorf("POST %d method=%q, want %q", i+1, request.Method, want[i])
					}
					if i == 0 {
						if request.Header.Get("Mcp-Method") != "server/discover" || request.Header.Get("Mcp-Protocol-Version") != upstreamHTTPModernVersion || request.Header.Get("Mcp-Session-Id") != "" || request.Meta.Params.Meta.ProtocolVersion != upstreamHTTPModernVersion {
							t.Errorf("invalid fallback discovery probe headers/meta: %v / %+v", request.Header, request.Meta.Params.Meta)
						}
						continue
					}
					if request.Header.Get("Mcp-Method") != "" || request.Header.Get("Mcp-Name") != "" {
						t.Errorf("legacy %s carried modern method/name headers: %v", request.Method, request.Header)
					}
					if i == 1 {
						if request.Meta.Params.ProtocolVersion != "2025-06-18" || request.Header.Get("Mcp-Protocol-Version") != "" || request.Header.Get("Mcp-Session-Id") != "" {
							t.Errorf("initialize params/headers mismatch: %+v / %v", request.Meta.Params, request.Header)
						}
					} else if request.Header.Get("Mcp-Session-Id") != "s1" || request.Header.Get("Mcp-Protocol-Version") != version {
						t.Errorf("legacy %s session/version headers=%v, want s1/%s", request.Method, request.Header, version)
					}
				}
			})
		}
	}
}

func TestUpstreamHTTPUnsupportedVersionBounded(t *testing.T) {
	for _, refusal := range []string{"retry-modern", "retry-exhausted"} {
		t.Run(refusal, func(t *testing.T) {
			peer := &upstreamHTTPPeer{t: t, refusal: refusal, version: "2025-06-18"}
			runtime, handle := newUpstreamHTTPHarness(t, peer)
			upstreamHTTPDescribeAndCall(t, runtime)
			assertUpstreamHTTPTakenOnce(t, handle)
			discovers, calls := upstreamHTTPCounts(peer)
			if discovers != 2 || calls != 1 {
				t.Fatalf("peer saw discovers=%d calls=%d, want exactly two discovers and one call", discovers, calls)
			}
			seen := upstreamHTTPSnapshot(peer)
			initializes := 0
			for _, request := range seen {
				if request.Method == "initialize" {
					initializes++
					if request.Meta.Params.ProtocolVersion != upstreamProtocolVersion {
						t.Errorf("initialize offered %q, want pinned %q", request.Meta.Params.ProtocolVersion, upstreamProtocolVersion)
					}
				}
			}
			wantInitializes := 0
			if refusal == "retry-exhausted" {
				wantInitializes = 1
			}
			if initializes != wantInitializes {
				t.Fatalf("peer saw %d initialize requests, want %d: %+v", initializes, wantInitializes, seen)
			}
		})
	}
}

func TestUpstreamHTTPInputRequiredFailsWithoutReplay(t *testing.T) {
	peer := &upstreamHTTPPeer{t: t, mode: "input-required"}
	runtime, handle := newUpstreamHTTPHarness(t, peer)
	inventory, err := runtime.describe(context.Background(), 0)
	if err != nil || len(inventory.Tools) != 1 {
		t.Fatalf("describe failed: inventory=%+v err=%v", inventory, err)
	}
	input := CallInput{Ordinal: 0, Tool: inventory.Tools[0].Name, Arguments: `{}`}
	if _, err := runtime.call(context.Background(), input); err != errCallFailed {
		t.Fatalf("first call error=%v, want exact errCallFailed", err)
	}
	if _, err := runtime.call(context.Background(), input); err != errInventory {
		t.Fatalf("second call error=%v, want exact binding failure errInventory", err)
	}
	_, calls := upstreamHTTPCounts(peer)
	if calls != 1 {
		t.Fatalf("peer saw %d calls, want one with no replay", calls)
	}
	assertUpstreamHTTPTakenOnce(t, handle)
}

func TestUpstreamHTTPDiscoveryErrorTextIsFixed(t *testing.T) {
	peer := &upstreamHTTPPeer{t: t, refusal: "rpc-method-secret", version: upstreamProtocolVersion}
	runtime, _ := newUpstreamHTTPHarness(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := runtime.describe(ctx, 0)
	if err == nil || err.Error() != errInventory.Error() || strings.Contains(err.Error(), "synthetic-peer-marker") {
		t.Fatalf("describe error=%v, want only fixed %q", err, errInventory)
	}
	seen := upstreamHTTPSnapshot(peer)
	if len(seen) != 2 || seen[0].Method != "server/discover" || seen[1].Method != "initialize" {
		t.Fatalf("peer saw requests %+v, want server/discover then initialize exactly once", seen)
	}
	discovers, calls := upstreamHTTPCounts(peer)
	if discovers != 1 || calls != 0 {
		t.Fatalf("peer saw discovers=%d calls=%d, want one discovery and no calls", discovers, calls)
	}
}

type upstreamHTTPParkedBody struct {
	ctx     context.Context
	started chan struct{}
	done    chan struct{}
	start   sync.Once
	finish  sync.Once
}

func (b *upstreamHTTPParkedBody) Read([]byte) (int, error) {
	b.start.Do(func() { close(b.started) })
	<-b.ctx.Done()
	b.finish.Do(func() { close(b.done) })
	return 0, context.Canceled
}
func (*upstreamHTTPParkedBody) Close() error { return nil }

func TestUpstreamHTTPShutdownDuringDiscoveryBodyRead(t *testing.T) {
	started, bodyDone := make(chan struct{}), make(chan struct{})
	peer := &upstreamHTTPPeer{t: t, parkDiscover: true, parkStarted: started, parkDone: bodyDone}
	runtime, handle := newUpstreamHTTPHarness(t, peer)
	result := make(chan error, 1)
	exited := make(chan struct{})
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := runtime.Close(closeCtx); err != nil {
			t.Errorf("runtime cleanup: %v", err)
		}
		joinExited(t, exited, "describe worker did not exit after shutdown")
	})
	go func() {
		defer close(exited)
		_, err := runtime.describe(context.Background(), 0)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("discovery response body was not read")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Close(closeCtx); err != nil {
		t.Fatalf("runtime close failed: %v", err)
	}
	select {
	case err := <-result:
		if err == nil || err.Error() != errInventory.Error() {
			t.Fatalf("describe error=%v, want fixed %q", err, errInventory)
		}
	case <-time.After(time.Second):
		t.Fatal("describe worker did not return after shutdown")
	}
	joinExited(t, exited, "describe worker did not exit after shutdown")
	select {
	case <-bodyDone:
	case <-time.After(time.Second):
		t.Fatal("parked discovery body did not join after cancellation")
	}
	if !peer.cleared.Load() {
		t.Fatal("flow clear callback was not called during shutdown")
	}
	assertUpstreamHTTPTakenOnce(t, handle)
}

var _ http.RoundTripper = (*upstreamHTTPPeer)(nil)
