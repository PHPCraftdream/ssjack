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

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpexchange"
	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/PHPCraftdream/ssjack/internal/wire"
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

// eraConnection scripts one upstream peer's JSON-RPC responses in order and
// records every written request so tests can pin the handshake era.
type eraConnection struct {
	started chan struct{}
	closed  chan struct{}
	written chan *jsonrpc.Request
	seenMu  sync.Mutex
	seen    []*jsonrpc.Request
	script  []func(req *jsonrpc.Request) jsonrpc.Message
	served  int // only the SDK's single reader goroutine touches this
	once    sync.Once
}

func newEraConnection(script ...func(req *jsonrpc.Request) jsonrpc.Message) *eraConnection {
	return &eraConnection{started: make(chan struct{}), closed: make(chan struct{}), written: make(chan *jsonrpc.Request, 16), script: script}
}

func (c *eraConnection) Write(_ context.Context, m jsonrpc.Message) error {
	request, _ := m.(*jsonrpc.Request)
	if request == nil {
		return nil
	}
	c.seenMu.Lock()
	c.seen = append(c.seen, request)
	c.seenMu.Unlock()
	select {
	case c.written <- request:
	default:
		return io.ErrShortWrite
	}
	return nil
}

func (c *eraConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case <-c.started:
	default:
		close(c.started)
	}
	for {
		var request *jsonrpc.Request
		select {
		case request = <-c.written:
		case <-c.closed:
			return nil, io.EOF
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if !request.ID.IsValid() {
			continue // notifications need no scripted reply
		}
		if c.served >= len(c.script) {
			select {
			case <-c.closed:
				return nil, io.EOF
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		response := c.script[c.served](request)
		c.served++
		return response, nil
	}
}

func (c *eraConnection) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (*eraConnection) SessionID() string { return "" }

func resultFor(req *jsonrpc.Request, result string) jsonrpc.Message {
	return &jsonrpc.Response{ID: req.ID, Result: json.RawMessage(result)}
}

func discoverOK(req *jsonrpc.Request) jsonrpc.Message {
	return resultFor(req, `{"supportedVersions":["2026-07-28"],"capabilities":{}}`)
}

// -32022 is the 2026-07-28 UnsupportedProtocolVersion code the pinned SDK
// negotiates on; the SDK's public jsonrpc package does not export it.
func discoverUnsupported(req *jsonrpc.Request) jsonrpc.Message {
	return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: -32022, Message: "unsupported protocol version", Data: json.RawMessage(`{"supported":["2026-07-28"],"requested":"2026-07-28"}`)}}
}

func discoverMethodNotFound(req *jsonrpc.Request) jsonrpc.Message {
	return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"}}
}

func initializeOK(version string) func(req *jsonrpc.Request) jsonrpc.Message {
	body, _ := json.Marshal(mcp.InitializeResult{ProtocolVersion: version, Capabilities: &mcp.ServerCapabilities{}, ServerInfo: &mcp.Implementation{Name: "fixture", Version: "1"}})
	return func(req *jsonrpc.Request) jsonrpc.Message { return resultFor(req, string(body)) }
}

func toolsOK(req *jsonrpc.Request) jsonrpc.Message {
	return resultFor(req, `{"tools":[{"name":"echo","description":"echo tool","inputSchema":{"type":"object"}}]}`)
}

func describeOverEra(t *testing.T, conn *eraConnection) wire.Reply {
	t.Helper()
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	exited := make(chan struct{})
	t.Cleanup(func() {
		_ = conn.Close()
		joinExited(t, exited, "describe worker did not exit")
	})
	describeAsync(t, r, context.Background(), exited, result)
	return awaitSignal(t, result, "describe did not return")
}

func seenRequests(conn *eraConnection) []*jsonrpc.Request {
	conn.seenMu.Lock()
	defer conn.seenMu.Unlock()
	return append([]*jsonrpc.Request(nil), conn.seen...)
}

func metaVersion(t *testing.T, req *jsonrpc.Request) string {
	t.Helper()
	var params struct {
		Meta struct {
			ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	}
	if json.Unmarshal(req.Params, &params) != nil {
		return ""
	}
	return params.Meta.ProtocolVersion
}

func toolsOf(t *testing.T, reply wire.Reply) []string {
	t.Helper()
	var envelope InventoryEnvelope
	if wire.Decode(reply.Data, &envelope) != nil {
		t.Fatal("inventory envelope was not decodable")
	}
	var out InventoryOutput
	if json.Unmarshal([]byte(envelope.Inventory), &out) != nil {
		t.Fatal("inventory was not decodable")
	}
	names := make([]string, 0, len(out.Tools))
	for _, tool := range out.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func hasEchoTool(names []string) bool {
	for _, name := range names {
		if strings.HasSuffix(name, "echo") {
			return true
		}
	}
	return false
}

// TestUpstreamHandshakeNegotiatesStatelessPeer proves acceptance 1: a peer
// that supports only 2026-07-28 is discovered probed and served through
// tools/list without any initialize request.
func TestUpstreamHandshakeNegotiatesStatelessPeer(t *testing.T) {
	conn := newEraConnection(discoverOK, toolsOK)
	reply := describeOverEra(t, conn)
	if !reply.OK {
		t.Fatalf("stateless peer describe failed: %s", reply.Error)
	}
	if !hasEchoTool(toolsOf(t, reply)) {
		t.Fatal("stateless inventory was missing the echo tool")
	}
	seen := seenRequests(conn)
	if len(seen) != 2 {
		t.Fatalf("stateless handshake wrote %d requests, want discover, tools/list", len(seen))
	}
	if seen[0].Method != "server/discover" {
		t.Fatalf("upstream handshake opened with %q, want the stateless server/discover probe", seen[0].Method)
	}
	if metaVersion(t, seen[0]) != modernProtocolVersion {
		t.Fatalf("probe offered %q, want %q", metaVersion(t, seen[0]), modernProtocolVersion)
	}
	for _, request := range seen {
		if request.Method == "initialize" {
			t.Fatal("stateless peer received an initialize request")
		}
	}
}

// TestUpstreamHandshakeFallsBackToPinnedInitializeEra proves acceptance 2: a
// discover refusal drives exactly one pinned initialize-era handshake on the
// same connection, offering upstreamProtocolVersion.
func TestUpstreamHandshakeFallsBackToPinnedInitializeEra(t *testing.T) {
	conn := newEraConnection(discoverMethodNotFound, initializeOK(upstreamProtocolVersion), toolsOK)
	reply := describeOverEra(t, conn)
	if !reply.OK {
		t.Fatalf("initialize-era peer describe failed: %s", reply.Error)
	}
	if !hasEchoTool(toolsOf(t, reply)) {
		t.Fatal("initialize-era inventory was missing the echo tool")
	}
	seen := seenRequests(conn)
	if len(seen) != 4 {
		t.Fatalf("fallback handshake wrote %d requests, want discover refusal, initialize, notifications/initialized, tools/list", len(seen))
	}
	discoveries, initializations := 0, 0
	var initialize *jsonrpc.Request
	for _, request := range seen {
		switch request.Method {
		case "server/discover":
			discoveries++
		case "initialize":
			initializations++
			initialize = request
		}
	}
	if discoveries != 1 || initializations != 1 || initialize == nil {
		t.Fatalf("fallback wrote discovers=%d initializes=%d, want one probe refusal then one initialize", discoveries, initializations)
	}
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(initialize.Params, &params); err != nil || params.ProtocolVersion != upstreamProtocolVersion {
		t.Fatalf("fallback initialize offered %q (%v), want the pinned %q", params.ProtocolVersion, err, upstreamProtocolVersion)
	}
}

// TestUpstreamHandshakeRecoversFromUnsupportedProtocolVersion proves
// acceptance 3: a -32022 discover answer with supported versions drives one
// bounded stateless retry, never a loop and never an initialize.
func TestUpstreamHandshakeRecoversFromUnsupportedProtocolVersion(t *testing.T) {
	conn := newEraConnection(discoverUnsupported, discoverOK, toolsOK)
	reply := describeOverEra(t, conn)
	if !reply.OK {
		t.Fatalf("unsupported-version peer describe failed: %s", reply.Error)
	}
	if !hasEchoTool(toolsOf(t, reply)) {
		t.Fatal("retried inventory was missing the echo tool")
	}
	discoveries, initializations := 0, 0
	for _, request := range seenRequests(conn) {
		switch request.Method {
		case "server/discover":
			discoveries++
		case "initialize":
			initializations++
		}
	}
	if discoveries != 2 || initializations != 0 {
		t.Fatalf("retry wrote discovers=%d initializes=%d, want two discovers, no initialize, no loop", discoveries, initializations)
	}
	if got := len(seenRequests(conn)); got != 3 {
		t.Fatalf("retry handshake wrote %d requests, want discover, retry discover, tools/list", got)
	}
}
