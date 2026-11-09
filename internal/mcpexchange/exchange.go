// Package mcpexchange supplies a bounded, request-only Streamable HTTP
// transport over the HTTP capability owned by mcphttp.
//
// New accepts only the endpoint minted by mcphttp and that exact owner's
// borrowed *http.Client (its *mcpflow.Transport, redirect refusal, and no jar).
// It never creates a client or performs network I/O. The once-only Connect binds
// the protocol connection to the caller's lifetime context; runtime supplies the
// 10-minute slot parent. mcphttp/mcpflow remain the owners of endpoint policy,
// credential attachment/clearing, HTTP bounds, and final I/O cleanup.
//
// The exchange is deliberately smaller than the full Streamable HTTP feature set:
// POST only, initialize, notifications/initialized, tools/list, tools/call,
// notifications/cancelled, and ping; at most four in-flight/queued results and
// 4096 requests; 64 KiB encoded requests and 256 KiB responses. No GET listener,
// DELETE, reconnect/resume, retries, cross-endpoint requests, or replay. Session
// IDs are bounded and fixed after negotiation; only the pinned SDK's supported
// protocol versions are accepted and the negotiated version accompanies later
// POSTs. JSON responses and one bounded event: message SSE response are parsed
// privately, matched to the exact request ID, and only JSON-RPC response messages
// are delivered to the SDK. Read and owned-cancellation Write failures report io.EOF so the SDK's
// Wait treats orderly owned shutdown as clean. Owned-stop EOF applies to admission (solely-owned
// refusal of an otherwise-admissible message, classified atomically under one lock) and to
// transport/decode READ INTERRUPTION: interruption without protocol evidence reports io.EOF
// only while an owned close is in progress and the fixed sticky errExchange on a live
// connection. Definite refusal evidence survives shutdown overlap as the fixed errExchange —
// this includes flow-rejected non-2xx status, invalid response headers, declared/actual
// response size limits, SSE token-limit failures, nonempty notification bodies, and
// exchange-stage session-header/status/media-type/malformed-JSON-SSE/response-ID evidence.
// Any rejection is a fixed local error; peer body text,
// headers, IDs, and parse diagnostics are not exposed in adapter errors.
//
// The tests use bounded fake HTTP peers, exact IDs, JSON/SSE negotiation, rejection
// and close/join barriers. They do not make network requests.
package mcpexchange

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
)

const (
	maxEndpoint = 2048
	maxRequest  = mcpflow.MaxRequest
	maxResponse = mcpflow.MaxResponse
	maxActive   = mcpflow.MaxActive
	maxMessages = mcpflow.MaxMessages
)

var errExchange = errors.New("remote MCP exchange unavailable; do not replay uncertain operations")

type Transport struct {
	endpoint string
	client   *http.Client
	mu       sync.Mutex
	used     bool
}

// New accepts only the fixed HTTPS endpoint and borrowed HTTP capability
// minted by mcphttp. It never creates or owns an HTTP client.
func New(endpoint string, client *http.Client) (*Transport, error) {
	if len(endpoint) == 0 || len(endpoint) > maxEndpoint || strings.ContainsAny(endpoint, "\x00\r\n\t ") || client == nil || client.Transport == nil || client.CheckRedirect == nil || client.Jar != nil {
		return nil, errExchange
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.String() != endpoint {
		return nil, errExchange
	}
	flow, ok := client.Transport.(*mcpflow.Transport)
	if !ok || !flow.Available() || client.Timeout != 0 {
		return nil, errExchange
	}
	return &Transport{endpoint: endpoint, client: client}, nil
}

func (t *Transport) Connect(ctx context.Context) (mcp.Connection, error) {
	if t == nil || ctx == nil || ctx.Err() != nil {
		return nil, errExchange
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.used {
		return nil, errExchange
	}
	t.used = true
	connCtx, cancel := context.WithCancel(ctx)
	return newConnection(connCtx, cancel, t.endpoint, t.client), nil
}

var _ mcp.Transport = (*Transport)(nil)

func validRequestID(id any) bool {
	switch value := id.(type) {
	case float64:
		return value >= -(1<<53) && value <= 1<<53 && value == math.Trunc(value)
	case int:
		return int64(value) >= -(1<<53) && int64(value) <= 1<<53
	case int32:
		return true
	case int64:
		return value >= -(1<<53) && value <= 1<<53
	case string:
		return len(value) <= 256 && utf8.ValidString(value)
	default:
		return false
	}
}

func validSessionID(id string) bool {
	if !utf8.ValidString(id) || len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, b := range []byte(id) {
		if b < 0x21 || b > 0x7e || b == ',' {
			return false
		}
	}
	return true
}

func supportedVersion(version string) bool {
	switch version {
	case "2024-11-05", "2025-03-26", "2025-06-18":
		return true
	default:
		return false
	}
}
