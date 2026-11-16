package mcpexchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

type connection struct {
	ctx      context.Context
	cancel   context.CancelFunc
	endpoint string
	client   *http.Client

	mu               sync.Mutex
	writeMu          sync.Mutex
	closed           bool
	closedCh         chan struct{}
	active           int
	activeDone       chan struct{}
	messages         int
	sessionID        string
	version          string
	modern           bool
	discovered       bool
	discoverAttempts int
	initialized      bool
	announced        bool
	incoming         chan jsonrpc.Message
	closeOnce        sync.Once
}

func newConnection(ctx context.Context, cancel context.CancelFunc, endpoint string, client *http.Client) *connection {
	return &connection{ctx: ctx, cancel: cancel, endpoint: endpoint, client: client, closedCh: make(chan struct{}), activeDone: closedSignal(), incoming: make(chan jsonrpc.Message, maxActive)}
}

func closedSignal() chan struct{} { ch := make(chan struct{}); close(ch); return ch }

// Read stops only on local closure or cancellation; Write also maps owned termination to io.EOF so the SDK's Wait reports orderly shutdown as clean.
func (c *connection) Read(ctx context.Context) (jsonrpc.Message, error) {
	if ctx == nil {
		return nil, errExchange
	}
	select {
	case <-c.closedCh:
		return nil, io.EOF
	case <-c.ctx.Done():
		return nil, io.EOF
	case <-ctx.Done():
		return nil, io.EOF
	default:
	}
	select {
	case message := <-c.incoming:
		if message == nil {
			return nil, errExchange
		}
		return message, nil
	case <-c.closedCh:
		return nil, io.EOF
	case <-c.ctx.Done():
		return nil, io.EOF
	case <-ctx.Done():
		return nil, io.EOF
	}
}

// admit classifies refusal under one lock: ownedStop marks refusal caused SOLELY by orderly owned termination; method/state/limit refusals stay sticky.
func (c *connection) admit(method string, notification bool) (admitted, ownedStop bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.allowsLocked(method, notification) || c.messages >= maxMessages || c.active >= maxActive || len(c.incoming)+c.active >= maxActive {
		return false, false
	}
	if c.closed || c.ctx.Err() != nil {
		return false, true
	}
	if c.messages == 0 {
		c.modern = method == "server/discover"
	}
	if c.active == 0 {
		c.activeDone = make(chan struct{})
	}
	c.active++
	c.messages++
	if method == "server/discover" {
		c.discoverAttempts++
	}
	return true, false
}

func (c *connection) allowsLocked(method string, notification bool) bool {
	if c.messages == 0 {
		return !notification && (method == "initialize" || method == "server/discover")
	}
	if c.modern {
		if c.discovered {
			switch method {
			case "tools/list", "tools/call":
				return !notification
			case "notifications/cancelled":
				return notification
			default:
				return false
			}
		}
		return !notification && (method == "initialize" || method == "server/discover" && c.discoverAttempts < 2)
	}
	if !allowedMethod(method, notification) {
		return false
	}
	if method == "initialize" {
		return false
	}
	if method == "notifications/initialized" {
		return c.initialized && !c.announced
	}
	return c.announced
}

func allowedMethod(method string, notification bool) bool {
	switch method {
	case "initialize", "tools/list", "tools/call", "ping":
		return !notification
	case "notifications/initialized", "notifications/cancelled":
		return notification
	default:
		return false
	}
}

func (c *connection) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.ctx.Err() != nil
}

// stopped maps an in-flight failure to io.EOF only under orderly owned close; live stays errExchange.
func (c *connection) stopped() error {
	if c.isClosed() {
		return io.EOF
	}
	return errExchange
}

func (c *connection) leave() {
	c.mu.Lock()
	c.active--
	if c.active == 0 {
		close(c.activeDone)
	}
	c.mu.Unlock()
}

// Ownership: the owned-termination test and refusal classification happen under c.mu in one admit decision; genuine method/state/limit refusals keep errExchange even while shutdown overlaps.
func (c *connection) Write(ctx context.Context, message jsonrpc.Message) error {
	request, ok := message.(*jsonrpc.Request)
	if ctx == nil || !ok || request == nil || ctx.Err() != nil || request.Extra != nil ||
		!allowedMethod(request.Method, !request.ID.IsValid()) && !(request.Method == "server/discover" && request.ID.IsValid()) || len(request.Params) > maxRequest-256 ||
		request.ID.IsValid() && !validRequestID(request.ID.Raw()) {
		return errExchange
	}
	if admitted, ownedStop := c.admit(request.Method, !request.ID.IsValid()); ownedStop {
		return io.EOF // owned stop of an otherwise-admissible operation
	} else if !admitted {
		return errExchange
	}
	defer c.leave()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire, err := jsonrpc.EncodeMessage(request)
	defer clear(wire)
	if err != nil || len(wire) == 0 || len(wire) > maxRequest {
		return errExchange
	}
	var requestID []byte
	if request.ID.IsValid() {
		if requestID, err = expectedID(wire); err != nil {
			return errExchange
		}
	}
	if c.isClosed() {
		return io.EOF
	}
	requestCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()

	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(wire))
	if err != nil {
		return errExchange
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json, text/event-stream")
	c.mu.Lock()
	modern := c.modern
	modernMethod := request.Method == "server/discover" || request.Method == "tools/list" || request.Method == "tools/call" || request.Method == "notifications/cancelled"
	if modern && modernMethod {
		version := requestMetaVersion(request.Params)
		if version != "" {
			if !headerToken(version) {
				c.mu.Unlock()
				return errExchange
			}
			c.version = version
		}
	}
	if c.sessionID != "" {
		httpRequest.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	if c.version != "" && (!modern || modernMethod) {
		httpRequest.Header.Set("Mcp-Protocol-Version", c.version)
	}
	c.mu.Unlock()
	if modern && modernMethod {
		// Routing headers derive only from these same request fields; encoded names are compared decoded per SEP-2243.
		httpRequest.Header.Set("Mcp-Method", request.Method)
		if request.Method == "tools/call" {
			name, ok := requestToolName(request.Params)
			if !ok {
				return errExchange
			}
			encodedName, ok := encodeNameHeader(name)
			if !ok {
				return errExchange
			}
			httpRequest.Header.Set("Mcp-Name", encodedName)
		}
	}
	response, err := c.client.Do(httpRequest)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if request.Method == "server/discover" && response != nil {
		c.mu.Lock()
		c.discovered = false
		c.mu.Unlock()
		if len(response.Header.Values("Mcp-Session-Id")) > 0 {
			return errExchange // discovery is always stateless
		}
	}
	if err != nil || response == nil || response.Body == nil {
		if mcpflow.DefiniteResponse(err) {
			return errExchange
		} // definite flow refusal survives owned stop
		return c.stopped()
	}
	if request.Method != "server/discover" {
		if err := c.captureSession(response); err != nil {
			return errExchange // definite header evidence
		}
	}
	if !request.ID.IsValid() {
		if response.StatusCode != http.StatusAccepted || response.ContentLength > 0 {
			return errExchange // definite status evidence
		}
		if err := consumeEmpty(response.Body); err == errTransportInterrupted {
			return c.stopped() // interrupted read: EOF only under owned stop
		} else if err != nil {
			return errExchange
		}
		if request.Method == "notifications/initialized" {
			c.mu.Lock()
			c.announced = true
			c.mu.Unlock()
		}
		return nil
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > maxResponse {
		return errExchange // definite status evidence
	}
	mediaType, err := parseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return errExchange // definite header evidence
	}
	var result *jsonrpc.Response
	switch mediaType {
	case "application/json":
		result, err = decodeJSONResponse(response.Body, requestID)
	case "text/event-stream":
		result, err = decodeSSEResponse(response.Body, requestID)
	default:
		err = errExchange
	}
	// Interruption is classified by ownership (io.EOF only under owned stop); complete malformed evidence stays errExchange; the sentinel never escapes Write.
	if err == errTransportInterrupted {
		return c.stopped()
	}
	if err != nil || result == nil {
		return errExchange
	}
	if request.Method == "initialize" {
		if result.Error != nil {
			return errExchange
		}
		var init struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(result.Result, &init) != nil || !supportedVersion(init.ProtocolVersion) {
			return errExchange
		}
		c.mu.Lock()
		if !modern && c.version != "" && c.version != init.ProtocolVersion {
			c.mu.Unlock()
			return errExchange
		}
		c.version = init.ProtocolVersion
		c.initialized = true
		c.modern = false
		c.mu.Unlock()
	}
	if request.Method == "server/discover" {
		if result.Error != nil {
			rpcError, ok := result.Error.(*jsonrpc.Error)
			if !ok {
				result.Error = &jsonrpc.Error{Message: "remote MCP discovery refused"}
			} else {
				rpcError.Message = "remote MCP discovery refused"
				if rpcError.Code == -32004 {
					rpcError.Code = -32022
				}
				var data struct {
					Supported []string `json:"supported"`
					Requested string   `json:"requested"`
				}
				if rawData := bytes.TrimSpace(rpcError.Data); len(rawData) > 0 && rawData[0] == '{' && json.Unmarshal(rawData, &data) == nil {
					supported := make([]string, 0, len(data.Supported))
					for _, version := range data.Supported {
						switch version {
						case "2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05":
							supported = append(supported, version)
						}
					}
					clean, err := json.Marshal(struct {
						Supported []string `json:"supported"`
						Requested string   `json:"requested"`
					}{Supported: supported, Requested: "2026-07-28"})
					if err == nil {
						rpcError.Data = clean
					} else {
						rpcError.Data = nil
					}
				} else {
					rpcError.Data = nil
				}
			}
			c.mu.Lock()
			c.discovered = false
			c.mu.Unlock()
		} else {
			var discovery struct {
				SupportedVersions []string `json:"supportedVersions"`
			}
			modernSupported := json.Unmarshal(result.Result, &discovery) == nil
			if modernSupported {
				modernSupported = false
				for _, version := range discovery.SupportedVersions {
					if version == "2026-07-28" {
						modernSupported = true
						break
					}
				}
			}
			c.mu.Lock()
			c.discovered = modernSupported
			c.mu.Unlock()
		}
	}
	if request.Method == "notifications/initialized" {
		c.mu.Lock()
		if !c.initialized {
			c.mu.Unlock()
			return errExchange // definite protocol state evidence
		}
		c.announced = true
		c.mu.Unlock()
	}
	select {
	case c.incoming <- result:
		return nil
	case <-requestCtx.Done():
		return c.stopped() // live caller ctx + non-closed connection stays errExchange
	case <-c.closedCh:
		return io.EOF
	}
}

func (c *connection) captureSession(response *http.Response) error {
	values := response.Header.Values("Mcp-Session-Id")
	if len(values) > 1 || len(values) == 1 && !validSessionID(values[0]) {
		return errExchange
	}
	if len(values) == 0 {
		return nil
	}
	id := values[0]
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.discovered || c.sessionID != "" && c.sessionID != id {
		return errExchange
	}
	c.sessionID = id
	return nil
}

func requestMetaVersion(params json.RawMessage) string {
	var probe struct {
		Meta struct {
			ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	}
	if json.Unmarshal(params, &probe) != nil {
		return ""
	}
	return probe.Meta.ProtocolVersion
}

func requestToolName(params json.RawMessage) (string, bool) {
	var probe struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(params, &probe) != nil || probe.Name == "" {
		return "", false
	}
	return probe.Name, true
}

func encodeNameHeader(name string) (string, bool) {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return "", false
	}
	literal := true
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			literal = false
			break
		}
	}
	if literal && name[0] != ' ' && name[len(name)-1] != ' ' && !(strings.HasPrefix(name, "=?base64?") && strings.HasSuffix(name, "?=")) {
		return name, true
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(name)) + "?=", true
}

func headerToken(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func (c *connection) SessionID() string { c.mu.Lock(); defer c.mu.Unlock(); return c.sessionID }
func (c *connection) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		close(c.closedCh)
		done := c.activeDone
		c.mu.Unlock()
		c.cancel()
		<-done
	})
	return nil
}

var _ interface {
	Read(context.Context) (jsonrpc.Message, error)
	Write(context.Context, jsonrpc.Message) error
	Close() error
	SessionID() string
} = (*connection)(nil)
