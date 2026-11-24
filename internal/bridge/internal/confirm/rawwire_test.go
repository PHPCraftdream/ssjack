package confirm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge/internal/confirm"
	tooltext "github.com/PHPCraftdream/ssjack/internal/bridge/internal/tooltext"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// This file drives the raw JSON-RPC wire against the server transport: the
// request bytes are built literally, so the tests see exactly what a
// hand-rolled client would send, including `_meta` triples the SDK client
// would inject or withhold on its own.
//
// RAW vs SDK tests: the raw tests here REPLACE the SDK-client confirmation
// tests that used to live in wire_test.go, because an SDK client built with
// mcp.NewClient(impl, nil) installs the multi-round-trip sending middleware
// (mcp/client.go:79-80) and auto-fulfils every input_required result by
// calling c.elicit, which fails with "client does not support elicitation"
// when no handler is installed (mcp/client.go:868-871). An SDK test of an
// input_required flow therefore never reaches its own assertions.

// The literal transfer arguments of the raw harness. They match
// uploadArguments(callOptions{overwrite: true}) so SDK-level and raw tests
// bind the same digest, and both remote_upload and remote_download accept this
// argument shape.
const rawUploadArguments = `{"target":"allowed","local":"a.bin","remote":"/srv/a.bin","overwrite":true}`

// rawMetaModern is the full `_meta` triple: the exact protocol revision plus
// the form capability.
const rawMetaModern = `{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}`

// rawMetaFormNoVersion declares the form capability but NO protocolVersion.
const rawMetaFormNoVersion = `{"io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}`

// rawMetaLegacyForm carries the legacy revision plus the form capability.
const rawMetaLegacyForm = `{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}`

// rawWireSchema is the exact requested-schema bytes the input_required result
// must carry on the wire.
const rawWireSchema = `{"type":"object","properties":{},"additionalProperties":false}`

// rawReviewMessage is the fixed dialog text.
const rawReviewMessage = "Review this operation before it starts."

// rawResponses builds literal inputResponses for one action.
func rawResponses(action string) string {
	return fmt.Sprintf(`{"%s":{"action":%q}}`, confirm.RequestKey, action)
}

// newRawBridge serves the full tool registry over one authenticated keeper
// connection and returns the mcp server (not yet connected to any transport).
func newRawBridge(t *testing.T, ctx context.Context, keeper *fakeKeeper, now func() time.Time, mgr *confirm.Manager) *mcp.Server {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("5", 64), Token: strings.Repeat("6", 64)}
	server, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, keeper.handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	connection, err := broker.Connect(ctx, server.Endpoint(), server.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	return tooltext.NewFullServerWithClockAndConfirm(connection, now, mgr)
}

// rawClient speaks JSON-RPC directly over an in-memory client transport: it
// writes literally built request bytes and asserts against re-encoded raw
// response bytes.
type rawClient struct {
	conn        mcp.Connection
	writeMu     sync.Mutex
	nextID      int
	lastID      int
	elicitCount int
}

// connectRawClient pairs a fresh in-memory transport with the server, performs
// the initialize handshake by hand and returns the raw client. initializeForm
// decides whether initialize declares the elicitation form capability; the
// per-request gate does not need it, which the tests prove.
func connectRawClient(t *testing.T, ctx context.Context, server *mcp.Server, initializeForm bool) *rawClient {
	t.Helper()
	return connectRawClientVersion(t, ctx, server, initializeForm, "2026-07-28")
}

// connectRawClientVersion is connectRawClient with an explicit initialize
// protocolVersion, so tests can build LEGACY-initialized sessions (the SDK
// client can also do this via ClientSessionOptions.ProtocolVersion).
func connectRawClientVersion(t *testing.T, ctx context.Context, server *mcp.Server, initializeForm bool, version string) *rawClient {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	session, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	conn, err := clientTransport.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &rawClient{conn: conn, nextID: 1}
	c.initialize(t, ctx, initializeForm, version)
	return c
}

// initialize performs the MCP initialize handshake by hand, then the
// initialized notification.
func (c *rawClient) initialize(t *testing.T, ctx context.Context, form bool, version string) {
	t.Helper()
	capabilities := `{}`
	if form {
		capabilities = `{"elicitation":{"form":{}}}`
	}
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"initialize","params":{"protocolVersion":%q,"capabilities":%s,"clientInfo":{"name":"raw-confirm","version":"1"}}}`, c.nextID, version, capabilities)
	c.nextID++
	c.roundTrip(t, ctx, payload)
	notification, err := jsonrpc.DecodeMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.conn.Write(ctx, notification); err != nil {
		t.Fatal(err)
	}
}

// write sends one message under the client's write mutex: the in-memory
// transport contract allows concurrent Write calls (mcp/transport.go:81-87),
// the mutex only keeps our own writes from interleaving.
func (c *rawClient) write(t *testing.T, ctx context.Context, message jsonrpc.Message) {
	t.Helper()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.Write(ctx, message); err != nil {
		t.Fatal(err)
	}
}

// readUntilResponse reads frames until a JSON-RPC response arrives, returning
// its re-encoded bytes. A server→client elicitation/create request is counted
// (elicitCount) and answered with a decline response, so a regression that
// reintroduces auto-Elicit cannot deadlock the client and is detectable via
// the counter.
func (c *rawClient) readUntilResponse(t *testing.T, ctx context.Context) []byte {
	t.Helper()
	for {
		message, err := c.conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		switch incoming := message.(type) {
		case *jsonrpc.Request:
			if incoming.IsCall() && incoming.Method == "elicitation/create" {
				c.elicitCount++
				answer := &jsonrpc.Response{ID: incoming.ID, Result: json.RawMessage(`{"action":"decline"}`)}
				c.write(t, ctx, answer)
			}
		case *jsonrpc.Response:
			encoded, err := jsonrpc.EncodeMessage(incoming)
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}
	}
}

// roundTrip sends literally built bytes and returns the raw response bytes:
// the read frame is re-encoded with the SDK's deterministic encoder before any
// assertion.
func (c *rawClient) roundTrip(t *testing.T, ctx context.Context, payload string) []byte {
	t.Helper()
	message, err := jsonrpc.DecodeMessage([]byte(payload))
	if err != nil {
		t.Fatalf("the literal request does not decode: %v", err)
	}
	c.write(t, ctx, message)
	return c.readUntilResponse(t, ctx)
}

// callPayloadTool builds a literal tools/call for the given tool with the next
// id of this client, remembering the id used.
func (c *rawClient) callPayloadTool(tool, meta, responses, state string) string {
	params := `{"name":"` + tool + `","arguments":` + rawUploadArguments
	if meta != "" {
		params += `,"_meta":` + meta
	}
	if responses != "" {
		params += `,"inputResponses":` + responses
	}
	if state != "" {
		params += fmt.Sprintf(`,"requestState":%q`, state)
	}
	params += `}`
	id := c.nextID
	c.nextID++
	c.lastID = id
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}`, id, params)
}

// callPayload builds a literal tools/call for remote_upload.
func (c *rawClient) callPayload(meta, responses, state string) string {
	return c.callPayloadTool("remote_upload", meta, responses, state)
}

// callToolName sends a built tools/call for the given tool and returns the raw
// response bytes.
func (c *rawClient) callToolName(t *testing.T, ctx context.Context, tool, meta, responses, state string) []byte {
	t.Helper()
	return c.roundTrip(t, ctx, c.callPayloadTool(tool, meta, responses, state))
}

// call sends a built tools/call and returns the raw response bytes.
func (c *rawClient) call(t *testing.T, ctx context.Context, meta, responses, state string) []byte {
	t.Helper()
	return c.roundTrip(t, ctx, c.callPayload(meta, responses, state))
}

// rawCall sends a fully literal params object under the next id.
func (c *rawClient) rawCall(t *testing.T, ctx context.Context, params string) []byte {
	t.Helper()
	id := c.nextID
	c.nextID++
	c.lastID = id
	return c.roundTrip(t, ctx, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":%s}`, id, params))
}

// lastID is the id of the most recently built request.
//
// rawFrame is the shape of a re-encoded raw response.
type rawFrame struct {
	ID     json.Number `json:"id"`
	Result *rawResult  `json:"result"`
	Error  *rawError   `json:"error"`
}

type rawResult struct {
	Content       json.RawMessage `json:"content"`
	IsError       bool            `json:"isError"`
	ResultType    string          `json:"resultType"`
	RequestState  string          `json:"requestState"`
	InputRequests json.RawMessage `json:"inputRequests"`
}

type rawError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func decodeRawFrame(t *testing.T, frameBytes []byte) *rawFrame {
	t.Helper()
	var frame rawFrame
	if json.Unmarshal(frameBytes, &frame) != nil {
		t.Fatal("the response bytes do not decode as a JSON-RPC frame")
	}
	return &frame
}

// requireInputRequiredFrame asserts the exact raw shape of a gated answer and
// returns the state token. wantID is the literal id of the request.
func requireInputRequiredFrame(t *testing.T, frameBytes []byte, wantID string) string {
	t.Helper()
	frame := decodeRawFrame(t, frameBytes)
	if frame.Error != nil {
		t.Fatalf("the gated call answered a JSON-RPC error, code %d", frame.Error.Code)
	}
	if frame.Result == nil {
		t.Fatal("the gated call answered without a result")
	}
	if frame.ID.String() != wantID {
		t.Fatalf("the response id is %s, want %s", frame.ID.String(), wantID)
	}
	if frame.Result.ResultType != "input_required" {
		t.Fatalf("the raw resultType is %q, want input_required", frame.Result.ResultType)
	}
	if string(frame.Result.Content) != "null" {
		t.Fatalf("the raw content is %s, want literal null", frame.Result.Content)
	}
	if frame.Result.RequestState == "" || len(frame.Result.RequestState) > 1024 {
		t.Fatalf("the raw state token is empty or over the 1 KiB cap")
	}
	var requests map[string]json.RawMessage
	if json.Unmarshal(frame.Result.InputRequests, &requests) != nil || len(requests) != 1 {
		t.Fatal("the raw inputRequests are not exactly one entry")
	}
	raw, ok := requests[confirm.RequestKey]
	if !ok {
		t.Fatalf("the raw input request key is not %s", confirm.RequestKey)
	}
	var request struct {
		Method string `json:"method"`
		Params struct {
			Mode            string          `json:"mode"`
			Message         string          `json:"message"`
			RequestedSchema json.RawMessage `json:"requestedSchema"`
		} `json:"params"`
	}
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("the raw input request does not decode")
	}
	if request.Method != "elicitation/create" {
		t.Fatalf("the raw method is %q, want elicitation/create", request.Method)
	}
	if request.Params.Mode != "form" {
		t.Fatalf("the raw mode is %q, want form", request.Params.Mode)
	}
	if request.Params.Message != rawReviewMessage {
		t.Fatalf("the raw message is not the fixed review text")
	}
	if string(request.Params.RequestedSchema) != rawWireSchema {
		t.Fatalf("the raw requested schema is %s, want %s", request.Params.RequestedSchema, rawWireSchema)
	}
	return frame.Result.RequestState
}

// requireRefusalFrame asserts the exact raw refusal frame of a fixed outcome.
func requireRefusalFrame(t *testing.T, frameBytes []byte, wantText, wantID string) {
	t.Helper()
	frame := decodeRawFrame(t, frameBytes)
	if frame.Error != nil {
		t.Fatalf("the refusal arrived as a JSON-RPC error, code %d", frame.Error.Code)
	}
	if frame.Result == nil || !frame.Result.IsError {
		t.Fatal("the refusal is not an isError result")
	}
	if frame.ID.String() != wantID {
		t.Fatalf("the response id is %s, want %s", frame.ID.String(), wantID)
	}
	var content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(frame.Result.Content, &content) != nil || len(content) != 1 || content[0].Type != "text" {
		t.Fatal("the refusal is not one text content block")
	}
	if content[0].Text != wantText {
		t.Fatalf("the refusal text is not the expected fixed outcome")
	}
	if frame.Result.InputRequests != nil && string(frame.Result.InputRequests) != "null" {
		t.Fatal("a refusal carried inputRequests")
	}
}

// requireDispatchFrame asserts a successful dispatch on the raw wire: one text
// block starting with the start text, no elicitation markers, and exactly one
// keeper operation of the given kind.
func requireDispatchFrame(t *testing.T, frameBytes []byte, wantID, operation string, keeper *fakeKeeper) {
	t.Helper()
	// Delta marker: everything the keeper recorded before this response
	// arrived predates the dispatch under test.
	before := len(keeper.recorded())
	frame := decodeRawFrame(t, frameBytes)
	if frame.Error != nil {
		t.Fatalf("the dispatch answered a JSON-RPC error, code %d", frame.Error.Code)
	}
	if frame.Result == nil || frame.Result.IsError {
		t.Fatal("the dispatch answered with an error result")
	}
	if frame.ID.String() != wantID {
		t.Fatalf("the response id is %s, want %s", frame.ID.String(), wantID)
	}
	// server.go:1013-1024 keeps nil Content only for input_required and
	// mrtr.go:53-62 stamps resultType:"complete" on a modern-initialized
	// session, so a dispatched result carries resultType absent (legacy
	// session) or exactly "complete"; anything else is a gate artifact.
	if frame.Result.ResultType != "" && frame.Result.ResultType != "complete" {
		t.Fatalf("the dispatched resultType is %q, want absent or complete", frame.Result.ResultType)
	}
	if frame.Result.RequestState != "" || frame.Result.InputRequests != nil {
		t.Fatal("a dispatched answer carried elicitation markers")
	}
	var content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(frame.Result.Content, &content) != nil || len(content) != 1 || content[0].Type != "text" {
		t.Fatal("the dispatch is not one text content block")
	}
	if !strings.HasPrefix(content[0].Text, "Started job ") {
		t.Fatal("the dispatch did not start a job")
	}
	// Delta semantics: exactly one NEW keeper operation, and it is the given
	// kind. This keeps the helper usable when the keeper already recorded
	// earlier operations in the same test.
	ops := keeper.recorded()
	if len(ops) != before+1 || ops[before] != operation {
		t.Fatalf("the keeper saw %d new operations, want exactly one %s", len(ops)-before, operation)
	}
}

// requireErrorFrame asserts a protocol-level JSON-RPC error answer.
func requireErrorFrame(t *testing.T, frameBytes []byte, wantCode int) {
	t.Helper()
	frame := decodeRawFrame(t, frameBytes)
	if frame.Error == nil {
		t.Fatal("the malformed request was not answered with a JSON-RPC error")
	}
	if frame.Error.Code != wantCode {
		t.Fatalf("the error code is %d, want %d", frame.Error.Code, wantCode)
	}
}

// The refusal text of a non-consumable retry.
const rawInvalidText = "operation was not started: confirmation could not be validated"

func TestRawWireGateAndRetries(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The full input_required shape, elicited by the per-request `_meta` of a
	// client that declared NO elicitation capability at initialize: the gate
	// must not require initialize to enable the modern path.
	t.Run("per_request_meta_alone_elicits", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, false)
		frame := client.call(t, ctx, rawMetaModern, "", "")
		state := requireInputRequiredFrame(t, frame, "2")
		if len(state) == 0 || len(state) > 1024 {
			t.Fatal("the state token is empty or over the 1 KiB cap")
		}
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("the keeper saw operations for a gated call")
		}
	})

	t.Run("meta_without_version_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		frame := client.call(t, ctx, rawMetaFormNoVersion, "", "")
		requireDispatchFrame(t, frame, "2", "transfer_upload", keeper)
	})

	t.Run("legacy_version_with_form_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		frame := client.call(t, ctx, rawMetaLegacyForm, "", "")
		requireDispatchFrame(t, frame, "2", "transfer_upload", keeper)
	})

	// A retry with a DIFFERENT literal id than the initial call must dispatch
	// under the retry's own id.
	t.Run("new_id_retry_dispatches", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		client.nextID = 17
		frame := client.call(t, ctx, rawMetaModern, "", "")
		state := requireInputRequiredFrame(t, frame, "17")
		retry := client.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireDispatchFrame(t, retry, "18", "transfer_upload", keeper)
	})

	t.Run("decline_retry_fixed_text", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		retry := client.call(t, ctx, rawMetaModern, rawResponses("decline"), state)
		requireRefusalFrame(t, retry, "operation was not started: declined", "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a declined retry dispatched anyway")
		}
	})

	t.Run("cancel_retry_fixed_text", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		retry := client.call(t, ctx, rawMetaModern, rawResponses("cancel"), state)
		requireRefusalFrame(t, retry, "operation was not started: cancelled", "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a cancelled retry dispatched anyway")
		}
	})

	t.Run("expired_retry_fixed_text", func(t *testing.T) {
		keeper := &fakeKeeper{}
		clock := newManualClock()
		server := newRawBridge(t, ctx, keeper, clock.Now, confirm.NewManager(clock.Now, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		clock.Advance(6 * time.Minute)
		retry := client.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireRefusalFrame(t, retry, "operation was not started: confirmation timed out", "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("an expired retry dispatched anyway")
		}
	})

	t.Run("unknown_token_fixed_text", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		retry := client.call(t, ctx, rawMetaModern, rawResponses("accept"), "not-a-real-state-token")
		requireRefusalFrame(t, retry, rawInvalidText, "2")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("an unknown token dispatched anyway")
		}
	})

	t.Run("altered_arguments_fixed_text", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		// The retry changes one argument byte against the minted digest.
		params := `{"name":"remote_upload","arguments":{"target":"allowed","local":"CHANGED.bin","remote":"/srv/a.bin","overwrite":true},"_meta":` + rawMetaModern + `,"inputResponses":` + rawResponses("accept") + `,"requestState":` + quoteState(state) + `}`
		retry := client.rawCall(t, ctx, params)
		requireRefusalFrame(t, retry, rawInvalidText, "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("altered arguments dispatched anyway")
		}
	})

	// A retry whose own request lacks the `_meta` triple is refused with the
	// fixed generic error WITHOUT consuming the state: a proper modern retry
	// from the same client afterwards still succeeds.
	t.Run("retry_without_meta_refused", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		params := `{"name":"remote_upload","arguments":` + rawUploadArguments + `,"inputResponses":` + rawResponses("accept") + `,"requestState":` + quoteState(state) + `}`
		retry := client.rawCall(t, ctx, params)
		requireRefusalFrame(t, retry, rawInvalidText, "3")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a meta-less retry dispatched anyway")
		}
		proper := client.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireDispatchFrame(t, proper, "4", "transfer_upload", keeper)
	})

	// Malformed inputResponses is rejected by the SDK BEFORE the receiving
	// middleware runs: params decoding happens in handleReceive
	// (mcp/shared.go:211) while the middleware chain is only invoked
	// afterwards (mcp/shared.go:220), so no middleware can pre-empt it. The
	// SDK's unmarshalParams error embeds the raw params with %q
	// (mcp/shared.go:349), so the wire error message echoes the full
	// arguments: an SDK-level leak that cannot be fixed at middleware level.
	// Only the protocol facts are asserted here; the arguments are never
	// reproduced.
	t.Run("malformed_inputResponses_sdk_error", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		state := requireInputRequiredFrame(t, client.call(t, ctx, rawMetaModern, "", ""), "2")
		params := `{"name":"remote_upload","arguments":` + rawUploadArguments + `,"_meta":` + rawMetaModern + `,"inputResponses":[1,2],"requestState":` + quoteState(state) + `}`
		retry := client.rawCall(t, ctx, params)
		requireErrorFrame(t, retry, -32602)
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a malformed retry dispatched anyway")
		}
	})

	// A LEGACY-initialized session receiving the FULL modern `_meta` triple
	// must never elicit: the session revision gate (gate.go:
	// multiRoundTripSession) fires before the request `_meta` gate, because
	// the SDK's client-side auto-fulfilment keys on the SESSION revision. A
	// regression that elicited here would deadlock this client: its own read
	// loop would count the elicitation/create request and answer decline.
	t.Run("legacy_session_modern_meta_passthrough", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClientVersion(t, ctx, server, true, "2025-11-25")
		frame := client.call(t, ctx, rawMetaModern, "", "")
		requireDispatchFrame(t, frame, "2", "transfer_upload", keeper)
		if client.elicitCount != 0 {
			t.Fatal("the gate elicited on a legacy-initialized session")
		}
	})

	// A retry (inputResponses + requestState) from a legacy-initialized
	// session is refused generically WITHOUT consuming the state: the state
	// was minted by a modern client on the same server, and that client's
	// proper retry afterwards still dispatches exactly once.
	t.Run("legacy_session_modern_meta_retry_refused_no_consume", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		modern := connectRawClient(t, ctx, server, true)
		legacy := connectRawClientVersion(t, ctx, server, true, "2025-11-25")
		state := requireInputRequiredFrame(t, modern.call(t, ctx, rawMetaModern, "", ""), "2")
		// The legacy session sends the accept retry with its OWN id and the
		// exact confirmed arguments.
		retry := legacy.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireRefusalFrame(t, retry, rawInvalidText, "2")
		if legacy.elicitCount != 0 {
			t.Fatal("the gate elicited on a legacy-initialized session")
		}
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a legacy-session retry dispatched anyway")
		}
		// The refusal consumed nothing: the rightful modern retry dispatches.
		proper := modern.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
		requireDispatchFrame(t, proper, "3", "transfer_upload", keeper)
	})

	// Gate-ELIGIBLE call whose arguments exceed canonicaljson.MaxInput: the
	// peek declares eligibility, canonicalization then fails and the gate
	// must refuse generically instead of dispatching an unbindable
	// state-changing path. Without the fail-closed branch this call would
	// dispatch (or elicit) with no digest bound to its retry.
	t.Run("canonicalization_fail_closed_oversized", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		params := `{"name":"remote_upload","arguments":` + oversizedArguments(true) + `,"_meta":` + rawMetaModern + `}`
		frame := client.rawCall(t, ctx, params)
		requireRefusalFrame(t, frame, rawInvalidText, "2")
		if client.elicitCount != 0 {
			t.Fatal("an oversized gate-eligible call elicited")
		}
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("an oversized gate-eligible call dispatched anyway")
		}
	})

	// The SAME oversized arguments WITHOUT overwrite are ineligible: the
	// gate must NOT refuse them on canonicalization grounds — the raw peek
	// decides eligibility before canonicalization — so the call passes
	// through untouched to the tools.
	t.Run("oversized_ineligible_call_untouched", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		params := `{"name":"remote_upload","arguments":` + oversizedArguments(false) + `,"_meta":` + rawMetaModern + `}`
		frameBytes := client.rawCall(t, ctx, params)
		if client.elicitCount != 0 {
			t.Fatal("an ineligible oversized call elicited")
		}
		frame := decodeRawFrame(t, frameBytes)
		if frame.Error != nil {
			t.Fatalf("the ineligible call answered a JSON-RPC error, code %d", frame.Error.Code)
		}
		if frame.ID.String() != "2" {
			t.Fatalf("the response id is %s, want 2", frame.ID.String())
		}
		if frame.Result == nil {
			t.Fatal("the ineligible call answered without a result")
		}
		if frame.Result.ResultType != "" && frame.Result.ResultType != "complete" {
			t.Fatalf("the resultType is %q, want absent or complete", frame.Result.ResultType)
		}
		if frame.Result.IsError {
			// Pass-through reached the tools and the tool answered its own
			// error; it must NOT be the gate's generic confirm refusal.
			var content []struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(frame.Result.Content, &content) != nil || len(content) != 1 {
				t.Fatal("the error result is not one text block")
			}
			if content[0].Text == confirm.Invalid {
				t.Fatal("the gate refused an ineligible call on canonicalization grounds")
			}
		}
	})

	// Gate-shaped modern request whose arguments are not canonicalizable
	// JSON: the server decodes tools/call params into CallToolParamsRaw
	// (Arguments json.RawMessage, requests.go:10), so ANY JSON arguments
	// value passes unmarshalParams and reaches the middleware, where
	// canonicalization fails closed (gate.go: match, fail-closed branch).
	t.Run("canonicalization_fail_closed", func(t *testing.T) {
		keeper := &fakeKeeper{}
		server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
		client := connectRawClient(t, ctx, server, true)
		params := `{"name":"remote_upload","arguments":"oops","_meta":` + rawMetaModern + `}`
		frame := client.rawCall(t, ctx, params)
		requireRefusalFrame(t, frame, rawInvalidText, "2")
		if ops := keeper.recorded(); len(ops) != 0 {
			t.Fatal("a non-canonicalizable call dispatched anyway")
		}
	})
}

// quoteState embeds a state token as a JSON string literal.
func quoteState(state string) string {
	encoded, err := json.Marshal(state)
	if err != nil {
		return `""`
	}
	return string(encoded)
}

// oversizedArguments builds a tools/call arguments object whose total byte
// length exceeds canonicaljson.MaxInput. The pad is pure filler; it is never
// printed or asserted on.
func oversizedArguments(overwrite bool) string {
	arguments := `{"target":"allowed","local":"a.bin","remote":"/srv/a.bin"`
	if overwrite {
		arguments += `,"overwrite":true`
	}
	arguments += `,"pad":"` + strings.Repeat("a", canonicaljson.MaxInput) + `"}`
	return arguments
}

// The pending state is bound to the originating session: another session's
// retry is refused without consuming the record, and the rightful session can
// still complete it.
func TestRawSessionBinding(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keeper := &fakeKeeper{}
	server := newRawBridge(t, ctx, keeper, nil, confirm.NewManager(nil, nil))
	clientA := connectRawClient(t, ctx, server, true)
	clientB := connectRawClient(t, ctx, server, true)
	state := requireInputRequiredFrame(t, clientA.call(t, ctx, rawMetaModern, "", ""), "2")
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatal("the keeper saw operations for a gated call")
	}
	// Client B answers with A's state and matching arguments.
	retry := clientB.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
	requireRefusalFrame(t, retry, rawInvalidText, "2")
	if ops := keeper.recorded(); len(ops) != 0 {
		t.Fatal("a foreign session dispatched anyway")
	}
	// The record was NOT consumed: client A's proper retry still dispatches.
	proper := clientA.call(t, ctx, rawMetaModern, rawResponses("accept"), state)
	requireDispatchFrame(t, proper, "3", "transfer_upload", keeper)
}

// A wired-but-disabled manager must be byte-identical on the wire to a server
// with no confirm wiring at all.
func TestRawOffByteIdentity(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keeperPlain := &fakeKeeper{}
	plain := connectRawClient(t, ctx, newRawBridge(t, ctx, keeperPlain, nil, nil), true)
	keeperOff := &fakeKeeper{}
	off := connectRawClient(t, ctx, newRawBridge(t, ctx, keeperOff, nil, confirm.NewManagerOff(nil, nil)), true)
	params := `{"name":"remote_upload","arguments":` + rawUploadArguments + `,"_meta":` + rawMetaModern + `}`
	framePlain := plain.rawCall(t, ctx, params)
	frameOff := off.rawCall(t, ctx, params)
	if string(framePlain) != string(frameOff) {
		t.Fatal("the disabled wiring changed the raw response bytes")
	}
	for _, needle := range []string{"inputRequests", "input_required", "elicitation", "requestState"} {
		if strings.Contains(string(framePlain), needle) {
			t.Fatalf("the unwired answer contains the marker %q", needle)
		}
	}
	requireDispatchFrame(t, framePlain, "2", "transfer_upload", keeperPlain)
	requireDispatchFrame(t, frameOff, "2", "transfer_upload", keeperOff)

	// The same byte-identity proof for LEGACY-initialized clients that DO
	// declare the form capability at initialize: the session revision gate
	// must make the wired-but-disabled path and the unwired path produce
	// literally identical frames for a full legacy `_meta` request and for a
	// plain request, and neither may elicit.
	t.Run("off_byte_identity_legacy_form_client", func(t *testing.T) {
		keeperPlain := &fakeKeeper{}
		plain := connectRawClientVersion(t, ctx, newRawBridge(t, ctx, keeperPlain, nil, nil), true, "2025-11-25")
		keeperOff := &fakeKeeper{}
		off := connectRawClientVersion(t, ctx, newRawBridge(t, ctx, keeperOff, nil, confirm.NewManagerOff(nil, nil)), true, "2025-11-25")
		for name, params := range map[string]string{
			"legacy_form_meta": `{"name":"remote_upload","arguments":` + rawUploadArguments + `,"_meta":` + rawMetaLegacyForm + `}`,
			"plain":            `{"name":"remote_upload","arguments":` + rawUploadArguments + `}`,
		} {
			framePlain := plain.rawCall(t, ctx, params)
			frameOff := off.rawCall(t, ctx, params)
			if string(framePlain) != string(frameOff) {
				t.Fatalf("%s: the disabled wiring changed the raw response bytes", name)
			}
			if plain.elicitCount != 0 || off.elicitCount != 0 {
				t.Fatalf("%s: an elicitation attempt was observed", name)
			}
			requireDispatchFrame(t, framePlain, frameIDOf(t, framePlain), "transfer_upload", keeperPlain)
			requireDispatchFrame(t, frameOff, frameIDOf(t, frameOff), "transfer_upload", keeperOff)
		}
	})
}
