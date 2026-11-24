package confirm

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const (
	toolCall     = "tools/call"
	revision2026 = "2026-07-28"

	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// emptySchema is the requested schema of the form: no fields to fill in.
type emptySchema struct {
	Type                 string   `json:"type"`
	Properties           struct{} `json:"properties"`
	AdditionalProperties bool     `json:"additionalProperties"`
}

// Middleware gates eligible tool calls behind one form elicitation. It is
// installed outside the SDK's multi-round-trip middleware, so it sees both
// the initial call and every retry. The middleware never waits: an initial
// eligible call returns at once with an input_required result and holds no
// connection, listener or other resource while the client decides — an
// uncontinued confirmation simply expires (doc section 6). The
// input_required result itself is handed to the tool handler through the
// context, because only a result returned by the SDK's own callTool gets the
// resultType and content shaping of handleMultiRoundTripResult.
func (m *Manager) Middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if !m.enabled || method != toolCall {
			return next(ctx, method, req)
		}
		call, ok := req.(*mcp.CallToolRequest)
		if !ok || call == nil || call.Params == nil {
			return next(ctx, method, req)
		}
		if len(call.Params.InputResponses) > 0 || call.Params.RequestState != "" {
			return m.retry(ctx, next, method, req, call.Params)
		}
		// Double gate, part one: the SESSION revision. A session initialized
		// at a legacy revision must never elicit, whatever the request's
		// `_meta` says — the SDK would treat the session as legacy and its
		// serverMultiRoundTripMiddleware would auto-fulfil our input request.
		if !multiRoundTripSession(req) {
			return next(ctx, method, req)
		}
		kind, tool, argDigest, failClosed, ok := m.match(call.Params)
		if failClosed {
			// The request was modern and gate-shaped, but its arguments could
			// not be canonicalized for binding. Fail closed instead of
			// dispatching a state-changing path we cannot bind.
			return refusal(Invalid), nil
		}
		if !ok {
			return next(ctx, method, req)
		}
		token, ok := m.create(tool, argDigest, kind, sessionIdentity(req))
		if !ok {
			// Pending is full: fail closed rather than start the operation
			// without a confirmation.
			return refusal(Invalid), nil
		}
		result := &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{RequestKey: &mcp.ElicitParams{
				Mode:            "form",
				Message:         m.dialog.ReviewMessage(kind),
				RequestedSchema: emptySchema{Type: "object"},
			}},
			RequestState: token,
		}
		return next(context.WithValue(ctx, pendingKey{}, result), method, req)
	}
}

// pendingKey carries the prepared input_required result to the tool handler.
type pendingKey struct{}

// PendingResult returns the input_required result a gated call must answer
// with, or nil for a call that runs normally.
func PendingResult(ctx context.Context) *mcp.CallToolResult {
	result, _ := ctx.Value(pendingKey{}).(*mcp.CallToolResult)
	return result
}

// retry validates a retry before the call reaches the tools: any failure is
// answered without invoking next, so the existing dispatch runs at most once.
//
//	retry-shape detection (caller) → session revision → request `_meta`
//	→ response decode → session-identity match (inside validate, after
//	canonicalization) → canonicalization → state validation.
func (m *Manager) retry(ctx context.Context, next mcp.MethodHandler, method string, req mcp.Request, params *mcp.CallToolParamsRaw) (mcp.Result, error) {
	if !multiRoundTripSession(req) {
		// A retry from a legacy-initialized session is refused generically
		// WITHOUT consuming state: it can never be one of ours, because we
		// never elicit on such a session.
		return refusal(Invalid), nil
	}
	if !modernRequestMeta(params) {
		// The SDK's legacy auto-Elicit path fires only for results returned on
		// legacy requests; a retry must never resurrect state from one.
		return refusal(Invalid), nil
	}
	response, ok := m.decodeResponse(params.InputResponses)
	if !ok || params.RequestState == "" {
		return refusal(Invalid), nil
	}
	if response.Action == "accept" && len(response.Content) != 0 {
		m.debugf("confirm: accept carried content")
		return refusal(Invalid), nil
	}
	canonical, err := canonicaljson.Canonicalize([]byte(params.Arguments))
	if err != nil {
		m.debugf("confirm: retry arguments are not canonicalizable")
		return refusal(Invalid), nil
	}
	digest := Digest(canonical)
	switch m.validate(params.RequestState, params.Name, digest, response.Action, sessionIdentity(req)) {
	case outcomeAccepted:
		return next(ctx, method, req)
	case outcomeDeclined:
		return refusal(Declined), nil
	case outcomeCancelled:
		return refusal(Cancelled), nil
	case outcomeTimedOut:
		return refusal(TimedOut), nil
	default:
		return refusal(Invalid), nil
	}
}

// match reports whether this initial call passes the gate shape, together
// with its dialog kind and tool name. failClosed distinguishes a request that
// passed ALL eligibility checks but whose arguments could not be canonicalized
// for the digest: the caller must refuse instead of dispatching.
//
// Eligibility runs BEFORE canonicalization: the tool name and the
// overwrite/app-eligibility flags are peeked from the RAW arguments with plain
// json.Unmarshal (peeking does not need canonical form), so an ineligible call
// is passed through untouched even if its arguments are not canonicalizable.
// Only a fully gate-eligible call is canonicalized: the peek decides
// eligibility, the canonical digest binds the retry.
func (m *Manager) match(params *mcp.CallToolParamsRaw) (Kind, string, string, bool, bool) {
	if !modernRequestMeta(params) {
		return "", "", "", false, false
	}
	switch params.Name {
	case "remote_upload", "remote_download":
		var arguments struct {
			Overwrite bool `json:"overwrite"`
		}
		if json.Unmarshal([]byte(params.Arguments), &arguments) != nil || !arguments.Overwrite {
			return "", "", "", false, false
		}
	case "app_exec":
		// Classification seam: with no Classify installed, app_exec is never
		// elicited and keeps today's flow.
		if m.classify == nil {
			return "", "", "", false, false
		}
	default:
		return "", "", "", false, false
	}
	canonical, err := canonicaljson.Canonicalize([]byte(params.Arguments))
	if err != nil {
		return "", "", "", true, false
	}
	digest := Digest(canonical)
	if params.Name == "app_exec" {
		nonObservational, err := m.classify.IsNonObservational(params.Name, canonical)
		if err != nil || !nonObservational {
			return "", "", "", false, false
		}
		return Kind("app"), params.Name, digest, false, true
	}
	return KindTransfer, params.Name, digest, false, true
}

// multiRoundTripSession mirrors the SDK's clientSupportsMultiRoundTrip
// (mcp/mrtr.go:65-70): the decision reads ONLY the session's InitializeParams
// revision, defaulting to latestProtocolVersion (shared.go:50 —
// latestProtocolVersion = protocolVersion20260728 = "2026-07-28") when
// InitializeParams() is nil. A per-request modern `_meta` on an already
// initialized session does NOT replace state.InitializeParams
// (server.go:1993-1997), so a legacy-initialized session receiving a
// modern-shaped request would pass the request `_meta` gate while the SDK
// still auto-fulfils input requests on it (serverMultiRoundTripMiddleware,
// mrtr.go:132-175). Requiring the session revision here prevents that.
func multiRoundTripSession(req mcp.Request) bool {
	ss, ok := req.GetSession().(*mcp.ServerSession)
	if !ok || ss == nil {
		// No server session to inspect: never elicit.
		return false
	}
	version := revision2026 // mirrors latestProtocolVersion
	if iparams := ss.InitializeParams(); iparams != nil {
		version = iparams.ProtocolVersion
	}
	return version >= revision2026
}

// modernRequestMeta mirrors the SDK's per-request validateRequestMeta
// (mcp/shared.go:564): the CURRENT tools/call's `_meta` selects the
// >= 2026-07-28 protocol, not the session's initialize revision. The gate
// demands an exact match against revision2026 — stricter than the SDK's `>=`
// compare — because this tree only speaks that one revision. A request whose
// `_meta` carries no protocolVersion is never eligible, even on a modern
// session: without the per-request declaration there is no consent to elicit.
func modernRequestMeta(params *mcp.CallToolParamsRaw) bool {
	meta := params.GetMeta()
	if meta == nil {
		return false
	}
	version, ok := meta[mcp.MetaKeyProtocolVersion].(string)
	if !ok || version != revision2026 {
		return false
	}
	return declaresForm(params)
}

// shortSession renders a session identity for failure-only diagnostics. It is
// an owner/session identifier, never argument content.
func shortSession(session any) string {
	if id, ok := session.(string); ok {
		if len(id) > 12 {
			return id[:12]
		}
		return id
	}
	return "(unnamed)"
}

// sessionIdentity is the stable per-connection identity of the originating
// MCP session. The SDK exposes (*mcp.ServerSession).ID() (mcp/server.go:1606),
// which returns the transport's session id; when the transport carries no id
// it falls back to the *mcp.ServerSession pointer, which server.go keeps one
// per connection, so the pointer is a stable opaque comparable key. A nil or
// non-server session yields "" (and never matches a stored identity).
func sessionIdentity(req mcp.Request) any {
	ss, ok := req.GetSession().(*mcp.ServerSession)
	if !ok || ss == nil {
		return ""
	}
	if id := ss.ID(); id != "" {
		return id
	}
	return ss
}

// declaresForm reports whether this request's own `_meta` positively declares
// form elicitation. URL-only does not qualify.
func declaresForm(params *mcp.CallToolParamsRaw) bool {
	meta := params.GetMeta()
	if meta == nil {
		return false
	}
	raw, ok := meta[metaClientCapabilities]
	if !ok || raw == nil {
		return false
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	var capabilities struct {
		Elicitation *struct {
			Form json.RawMessage `json:"form"`
		} `json:"elicitation"`
	}
	if json.Unmarshal(encoded, &capabilities) != nil || capabilities.Elicitation == nil || len(capabilities.Elicitation.Form) == 0 {
		return false
	}
	var form any
	return json.Unmarshal(capabilities.Elicitation.Form, &form) == nil && form != nil
}

// decodeResponse reads the single elicitation response of a retry. Exactly
// one entry under RequestKey is accepted; anything else fails.
func (m *Manager) decodeResponse(responses mcp.InputResponseMap) (*mcp.ElicitResult, bool) {
	if len(responses) != 1 {
		return nil, false
	}
	raw, ok := responses[RequestKey]
	if !ok || raw == nil {
		return nil, false
	}
	if result, ok := raw.(*mcp.ElicitResult); ok {
		// Raw wire values always arrive here already typed: the SDK decodes
		// InputResponseMap via unmarshalInputResponse (mcp/protocol.go:157),
		// which returns *mcp.ElicitResult for any object with an "action"
		// key. ElicitResult.Content is a map, so an explicit wire null and an
		// omitted field both decode to nil and are indistinguishable here;
		// that limitation is accepted for the typed path.
		return result, validAction(result.Action)
	}
	// Non-typed values are constructed in-process. Detect an explicit
	// "content": null at the JSON level, which the typed path cannot.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var probe struct {
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(encoded, &probe) == nil && string(probe.Content) == "null" {
		m.debugf("confirm: accept carried explicit null content")
		return nil, false
	}
	var result mcp.ElicitResult
	if json.Unmarshal(encoded, &result) != nil {
		return nil, false
	}
	return &result, validAction(result.Action)
}

func validAction(action string) bool {
	return action == "accept" || action == "decline" || action == "cancel"
}

// refusal answers a refused retry in the bridge's tool-error shape: one text
// block with isError set.
func refusal(message string) *mcp.CallToolResult {
	result := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: message}}}
	result.SetError(errors.New(message))
	return result
}
