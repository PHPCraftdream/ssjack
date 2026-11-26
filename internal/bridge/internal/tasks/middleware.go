package tasks

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	methodGet    = "tasks/get"
	methodUpdate = "tasks/update"
	methodCancel = "tasks/cancel"

	toolCall     = "tools/call"
	revision2026 = "2026-07-28"

	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
)

// transferTools names the two tools that carry a task.
var transferTools = map[string]bool{
	"remote_upload":   true,
	"remote_download": true,
}

// execTools names the two tools that carry an exec task.
var execTools = map[string]bool{
	"remote_exec": true,
	"app_exec":    true,
}

// requiredExtension is the error data of a non-declaring client: the extension
// the request needs.
var requiredExtension = json.RawMessage(`{"requiredCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`)

// startCapture is the job id of the start the tool handler made while one
// tools/call interception watched it.
type startCapture struct{ jobID string }

type startCaptureKey struct{}

// watchingStart returns a context whose transfer start is recorded, and the
// capture to read after the call.
func watchingStart(ctx context.Context) (context.Context, *startCapture) {
	capture := &startCapture{}
	return context.WithValue(ctx, startCaptureKey{}, capture), capture
}

// CapturedStart publishes the job id of a started transfer or exec to the task
// interception that wraps this call, when there is one.
func CapturedStart(ctx context.Context, jobID string) {
	if capture, ok := ctx.Value(startCaptureKey{}).(*startCapture); ok {
		capture.jobID = jobID
	}
}

// Install registers the three task methods, the extension gate and the
// tools/call interception on server.
func (m *Manager) Install(server *mcp.Server) error {
	if err := mcp.AddReceivingCustomMethod(server, methodGet, func(ctx context.Context, _ *mcp.ServerSession, params *GetParams) (*GetResult, error) {
		return m.get(ctx, params)
	}); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, methodUpdate, func(_ context.Context, _ *mcp.ServerSession, params *UpdateParams) (*Ack, error) {
		return m.update(params)
	}); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, methodCancel, func(ctx context.Context, _ *mcp.ServerSession, params *CancelParams) (*Ack, error) {
		return m.cancel(ctx, params)
	}); err != nil {
		return err
	}
	server.AddReceivingMiddleware(m.gate)
	server.AddReceivingMiddleware(m.intercept)
	return nil
}

// requestMeta returns the per-request `_meta` map of one request. A request
// without its own metadata declares nothing: the revision and capabilities an
// earlier discover or initialize stored in the SDK session are never consulted.
func requestMeta(params mcp.Params) map[string]any {
	if params == nil {
		return nil
	}
	return params.GetMeta()
}

// requestVersion returns the revision the request itself declares.
func requestVersion(params mcp.Params) (string, bool) {
	meta := requestMeta(params)
	if meta == nil {
		return "", false
	}
	version, ok := meta[metaProtocolVersion].(string)
	return version, ok
}

// requestExtensions returns the extensions the request itself declares. The
// value may arrive typed (in-process) or as a generic JSON map (over the
// wire), so it is re-encoded before it is read.
func requestExtensions(params mcp.Params) (map[string]json.RawMessage, bool) {
	meta := requestMeta(params)
	if meta == nil {
		return nil, false
	}
	raw, ok := meta[metaClientCapabilities]
	if !ok || raw == nil {
		return nil, false
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var capabilities struct {
		Extensions map[string]json.RawMessage `json:"extensions"`
	}
	if json.Unmarshal(encoded, &capabilities) != nil || capabilities.Extensions == nil {
		return nil, false
	}
	return capabilities.Extensions, true
}

// requestDeclaresTasks reports whether this request itself uses revision
// 2026-07-28 and declares the extension in its own metadata.
func requestDeclaresTasks(params mcp.Params) bool {
	version, ok := requestVersion(params)
	if !ok || version < revision2026 {
		return false
	}
	extensions, ok := requestExtensions(params)
	if !ok {
		return false
	}
	_, declared := extensions[Extension]
	return declared
}

// gate keeps the three task methods to revision 2026-07-28 and to clients that
// declare the extension on the request itself.
func (m *Manager) gate(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if !taskMethod(method) {
			return next(ctx, method, req)
		}
		params := req.GetParams()
		if version, declared := requestVersion(params); !declared || version < revision2026 {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"}
		}
		if !requestDeclaresTasks(params) {
			return nil, &jsonrpc.Error{Code: mcp.CodeMissingRequiredClientCapabilities, Message: "missing required client capability", Data: requiredExtension}
		}
		return next(ctx, method, req)
	}
}

// intercept answers eligible transfer or exec starts with a task handle instead
// of today's text; every other call, and every ineligible one, takes today's path.
// The tool's own handler performs the call, so input validation, keeper start
// and refusal results remain exactly the tool's.
func (m *Manager) intercept(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != toolCall {
			return next(ctx, method, req)
		}
		call, ok := req.(*mcp.CallToolRequest)
		if !ok || call == nil || call.Params == nil {
			return next(ctx, method, req)
		}
		_, transfer := transferTools[call.Params.Name]
		_, exec := execTools[call.Params.Name]
		if (!transfer && !exec) || !requestDeclaresTasks(call.Params) {
			return next(ctx, method, req)
		}
		capturedCtx, capture := watchingStart(ctx)
		result, err := next(capturedCtx, method, req)
		if err != nil || capture.jobID == "" {
			return result, err
		}
		if exec {
			return m.CreateExec(capture.jobID, call.Params.Name == "app_exec"), nil
		}
		return m.create(capture.jobID), nil
	}
}

// taskMethod reports whether method is one of the three task methods.
func taskMethod(method string) bool {
	return method == methodGet || method == methodUpdate || method == methodCancel
}
