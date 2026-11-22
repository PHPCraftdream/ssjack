package tasks

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Extension is the identifier of the MCP tasks extension.
const Extension = "io.modelcontextprotocol/tasks"

// The advisory values every task answer reports.
const (
	// TTLMs is the task lifetime reported from creation; the extension treats
	// it as an advisory hint, not a deadline.
	TTLMs = 7200000
	// PollIntervalMs is the polling interval every answer reports: one keeper
	// round trip per poll on the shared connection.
	PollIntervalMs = 10000
)

// Task statuses of the extension.
const (
	statusWorking   = "working"
	statusCompleted = "completed"
	statusCancelled = "cancelled"
	statusFailed    = "failed"
)

// The transfer states a job reports to the bridge.
const (
	stateRunning   = "running"
	stateCancelled = "cancelled"
)

// Result types of the extension.
const (
	resultTypeTask     = "task"
	resultTypeComplete = "complete"
)

// The fixed messages of the task machinery. They repeat no job data.
const (
	failureMessage       = "the task could not be read"
	cancelFailureMessage = "the cancellation could not be requested"
	unknownMessage       = "unknown task"
)

// taskWire is the Task shape the extension defines; the handle and every
// tasks/get answer carry it.
type taskWire struct {
	TaskID         string `json:"taskId"`
	Status         string `json:"status"`
	StatusMessage  string `json:"statusMessage,omitempty"`
	CreatedAt      string `json:"createdAt"`
	LastUpdatedAt  string `json:"lastUpdatedAt"`
	TTLMs          int64  `json:"ttlMs"`
	PollIntervalMs int    `json:"pollIntervalMs"`
}

// Handle is the CreateTaskResult answer of an eligible tools/call.
type Handle struct {
	mcp.ResultBase
	ResultType string `json:"resultType"`
	taskWire
}

// taskFailure is the nested error of a failed task.
type taskFailure struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

// GetResult is one tasks/get answer.
type GetResult struct {
	mcp.ResultBase
	ResultType string `json:"resultType"`
	taskWire
	Result *mcp.CallToolResult `json:"result,omitempty"`
	Error  *taskFailure        `json:"error,omitempty"`
}

// GetParams are the tasks/get parameters.
type GetParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

// CancelParams are the tasks/cancel parameters.
type CancelParams struct {
	mcp.ParamsBase
	TaskID string `json:"taskId"`
}

// UpdateParams are the tasks/update parameters. This bridge issues no input
// request, so the responses are acknowledged and dropped.
type UpdateParams struct {
	mcp.ParamsBase
	TaskID         string                     `json:"taskId"`
	InputResponses map[string]json.RawMessage `json:"inputResponses,omitempty"`
}

// Ack is the empty acknowledgement of tasks/cancel and tasks/update.
type Ack struct {
	mcp.ResultBase
	ResultType string `json:"resultType"`
}

// textResult is the one-text-block tool result the transfer tools answer with;
// a task result is today's status text, byte for byte.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// ackResult is the empty acknowledgement of the two write methods.
func ackResult() *Ack { return &Ack{ResultType: resultTypeComplete} }
