package tasks

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

// Tools is the seam the task path drives: the keeper operations of the two
// transfer tools and the texts those tools already produce.
type Tools interface {
	// Status reads one status record with no wait.
	Status(ctx context.Context, input transfer.StatusInput) (transfer.StatusOutput, error)
	// Cancel requests a cancellation.
	Cancel(ctx context.Context, input transfer.CancelInput) (transfer.CancelOutput, error)
	// StatusText is the complete transfer status text of one record.
	StatusText(transfer.StatusOutput) string
	// StatusLine is the field lines of one record joined for a statusMessage.
	StatusLine(transfer.StatusOutput) string
	// CancelledText is the fixed cancellation line of a job.
	CancelledText(string) string
}

// Manager serves tasks/get, tasks/update and tasks/cancel for the transfer
// tools of one bridge session over a bounded, RAM-only record set. One lock
// serialises its operations: a status read holds it for the interval the
// shared keeper connection is busy anyway.
type Manager struct {
	tools Tools
	now   func() time.Time

	mu      sync.Mutex
	records map[string]*record
	order   []string
}

// NewManager builds the task manager of one bridge; now is the clock of the
// retention rules (nil is the real clock).
func NewManager(tools Tools, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{tools: tools, now: now, records: make(map[string]*record)}
}

// get answers one poll. While the task is not frozen it performs exactly one
// on-demand status read with no wait; a running job moves lastUpdatedAt only
// when the keeper's record changes, while the first terminal record, a job the
// keeper no longer knows and a lost keeper attachment freeze it.
func (m *Manager) get(ctx context.Context, params *GetParams) (*GetResult, error) {
	taskID := ""
	if params != nil {
		taskID = params.TaskID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.lookupLocked(taskID)
	if !ok {
		return nil, unknownTask()
	}
	if rec.frozen {
		return rec.answer(), nil
	}
	out, err := m.tools.Status(ctx, transfer.StatusInput{JobID: rec.id})
	if err != nil {
		if transfer.IsUnknownJob(err) || errors.Is(err, broker.ErrSessionClosed) {
			rec.freeze(statusFailed, m.now())
			return rec.answer(), nil
		}
		return nil, internalFailure(failureMessage)
	}
	switch out.State {
	case stateRunning:
		if out != rec.last {
			rec.updatedAt, rec.last = m.now(), out
		}
		rec.message = m.tools.StatusLine(out)
	case stateCancelled:
		rec.freeze(statusCancelled, m.now())
		rec.message = m.tools.CancelledText(rec.id)
	default:
		rec.freeze(statusCompleted, m.now())
		rec.result = textResult(m.tools.StatusText(out))
	}
	return rec.answer(), nil
}

// cancel passes a cancellation to the keeper. The reply says only that a
// cancellation was requested; the following status read decides the state.
func (m *Manager) cancel(ctx context.Context, params *CancelParams) (*Ack, error) {
	taskID := ""
	if params != nil {
		taskID = params.TaskID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.lookupLocked(taskID)
	if !ok {
		return nil, unknownTask()
	}
	if rec.frozen {
		return ackResult(), nil
	}
	if _, err := m.tools.Cancel(ctx, transfer.CancelInput{JobID: rec.id}); err != nil {
		if transfer.IsUnknownJob(err) {
			m.removeLocked(rec.id)
			return nil, unknownTask()
		}
		return nil, internalFailure(cancelFailureMessage)
	}
	rec.cancelRequested = true
	return ackResult(), nil
}

// update acknowledges a tasks/update without changing any state: this bridge
// never issues an input request.
func (m *Manager) update(params *UpdateParams) (*Ack, error) {
	taskID := ""
	if params != nil {
		taskID = params.TaskID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.lookupLocked(taskID); !ok {
		return nil, unknownTask()
	}
	return ackResult(), nil
}

// unknownTask is the one answer for every handle this bridge does not retain:
// never issued, already dropped, or another session's.
func unknownTask() error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: unknownMessage}
}

// internalFailure is the retryable JSON-RPC failure of the task machinery.
func internalFailure(message string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: message}
}
