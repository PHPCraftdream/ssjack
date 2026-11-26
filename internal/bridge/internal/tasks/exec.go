package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const contextCanceledText = "context canceled"

type toolKind uint8

const (
	remoteExec toolKind = iota + 1
	appExec
)

// execControl contains the content-free fields retained from one exec read.
type execControl struct {
	done, errored              bool
	exitCode                   int
	stdoutOffset, stderrOffset int64
	stdoutMore, stderrMore     bool
	stdoutLost, stderrLost     bool
}

// ExecTools is the keeper seam for command and application job operations.
// Read returns the keeper's raw chunk bytes, used to derive the pre-read resume
// offsets from its next offsets; when a job is evicted, the keeper returns its
// fixed error text, which the manager matches.
type ExecTools interface {
	Read(context.Context, remote.ReadInput, bool) (remote.ReadOutput, error)
	Cancel(context.Context, remote.JobInput, bool) error
}

// ReadExec performs the shared task read path against the exec keeper.
func (m *Manager) ReadExec(ctx context.Context, params *GetParams) (*GetResult, error) {
	id := ""
	if params != nil {
		id = params.TaskID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.lookupLocked(id)
	if !ok {
		return nil, unknownTask()
	}
	if r.kind == 0 {
		return nil, unknownTask()
	}
	if r.frozen {
		return r.answer(), nil
	}
	if m.execTools == nil {
		return nil, internalFailure(failureMessage)
	}
	out, err := m.execTools.Read(ctx, remote.ReadInput{JobID: r.id}, r.kind == appExec)
	if err != nil {
		if errors.Is(err, broker.ErrSessionClosed) || err.Error() == "unknown operation" {
			r.freeze(statusFailed, m.now())
			return r.answer(), nil
		}
		return nil, internalFailure(failureMessage)
	}
	// Discard the raw output before deriving or storing any record/result data.
	stdoutLen, stderrLen := len(out.Stdout), len(out.Stderr)
	out.Stdout, out.Stderr = nil, nil
	control := execControl{done: out.Done, errored: out.Error != "", exitCode: out.ExitCode,
		stdoutOffset: clampOffset(out.StdoutOffset - int64(stdoutLen)), stderrOffset: clampOffset(out.StderrOffset - int64(stderrLen)),
		stdoutMore: stdoutLen > 0 || out.StdoutMore, stderrMore: stderrLen > 0 || out.StderrMore,
		stdoutLost: out.StdoutLost, stderrLost: out.StderrLost}
	if control != r.lastExec {
		r.updatedAt, r.lastExec = m.now(), control
	}
	if !control.done {
		r.status = statusWorking
		r.message = ""
		return r.answer(), nil
	}
	if out.Error == contextCanceledText {
		r.freeze(statusCancelled, m.now())
		r.message = "Cancelled job " + r.id
		return r.answer(), nil
	}
	r.freeze(statusCompleted, m.now())
	r.result = textResult(renderExecResult(r.id, control, out.Error))
	return r.answer(), nil
}

// CancelExec requests cancellation using the tool kind fixed on task creation.
func (m *Manager) CancelExec(ctx context.Context, params *CancelParams) (*Ack, error) {
	id := ""
	if params != nil {
		id = params.TaskID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.lookupLocked(id)
	if !ok {
		return nil, unknownTask()
	}
	if r.frozen {
		return ackResult(), nil
	}
	if r.kind == 0 {
		return nil, unknownTask()
	}
	if m.execTools == nil {
		return nil, internalFailure(cancelFailureMessage)
	}
	if err := m.execTools.Cancel(ctx, remote.JobInput{JobID: r.id}, r.kind == appExec); err != nil {
		if err.Error() == "unknown operation" {
			m.removeLocked(r.id)
			return nil, unknownTask()
		}
		return nil, internalFailure(cancelFailureMessage)
	}
	r.cancelRequested = true
	return ackResult(), nil
}

// CreateExec records a job after its start returned an id.
func (m *Manager) CreateExec(jobID string, application bool) *Handle {
	kind := remoteExec
	if application {
		kind = appExec
	}
	return m.createKind(jobID, kind)
}

func clampOffset(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func renderExecResult(id string, c execControl, errText string) string {
	status := fmt.Sprintf("Status: finished · exit code %d", c.exitCode)
	resume := fmt.Sprintf("Resume: stdout_offset=%d stderr_offset=%d · more: stdout=%s stderr=%s · lost: stdout=%s stderr=%s · job %s", c.stdoutOffset, c.stderrOffset, yesNo(c.stdoutMore), yesNo(c.stderrMore), yesNo(c.stdoutLost), yesNo(c.stderrLost), id)
	if errText != "" {
		return status + "\nError: " + oneLine(errText) + "\n" + resume
	}
	return status + "\n" + resume
}
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
