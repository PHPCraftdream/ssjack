package tasks

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

const (
	// Bounds is the number of task records one bridge retains.
	Bounds = 64
	// Retention is how long a frozen record stays answerable.
	Retention = time.Hour
)

// stamp formats a record timestamp: RFC 3339 in UTC with whole seconds.
func stamp(at time.Time) string { return at.UTC().Format(time.RFC3339) }

// record is the RAM-only state of one task: a transfer job this bridge
// started. It never carries job content, a path or keeper text.
type record struct {
	id        string
	createdAt time.Time
	updatedAt time.Time
	status    string
	message   string
	// last is the running status record of the previous poll: the task moves
	// lastUpdatedAt when the keeper's record changes, not when its text does.
	last     transfer.StatusOutput
	result   *mcp.CallToolResult
	frozen   bool
	frozenAt time.Time
	// cancelRequested records that a cancellation was passed to the keeper. It
	// is never the task state: the following status read decides that.
	cancelRequested bool
}

// wire renders the Task shape of the record.
func (r *record) wire() taskWire {
	return taskWire{
		TaskID: r.id, Status: r.status, StatusMessage: r.message,
		CreatedAt: stamp(r.createdAt), LastUpdatedAt: stamp(r.updatedAt),
		TTLMs: TTLMs, PollIntervalMs: PollIntervalMs,
	}
}

// handle is the CreateTaskResult of a started job.
func (r *record) handle() *Handle {
	return &Handle{ResultType: resultTypeTask, taskWire: r.wire()}
}

// answer is one tasks/get result of the record as it is now.
func (r *record) answer() *GetResult {
	out := &GetResult{ResultType: resultTypeComplete, taskWire: r.wire()}
	switch r.status {
	case statusCompleted:
		out.Result = r.result
	case statusFailed:
		out.Error = &taskFailure{Code: jsonrpc.CodeInternalError, Message: failureMessage}
	}
	return out
}

// freeze ends the task in a terminal state at at; nothing changes it again, and
// the progress message of an earlier poll is dropped.
func (r *record) freeze(status string, at time.Time) {
	r.status, r.frozen, r.frozenAt, r.updatedAt = status, true, at, at
	r.message = ""
}

// create records a task for a job the keeper just started and returns its
// handle. A full set drops the oldest frozen record first and, when none is
// frozen, the oldest record at all.
func (m *Manager) create(jobID string) *Handle {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	m.removeLocked(jobID)
	for len(m.records) >= Bounds {
		m.evictLocked()
	}
	rec := &record{id: jobID, createdAt: now, updatedAt: now, status: statusWorking}
	m.records[jobID] = rec
	m.order = append(m.order, jobID)
	return rec.handle()
}

// lookupLocked returns the record of an id this bridge retains. A frozen
// record whose retention ended is dropped first and reported unknown.
func (m *Manager) lookupLocked(id string) (*record, bool) {
	if id == "" {
		return nil, false
	}
	m.expireLocked(m.now())
	rec, ok := m.records[id]
	return rec, ok
}

// removeLocked drops one record and its order entry.
func (m *Manager) removeLocked(id string) {
	if _, ok := m.records[id]; !ok {
		return
	}
	delete(m.records, id)
	for index, kept := range m.order {
		if kept == id {
			m.order = append(m.order[:index], m.order[index+1:]...)
			return
		}
	}
}

// expireLocked drops every frozen record whose retention has ended.
func (m *Manager) expireLocked(now time.Time) {
	for _, id := range append([]string(nil), m.order...) {
		if rec, ok := m.records[id]; ok && rec.frozen && !now.Before(rec.frozenAt.Add(Retention)) {
			m.removeLocked(id)
		}
	}
}

// evictLocked drops the frozen record with the earliest freeze time and, when
// none is frozen, the oldest record at all. A freeze time is the moment the
// record ended, which creation order does not follow.
func (m *Manager) evictLocked() {
	oldest := ""
	earliest := ""
	var earliestAt time.Time
	for _, id := range m.order {
		rec, ok := m.records[id]
		if !ok {
			continue
		}
		if oldest == "" {
			oldest = id
		}
		if !rec.frozen {
			continue
		}
		if earliest == "" || rec.frozenAt.Before(earliestAt) {
			earliest, earliestAt = id, rec.frozenAt
		}
	}
	if earliest != "" {
		oldest = earliest
	}
	m.removeLocked(oldest)
}
