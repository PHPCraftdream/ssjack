package tasks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

// fakeTools is the keeper seam of one test: it counts calls and answers from
// injected functions.
type fakeTools struct {
	mu       sync.Mutex
	ids      int
	starts   int
	statuses int
	cancels  int
	statusFn func(call int, input transfer.StatusInput) (transfer.StatusOutput, error)
	cancelFn func(input transfer.CancelInput) (transfer.CancelOutput, error)
	startErr error
}

func (f *fakeTools) Start(_ context.Context, _ transfer.StartInput, _ bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	if f.startErr != nil {
		return "", f.startErr
	}
	f.ids++
	return fmt.Sprintf("%064x", f.ids), nil
}

func (f *fakeTools) Status(_ context.Context, input transfer.StatusInput) (transfer.StatusOutput, error) {
	f.mu.Lock()
	f.statuses++
	call := f.statuses
	fn := f.statusFn
	f.mu.Unlock()
	if fn == nil {
		return transfer.StatusOutput{}, transfer.ErrUnknownJob
	}
	return fn(call, input)
}

func (f *fakeTools) Cancel(_ context.Context, input transfer.CancelInput) (transfer.CancelOutput, error) {
	f.mu.Lock()
	f.cancels++
	fn := f.cancelFn
	f.mu.Unlock()
	if fn == nil {
		return transfer.CancelOutput{Cancelled: true}, nil
	}
	return fn(input)
}

func (f *fakeTools) StatusText(out transfer.StatusOutput) string {
	return "text " + out.State + " " + out.JobID
}

func (f *fakeTools) StatusLine(out transfer.StatusOutput) string { return "line " + out.Phase }

func (f *fakeTools) CancelledText(id string) string { return "Cancelled job " + id }

func (f *fakeTools) Failure(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}

func (f *fakeTools) calls() (starts, statuses, cancels int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.statuses, f.cancels
}

func (f *fakeTools) setStatus(fn func(call int, input transfer.StatusInput) (transfer.StatusOutput, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusFn = fn
}

func (f *fakeTools) setCancel(fn func(input transfer.CancelInput) (transfer.CancelOutput, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelFn = fn
}

// testClock is the injected retention clock.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func newTestManager(t *testing.T) (*Manager, *fakeTools, *testClock) {
	t.Helper()
	clock := newTestClock()
	tools := &fakeTools{}
	return NewManager(tools, clock.Now), tools, clock
}

// createTask starts a job through the fake keeper and records it.
func createTask(t *testing.T, m *Manager, tools *fakeTools) string {
	t.Helper()
	id, err := tools.Start(context.Background(), transfer.StartInput{Target: "t", Local: "l", Remote: "/r"}, false)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if handle := m.create(id); handle.TaskID != id {
		t.Fatalf("handle task id = %q, want %q", handle.TaskID, id)
	}
	return id
}

func getTask(t *testing.T, m *Manager, id string) (*GetResult, error) {
	t.Helper()
	return m.get(context.Background(), &GetParams{TaskID: id})
}

func requireRPCError(t *testing.T, err error, code int64, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error is nil, want %d %q", code, message)
	}
	var rpcErr *jsonrpc.Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error %v is not *jsonrpc.Error", err)
	}
	if rpcErr.Code != code || rpcErr.Message != message {
		t.Fatalf("error = %d %q, want %d %q", rpcErr.Code, rpcErr.Message, code, message)
	}
}

func resultText(t *testing.T, res *GetResult) string {
	t.Helper()
	if res.Result == nil {
		t.Fatalf("result is nil")
	}
	if len(res.Result.Content) != 1 {
		t.Fatalf("result has %d content blocks, want 1", len(res.Result.Content))
	}
	text, ok := res.Result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *mcp.TextContent", res.Result.Content[0])
	}
	return text.Text
}

func parseStamp(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func doneStatus(_ int, input transfer.StatusInput) (transfer.StatusOutput, error) {
	return transfer.StatusOutput{JobID: input.JobID, State: "done"}, nil
}

func runningStatus(phase string) func(int, transfer.StatusInput) (transfer.StatusOutput, error) {
	return func(_ int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: phase}, nil
	}
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func TestCreateAnswersAWorkingHandle(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id, err := tools.Start(context.Background(), transfer.StartInput{Target: "t", Local: "l", Remote: "/r"}, false)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	handle := m.create(id)

	if handle.ResultType != resultTypeTask {
		t.Fatalf("result type = %q, want %q", handle.ResultType, resultTypeTask)
	}
	if handle.TaskID != id {
		t.Fatalf("task id = %q, want %q", handle.TaskID, id)
	}
	if !isHex64(handle.TaskID) {
		t.Fatalf("task id %q is not a 64-hex string", handle.TaskID)
	}
	if handle.Status != statusWorking {
		t.Fatalf("status = %q, want %q", handle.Status, statusWorking)
	}
	if handle.TTLMs != TTLMs {
		t.Fatalf("ttl = %d, want %d", handle.TTLMs, TTLMs)
	}
	if handle.PollIntervalMs != PollIntervalMs {
		t.Fatalf("poll interval = %d, want %d", handle.PollIntervalMs, PollIntervalMs)
	}
	if handle.StatusMessage != "" {
		t.Fatalf("status message = %q, want empty", handle.StatusMessage)
	}
	if handle.CreatedAt != handle.LastUpdatedAt {
		t.Fatalf("created %q != last updated %q", handle.CreatedAt, handle.LastUpdatedAt)
	}
	created := parseStamp(t, handle.CreatedAt)
	parseStamp(t, handle.LastUpdatedAt)
	if !created.Equal(clock.Now()) {
		t.Fatalf("created at %v, want %v", created, clock.Now())
	}
	if starts, statuses, cancels := tools.calls(); starts != 1 || statuses != 0 || cancels != 0 {
		t.Fatalf("keeper calls = %d/%d/%d, want 1/0/0", starts, statuses, cancels)
	}
}

func TestPollReportsRunningRecordsAndMovesLastUpdatedAt(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(call int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		phase := "two"
		if call == 1 {
			phase = "one"
		}
		return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: phase}, nil
	})

	first, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if first.Status != statusWorking {
		t.Fatalf("first status = %q, want %q", first.Status, statusWorking)
	}
	if first.StatusMessage != "line one" {
		t.Fatalf("first status message = %q, want %q", first.StatusMessage, "line one")
	}
	if first.Result != nil {
		t.Fatalf("first result = %v, want nil", first.Result)
	}
	firstStamp := parseStamp(t, first.LastUpdatedAt)

	clock.Advance(time.Second)
	second, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second.StatusMessage != "line two" {
		t.Fatalf("second status message = %q, want %q", second.StatusMessage, "line two")
	}
	secondStamp := parseStamp(t, second.LastUpdatedAt)
	if !secondStamp.After(firstStamp) {
		t.Fatalf("second last updated %v is not after %v", secondStamp, firstStamp)
	}

	third, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("third get: %v", err)
	}
	if third.StatusMessage != "line two" {
		t.Fatalf("third status message = %q, want %q", third.StatusMessage, "line two")
	}
	if third.LastUpdatedAt != second.LastUpdatedAt {
		t.Fatalf("third last updated = %q, want %q", third.LastUpdatedAt, second.LastUpdatedAt)
	}
	if _, statuses, _ := tools.calls(); statuses != 3 {
		t.Fatalf("status calls = %d, want 3", statuses)
	}
}

func TestPollFreezesOnACompletedRecordAndStopsReading(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(doneStatus)

	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.Status != statusCompleted {
		t.Fatalf("status = %q, want %q", res.Status, statusCompleted)
	}
	if text := resultText(t, res); text != "text done "+id {
		t.Fatalf("result text = %q, want %q", text, "text done "+id)
	}
	if res.StatusMessage != "" {
		t.Fatalf("status message = %q, want empty", res.StatusMessage)
	}
	if _, statuses, _ := tools.calls(); statuses != 1 {
		t.Fatalf("status calls = %d, want 1", statuses)
	}
	frozen := res.LastUpdatedAt

	clock.Advance(time.Second)
	again, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if again.LastUpdatedAt != frozen {
		t.Fatalf("last updated = %q, want %q", again.LastUpdatedAt, frozen)
	}
	if text := resultText(t, again); text != "text done "+id {
		t.Fatalf("second result text = %q, want %q", text, "text done "+id)
	}
	if _, statuses, _ := tools.calls(); statuses != 1 {
		t.Fatalf("status calls after freeze = %d, want 1", statuses)
	}
}

func TestPollMapsCancelledJobs(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(_ int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		return transfer.StatusOutput{JobID: input.JobID, State: stateCancelled}, nil
	})

	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.Status != statusCancelled {
		t.Fatalf("status = %q, want %q", res.Status, statusCancelled)
	}
	if res.StatusMessage != "Cancelled job "+id {
		t.Fatalf("status message = %q, want %q", res.StatusMessage, "Cancelled job "+id)
	}
	if res.Result != nil {
		t.Fatalf("result = %v, want nil", res.Result)
	}
}

func TestPollFreezesFailedWhenTheKeeperLostTheJob(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(int, transfer.StatusInput) (transfer.StatusOutput, error) {
		return transfer.StatusOutput{}, transfer.ErrUnknownJob
	})

	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.Status != statusFailed {
		t.Fatalf("status = %q, want %q", res.Status, statusFailed)
	}
	if res.Error == nil {
		t.Fatalf("error is nil")
	}
	if res.Error.Code != jsonrpc.CodeInternalError || res.Error.Message != failureMessage {
		t.Fatalf("error = %d %q, want %d %q", res.Error.Code, res.Error.Message, jsonrpc.CodeInternalError, failureMessage)
	}
	if res.Result != nil {
		t.Fatalf("result = %v, want nil", res.Result)
	}
	frozen := res.LastUpdatedAt

	tools.setStatus(doneStatus)
	clock.Advance(time.Second)
	again, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if again.Status != statusFailed || again.Error == nil || again.Error.Code != jsonrpc.CodeInternalError || again.Error.Message != failureMessage {
		t.Fatalf("second answer = %q %+v, want the frozen failure", again.Status, again.Error)
	}
	if again.LastUpdatedAt != frozen {
		t.Fatalf("last updated = %q, want %q", again.LastUpdatedAt, frozen)
	}
	if again.Result != nil {
		t.Fatalf("second result = %v, want nil", again.Result)
	}
	if _, statuses, _ := tools.calls(); statuses != 1 {
		t.Fatalf("status calls = %d, want 1", statuses)
	}
}

func TestPollReportsAWellFormedReadErrorAndStaysWorking(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(call int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		if call == 1 {
			return transfer.StatusOutput{}, errors.New("keeper refused")
		}
		return doneStatus(call, input)
	})

	_, err := getTask(t, m, id)
	requireRPCError(t, err, jsonrpc.CodeInternalError, failureMessage)

	m.mu.Lock()
	rec, ok := m.records[id]
	status := ""
	if ok {
		status = rec.status
	}
	m.mu.Unlock()
	if !ok || status != statusWorking {
		t.Fatalf("record status = %q (present %v), want %q", status, ok, statusWorking)
	}

	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if res.Status != statusCompleted {
		t.Fatalf("second status = %q, want %q", res.Status, statusCompleted)
	}
	if text := resultText(t, res); text != "text done "+id {
		t.Fatalf("result text = %q, want %q", text, "text done "+id)
	}
}

func TestPollFreezesFailedOnALostAttachment(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(int, transfer.StatusInput) (transfer.StatusOutput, error) {
		return transfer.StatusOutput{}, broker.ErrSessionClosed
	})

	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.Status != statusFailed {
		t.Fatalf("status = %q, want %q", res.Status, statusFailed)
	}
	if res.Error == nil || res.Error.Code != jsonrpc.CodeInternalError || res.Error.Message != failureMessage {
		t.Fatalf("error = %+v, want %d %q", res.Error, jsonrpc.CodeInternalError, failureMessage)
	}
	frozen := res.LastUpdatedAt

	tools.setStatus(doneStatus)
	again, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if again.Status != statusFailed || again.LastUpdatedAt != frozen {
		t.Fatalf("second answer = %q at %q, want %q at %q", again.Status, again.LastUpdatedAt, statusFailed, frozen)
	}
	if _, statuses, _ := tools.calls(); statuses != 1 {
		t.Fatalf("status calls = %d, want 1", statuses)
	}
}

func TestUnknownHandlesAnswerInvalidParamsWithoutTheKeeper(t *testing.T) {
	m, tools, _ := newTestManager(t)
	unknown := fmt.Sprintf("%064x", 7777)
	ctx := context.Background()

	ops := []struct {
		name string
		call func(id string) error
	}{
		{"get", func(id string) error { _, err := m.get(ctx, &GetParams{TaskID: id}); return err }},
		{"cancel", func(id string) error { _, err := m.cancel(ctx, &CancelParams{TaskID: id}); return err }},
		{"update", func(id string) error { _, err := m.update(&UpdateParams{TaskID: id}); return err }},
	}
	handles := []struct{ name, id string }{
		{"unknown", unknown},
		{"empty", ""},
	}
	for _, handle := range handles {
		for _, op := range ops {
			t.Run(handle.name+"/"+op.name, func(t *testing.T) {
				requireRPCError(t, op.call(handle.id), jsonrpc.CodeInvalidParams, unknownMessage)
			})
		}
	}
	if starts, statuses, cancels := tools.calls(); starts != 0 || statuses != 0 || cancels != 0 {
		t.Fatalf("keeper calls = %d/%d/%d, want 0/0/0", starts, statuses, cancels)
	}
}

func TestCancelRecordsTheRequestAndLeavesTheStateToTheNextRead(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)

	ack, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if ack == nil {
		t.Fatalf("ack is nil")
	}
	if ack.ResultType != resultTypeComplete {
		t.Fatalf("ack result type = %q, want %q", ack.ResultType, resultTypeComplete)
	}
	if _, statuses, cancels := tools.calls(); statuses != 0 || cancels != 1 {
		t.Fatalf("keeper calls = status %d cancel %d, want 0/1", statuses, cancels)
	}

	m.mu.Lock()
	rec, ok := m.records[id]
	requested := false
	if ok {
		requested = rec.cancelRequested
	}
	m.mu.Unlock()
	if !ok {
		t.Fatalf("record %q is gone", id)
	}
	if !requested {
		t.Fatalf("cancelRequested = false, want true")
	}

	tools.setStatus(func(_ int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		return transfer.StatusOutput{JobID: input.JobID, State: stateCancelled}, nil
	})
	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.Status != statusCancelled {
		t.Fatalf("status = %q, want %q", res.Status, statusCancelled)
	}
}

func TestCancelDropsTheRecordWhenTheKeeperLostTheJob(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setCancel(func(transfer.CancelInput) (transfer.CancelOutput, error) {
		return transfer.CancelOutput{}, transfer.ErrUnknownJob
	})

	_, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)

	_, err = getTask(t, m, id)
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)

	if _, statuses, cancels := tools.calls(); statuses != 0 || cancels != 1 {
		t.Fatalf("keeper calls = status %d cancel %d, want 0/1", statuses, cancels)
	}
}

func TestCancelLeavesTheRecordOnAReadError(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setCancel(func(transfer.CancelInput) (transfer.CancelOutput, error) {
		return transfer.CancelOutput{}, errors.New("keeper refused")
	})

	_, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
	requireRPCError(t, err, jsonrpc.CodeInternalError, cancelFailureMessage)

	tools.setStatus(runningStatus("one"))
	res, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.Status != statusWorking {
		t.Fatalf("status = %q, want %q", res.Status, statusWorking)
	}
}

func TestCancelOnAFrozenRecordAcksWithoutTheKeeper(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(doneStatus)

	frozen, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if frozen.Status != statusCompleted {
		t.Fatalf("status = %q, want %q", frozen.Status, statusCompleted)
	}
	frozenText := resultText(t, frozen)

	ack, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if ack == nil || ack.ResultType != resultTypeComplete {
		t.Fatalf("ack = %+v, want a complete ack", ack)
	}
	if _, statuses, cancels := tools.calls(); statuses != 1 || cancels != 0 {
		t.Fatalf("keeper calls = status %d cancel %d, want 1/0", statuses, cancels)
	}

	again, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if again.Status != frozen.Status || again.LastUpdatedAt != frozen.LastUpdatedAt {
		t.Fatalf("second answer = %q at %q, want %q at %q", again.Status, again.LastUpdatedAt, frozen.Status, frozen.LastUpdatedAt)
	}
	if text := resultText(t, again); text != frozenText {
		t.Fatalf("second result text = %q, want %q", text, frozenText)
	}
}

func TestUpdateAcknowledgesAKnownHandle(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	beforeStarts, beforeStatuses, beforeCancels := tools.calls()

	ack, err := m.update(&UpdateParams{TaskID: id})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if ack == nil {
		t.Fatalf("ack is nil")
	}
	if ack.ResultType != resultTypeComplete {
		t.Fatalf("ack result type = %q, want %q", ack.ResultType, resultTypeComplete)
	}
	if starts, statuses, cancels := tools.calls(); starts != beforeStarts || statuses != beforeStatuses || cancels != beforeCancels {
		t.Fatalf("keeper calls = %d/%d/%d, want %d/%d/%d", starts, statuses, cancels, beforeStarts, beforeStatuses, beforeCancels)
	}

	_, err = m.update(&UpdateParams{TaskID: fmt.Sprintf("%064x", 8888)})
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)
}

func TestBoundsDropTheOldestFrozenRecordFirst(t *testing.T) {
	m, tools, _ := newTestManager(t)
	ids := make([]string, 0, Bounds+2)
	for i := 0; i < Bounds; i++ {
		ids = append(ids, createTask(t, m, tools))
	}

	tools.setStatus(func(_ int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		if input.JobID == ids[0] {
			return transfer.StatusOutput{JobID: input.JobID, State: "done"}, nil
		}
		return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: "one"}, nil
	})
	frozen, err := getTask(t, m, ids[0])
	if err != nil {
		t.Fatalf("get first: %v", err)
	}
	if frozen.Status != statusCompleted {
		t.Fatalf("first status = %q, want %q", frozen.Status, statusCompleted)
	}

	createTask(t, m, tools)

	_, err = getTask(t, m, ids[0])
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)

	res, err := getTask(t, m, ids[1])
	if err != nil {
		t.Fatalf("get second: %v", err)
	}
	if res.Status != statusWorking {
		t.Fatalf("second status = %q, want %q", res.Status, statusWorking)
	}

	m.mu.Lock()
	kept := len(m.records)
	m.mu.Unlock()
	if kept != Bounds {
		t.Fatalf("records = %d, want %d", kept, Bounds)
	}

	newest := createTask(t, m, tools)

	_, err = getTask(t, m, ids[1])
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)

	res, err = getTask(t, m, newest)
	if err != nil {
		t.Fatalf("get newest: %v", err)
	}
	if res.Status != statusWorking {
		t.Fatalf("newest status = %q, want %q", res.Status, statusWorking)
	}
}

func TestRetentionEndsAFrozenRecordAfterAnHour(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(doneStatus)

	frozen, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if frozen.Status != statusCompleted {
		t.Fatalf("status = %q, want %q", frozen.Status, statusCompleted)
	}

	clock.Advance(59 * time.Minute)
	kept, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get at 59m: %v", err)
	}
	if kept.Status != statusCompleted {
		t.Fatalf("status at 59m = %q, want %q", kept.Status, statusCompleted)
	}
	if kept.LastUpdatedAt != frozen.LastUpdatedAt {
		t.Fatalf("last updated at 59m = %q, want %q", kept.LastUpdatedAt, frozen.LastUpdatedAt)
	}

	clock.Advance(2 * time.Minute)
	_, err = getTask(t, m, id)
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)

	if _, statuses, _ := tools.calls(); statuses != 1 {
		t.Fatalf("status calls = %d, want 1", statuses)
	}
}

// A completed freeze drops the progress message of the running poll before it.
func TestCompletedFreezeDropsTheStaleStatusMessage(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(call int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		if call == 1 {
			return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: "one"}, nil
		}
		return doneStatus(call, input)
	})

	first, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if first.Status != statusWorking || first.StatusMessage != "line one" {
		t.Fatalf("first answer = %q %q, want %q %q", first.Status, first.StatusMessage, statusWorking, "line one")
	}

	second, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second.Status != statusCompleted {
		t.Fatalf("second status = %q, want %q", second.Status, statusCompleted)
	}
	if text := resultText(t, second); text == "" {
		t.Fatalf("second result text is empty")
	}
	if second.StatusMessage != "" {
		t.Fatalf("second status message = %q, want empty", second.StatusMessage)
	}
}

// A failed freeze drops the progress message of the running poll before it.
func TestFailedFreezeDropsTheStaleStatusMessage(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(call int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		if call == 1 {
			return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: "one"}, nil
		}
		return transfer.StatusOutput{}, transfer.ErrUnknownJob
	})

	first, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if first.Status != statusWorking || first.StatusMessage != "line one" {
		t.Fatalf("first answer = %q %q, want %q %q", first.Status, first.StatusMessage, statusWorking, "line one")
	}

	second, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second.Status != statusFailed {
		t.Fatalf("second status = %q, want %q", second.Status, statusFailed)
	}
	if second.Error == nil || second.Error.Code != jsonrpc.CodeInternalError || second.Error.Message != failureMessage {
		t.Fatalf("second error = %+v, want %d %q", second.Error, jsonrpc.CodeInternalError, failureMessage)
	}
	if second.StatusMessage != "" {
		t.Fatalf("second status message = %q, want empty", second.StatusMessage)
	}
}

// An unchanged running record keeps its last updated stamp across polls.
func TestUnchangedRecordKeepsItsLastUpdatedAt(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id := createTask(t, m, tools)
	same := transfer.StatusOutput{JobID: id, State: stateRunning, Phase: "one"}
	tools.setStatus(func(int, transfer.StatusInput) (transfer.StatusOutput, error) {
		return same, nil
	})

	first, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	clock.Advance(time.Second)
	second, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second.StatusMessage != first.StatusMessage {
		t.Fatalf("second status message = %q, want %q", second.StatusMessage, first.StatusMessage)
	}
	if second.LastUpdatedAt != first.LastUpdatedAt {
		t.Fatalf("second last updated = %q, want %q", second.LastUpdatedAt, first.LastUpdatedAt)
	}
	if _, statuses, _ := tools.calls(); statuses != 2 {
		t.Fatalf("status calls = %d, want 2", statuses)
	}
}

// A keeper record change under identical text still moves the last updated stamp.
func TestRoundingHiddenRecordChangeMovesLastUpdatedAt(t *testing.T) {
	m, tools, clock := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(func(call int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		rate := int64(1_300_000)
		if call > 1 {
			rate = 1_300_001
		}
		return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: "one", BytesPerSecond: rate}, nil
	})

	first, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	clock.Advance(time.Second)
	second, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second.StatusMessage != first.StatusMessage {
		t.Fatalf("second status message = %q, want the byte-identical %q", second.StatusMessage, first.StatusMessage)
	}
	if !parseStamp(t, second.LastUpdatedAt).After(parseStamp(t, first.LastUpdatedAt)) {
		t.Fatalf("second last updated %q is not after %q", second.LastUpdatedAt, first.LastUpdatedAt)
	}
}

// A frozen record acks a cancel and keeps its answer once the keeper dropped the job.
func TestFrozenCancelAfterTheKeeperEvictedTheJob(t *testing.T) {
	m, tools, _ := newTestManager(t)
	id := createTask(t, m, tools)
	tools.setStatus(doneStatus)

	frozen, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if frozen.Status != statusCompleted {
		t.Fatalf("status = %q, want %q", frozen.Status, statusCompleted)
	}
	frozenText := resultText(t, frozen)

	tools.setStatus(func(int, transfer.StatusInput) (transfer.StatusOutput, error) {
		return transfer.StatusOutput{}, transfer.ErrUnknownJob
	})
	tools.setCancel(func(transfer.CancelInput) (transfer.CancelOutput, error) {
		return transfer.CancelOutput{}, transfer.ErrUnknownJob
	})
	_, beforeStatuses, beforeCancels := tools.calls()

	ack, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if ack == nil || ack.ResultType != resultTypeComplete {
		t.Fatalf("ack = %+v, want a complete ack", ack)
	}
	_, afterStatuses, afterCancels := tools.calls()
	if afterCancels != beforeCancels {
		t.Fatalf("cancel calls = %d, want %d", afterCancels, beforeCancels)
	}
	if afterStatuses != beforeStatuses {
		t.Fatalf("status calls after cancel = %d, want %d", afterStatuses, beforeStatuses)
	}

	again, err := getTask(t, m, id)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if again.Status != frozen.Status || again.LastUpdatedAt != frozen.LastUpdatedAt {
		t.Fatalf("second answer = %q at %q, want %q at %q", again.Status, again.LastUpdatedAt, frozen.Status, frozen.LastUpdatedAt)
	}
	if text := resultText(t, again); text != frozenText {
		t.Fatalf("second result text = %q, want %q", text, frozenText)
	}
	if _, endStatuses, _ := tools.calls(); endStatuses != afterStatuses {
		t.Fatalf("status calls = %d, want %d", endStatuses, afterStatuses)
	}
}

// Eviction drops the earliest-frozen record, not the earliest-created one.
func TestEvictionDropsTheEarliestFrozenRecord(t *testing.T) {
	m, tools, clock := newTestManager(t)
	oldestCreated := createTask(t, m, tools)
	olderFrozen := createTask(t, m, tools)
	frozenFirst := createTask(t, m, tools)
	tools.setStatus(func(_ int, input transfer.StatusInput) (transfer.StatusOutput, error) {
		if input.JobID == olderFrozen || input.JobID == frozenFirst {
			return transfer.StatusOutput{JobID: input.JobID, State: "done"}, nil
		}
		return transfer.StatusOutput{JobID: input.JobID, State: stateRunning, Phase: "one"}, nil
	})

	if res, err := getTask(t, m, frozenFirst); err != nil || res.Status != statusCompleted {
		t.Fatalf("freeze first = %+v, %v, want %q", res, err, statusCompleted)
	}
	clock.Advance(time.Second)
	if res, err := getTask(t, m, olderFrozen); err != nil || res.Status != statusCompleted {
		t.Fatalf("freeze second = %+v, %v, want %q", res, err, statusCompleted)
	}

	for filled := 3; filled < Bounds; filled++ {
		createTask(t, m, tools)
	}
	createTask(t, m, tools)

	_, err := getTask(t, m, frozenFirst)
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)

	kept, err := getTask(t, m, olderFrozen)
	if err != nil {
		t.Fatalf("get earlier frozen: %v", err)
	}
	if kept.Status != statusCompleted {
		t.Fatalf("earlier frozen status = %q, want %q", kept.Status, statusCompleted)
	}

	working, err := getTask(t, m, oldestCreated)
	if err != nil {
		t.Fatalf("get oldest created: %v", err)
	}
	if working.Status != statusWorking {
		t.Fatalf("oldest created status = %q, want %q", working.Status, statusWorking)
	}

	m.mu.Lock()
	records := len(m.records)
	m.mu.Unlock()
	if records != Bounds {
		t.Fatalf("records = %d, want %d", records, Bounds)
	}
}
