package tasks

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeExecTools struct {
	read               remote.ReadOutput
	readErr, cancelErr error
	cancelApp          bool
	reads, cancels     int
}

func (f *fakeExecTools) Read(_ context.Context, _ remote.ReadInput, app bool) (remote.ReadOutput, error) {
	f.reads++
	return f.read, f.readErr
}
func (f *fakeExecTools) Cancel(_ context.Context, _ remote.JobInput, app bool) error {
	f.cancels++
	f.cancelApp = app
	return f.cancelErr
}
func execFixture(application bool) (*Manager, *fakeExecTools, string) {
	f := &fakeExecTools{}
	m := NewManagerWithExec(nil, f, nil)
	h := m.CreateExec("job-id", application)
	return m, f, h.TaskID
}
func pollExec(m *Manager, id string) (*GetResult, error) {
	return m.ReadExec(context.Background(), &GetParams{TaskID: id})
}

func resultTextNamed(t *testing.T, name string, res *GetResult) string {
	t.Helper()
	if res.Result == nil {
		t.Fatalf("%s: result is nil", name)
	}
	if len(res.Result.Content) != 1 {
		t.Fatalf("%s: result has %d content blocks, want 1", name, len(res.Result.Content))
	}
	text, ok := res.Result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s: content is %T, want *mcp.TextContent", name, res.Result.Content[0])
	}
	return text.Text
}

func TestExecStateMappingAndRenderers(t *testing.T) {
	cases := []struct {
		name         string
		out          remote.ReadOutput
		status, want string
	}{
		{"running", remote.ReadOutput{}, statusWorking, ""},
		{"success", remote.ReadOutput{Done: true}, statusCompleted, "Status: finished · exit code 0\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no · job job-id"},
		{"nonzero", remote.ReadOutput{Done: true, ExitCode: 3}, statusCompleted, "Status: finished · exit code 3\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no · job job-id"},
		{"runner error", remote.ReadOutput{Done: true, ExitCode: -1, Error: "runner\nfailed"}, statusCompleted, "Status: finished · exit code -1\nError: runner failed\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no · job job-id"},
		{"timeout", remote.ReadOutput{Done: true, ExitCode: -1, Error: "context deadline exceeded"}, statusCompleted, "Status: finished · exit code -1\nError: context deadline exceeded\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no · job job-id"},
	}
	for _, tc := range cases {
		t.Run("case", func(t *testing.T) {
			m, f, id := execFixture(false)
			f.read = tc.out
			got, err := pollExec(m, id)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if got.Status != tc.status {
				t.Fatalf("%s: status %q want %q", tc.name, got.Status, tc.status)
			}
			if tc.status == statusWorking {
				if got.StatusMessage != "" || got.Result != nil {
					t.Fatalf("%s: working response %+v", tc.name, got)
				}
				return
			}
			if text := resultTextNamed(t, tc.name, got); text != tc.want {
				t.Fatalf("%s: result %q want %q", tc.name, text, tc.want)
			}
		})
	}
}

func TestExecCancellationClassificationAndRace(t *testing.T) {
	for _, tc := range []struct {
		name, err string
		code      int
		status    string
		hasResult bool
	}{
		{"cancel literal", "context canceled", 0, statusCancelled, false}, {"runner wins", "", 7, statusCompleted, true}, {"near match", "context canceled ", -1, statusCompleted, true},
	} {
		t.Run("case", func(t *testing.T) {
			m, f, id := execFixture(true)
			if _, err := m.CancelExec(context.Background(), &CancelParams{TaskID: id}); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !f.cancelApp {
				t.Fatalf("%s: app task did not use app cancel", tc.name)
			}
			f.read = remote.ReadOutput{Done: true, Error: tc.err, ExitCode: tc.code}
			got, err := pollExec(m, id)
			if err != nil || got.Status != tc.status || (got.Result != nil) != tc.hasResult {
				t.Fatalf("%s: got %+v, %v", tc.name, got, err)
			}
			if tc.status == statusCancelled && got.StatusMessage != "Cancelled job job-id" {
				t.Fatalf("%s: message %q", tc.name, got.StatusMessage)
			}
		})
	}
}

func TestExecReadOffsetDerivationAndChunkExclusion(t *testing.T) {
	cases := []struct {
		name           string
		out            remote.ReadOutput
		stdout, stderr int64
		sm, em, sl, el bool
	}{
		{"clamp and flags", remote.ReadOutput{Stdout: []byte("abc"), Stderr: []byte("xy"), StdoutOffset: 2, StderrOffset: 5, StdoutLost: true, StderrMore: true}, 0, 3, true, true, true, false},
		{"more without bytes", remote.ReadOutput{StdoutMore: true, StderrMore: true}, 0, 0, true, true, false, false},
		{"nonempty with more false", remote.ReadOutput{Stdout: []byte("s"), StdoutOffset: 1, Stderr: []byte("e"), StderrOffset: 1}, 0, 0, true, true, false, false},
		{"stderr lost", remote.ReadOutput{Stderr: []byte("z"), StderrOffset: 7, StderrLost: true}, 0, 6, false, true, false, true},
	}
	for _, tc := range cases {
		t.Run("case", func(t *testing.T) {
			m, f, id := execFixture(false)
			tc.out.Done = true
			f.read = tc.out
			got, err := pollExec(m, id)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			text := resultTextNamed(t, tc.name, got)
			want := renderExecResult(id, execControl{done: true, stdoutOffset: tc.stdout, stderrOffset: tc.stderr, stdoutMore: tc.sm, stderrMore: tc.em, stdoutLost: tc.sl, stderrLost: tc.el}, "")
			if text != want {
				t.Fatalf("%s: result %q want %q", tc.name, text, want)
			}
			if strings.Contains(text, "abc") || strings.Contains(text, "xy") {
				t.Fatalf("%s: leaked chunk %q", tc.name, text)
			}
		})
	}
	m, f, id := execFixture(false)
	f.read = remote.ReadOutput{Done: true, Stdout: []byte("CANARY/output"), Stderr: []byte("secret"), StdoutOffset: 5, StdoutLost: true}
	got, err := pollExec(m, id)
	if err != nil {
		t.Fatalf("canary: %v", err)
	}
	text := resultText(t, got)
	if strings.Contains(text, "CANARY") || strings.Contains(text, "secret") {
		t.Fatalf("canary: result %q", text)
	}
	m.mu.Lock()
	snapshot := *m.records[id]
	m.mu.Unlock()
	allowed := map[string]bool{"id": true, "createdAt": true, "updatedAt": true, "status": true, "message": true, "last": true, "lastExec": true, "kind": true, "result": true, "frozen": true, "frozenAt": true, "cancelRequested": true}
	for i := 0; i < reflect.TypeOf(snapshot).NumField(); i++ {
		field := reflect.TypeOf(snapshot).Field(i).Name
		if !allowed[field] {
			t.Fatalf("canary: record field %q missing allow-list", field)
		}
	}
	for _, v := range []string{snapshot.message, snapshot.result.Content[0].(*mcp.TextContent).Text} {
		if strings.Contains(v, "CANARY") || strings.Contains(v, "secret") {
			t.Fatalf("canary: record leaks bytes %q", v)
		}
	}
}

func TestExecLastUpdatedTracksControlAndStopsAtFreeze(t *testing.T) {
	clock := newTestClock()
	f := &fakeExecTools{}
	m := NewManagerWithExec(nil, f, clock.Now)
	id := m.CreateExec("clock", false).TaskID
	cases := []struct {
		name    string
		out     remote.ReadOutput
		advance bool
		frozen  bool
	}{
		{"initial", remote.ReadOutput{}, false, false}, {"same", remote.ReadOutput{}, true, false},
		{"offset changed", remote.ReadOutput{StdoutOffset: 4}, true, false}, {"flag changed", remote.ReadOutput{StdoutOffset: 4, StderrLost: true}, true, false},
		{"freeze", remote.ReadOutput{Done: true, ExitCode: 0}, true, true},
	}
	var previous string
	for _, tc := range cases {
		t.Run("case", func(t *testing.T) {
			if tc.advance {
				clock.Advance(time.Second)
			}
			f.read = tc.out
			got, err := m.get(context.Background(), &GetParams{TaskID: id})
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if tc.name == "same" && got.LastUpdatedAt != previous {
				t.Fatalf("%s: unchanged updated %q -> %q", tc.name, previous, got.LastUpdatedAt)
			}
			if (tc.name == "offset changed" || tc.name == "flag changed" || tc.name == "freeze") && got.LastUpdatedAt == previous {
				t.Fatalf("%s: updatedAt did not change", tc.name)
			}
			if tc.frozen && got.Status != statusCompleted {
				t.Fatalf("%s: expected completed status, got %q", tc.name, got.Status)
			}
			previous = got.LastUpdatedAt
		})
	}
	clock.Advance(time.Second)
	stamp := previous
	f.read = remote.ReadOutput{Done: true, ExitCode: 9}
	got, err := m.get(context.Background(), &GetParams{TaskID: id})
	if err != nil || got.LastUpdatedAt != stamp {
		t.Fatalf("frozen: got %+v, %v, want stamp %q", got, err, stamp)
	}
}

func TestExecCreateKindAndManagerDispatch(t *testing.T) {
	tools := &fakeTools{}
	f := &fakeExecTools{}
	m := NewManagerWithExec(tools, f, nil)
	execID := m.CreateExec("exec", false).TaskID
	m.mu.Lock()
	kind := m.records[execID].kind
	m.mu.Unlock()
	if kind != remoteExec {
		t.Fatalf("CreateExec kind %d", kind)
	}
	f.read = remote.ReadOutput{}
	got, err := m.get(context.Background(), &GetParams{TaskID: execID})
	if err != nil || got.Status != statusWorking {
		t.Fatalf("exec get: %+v %v", got, err)
	}
	ack, err := m.cancel(context.Background(), &CancelParams{TaskID: execID})
	if err != nil || ack == nil {
		t.Fatalf("exec cancel: %+v %v", ack, err)
	}
	ack, err = m.update(&UpdateParams{TaskID: execID})
	if err != nil || ack == nil {
		t.Fatalf("exec update: %+v %v", ack, err)
	}
	if f.reads != 1 || f.cancels != 1 {
		t.Fatalf("exec seam calls %d/%d want 1/1", f.reads, f.cancels)
	}
	if starts, statuses, cancels := tools.calls(); starts != 0 || statuses != 0 || cancels != 0 {
		t.Fatalf("transfer calls %d/%d/%d want 0/0/0", starts, statuses, cancels)
	}
	transferID := createTask(t, m, tools)
	tools.setStatus(runningStatus("phase"))
	if _, err := m.get(context.Background(), &GetParams{TaskID: transferID}); err != nil {
		t.Fatalf("transfer get: %v", err)
	}
	if _, err := m.cancel(context.Background(), &CancelParams{TaskID: transferID}); err != nil {
		t.Fatalf("transfer cancel: %v", err)
	}
	if f.reads != 1 || f.cancels != 1 {
		t.Fatalf("transfer dispatched exec: %d/%d", f.reads, f.cancels)
	}
	if _, statuses, cancels := tools.calls(); statuses != 1 || cancels != 1 {
		t.Fatalf("transfer calls %d/%d want 1/1", statuses, cancels)
	}
	if _, err := m.update(&UpdateParams{TaskID: "unknown"}); err == nil {
		t.Fatal("unknown update succeeded")
	} else {
		requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)
	}
}

func requireExecRPCError(t *testing.T, name string, err error, code int64, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: error is nil, want %d %q", name, code, message)
	}
	var rpcErr *jsonrpc.Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("%s: error %v is not *jsonrpc.Error", name, err)
	}
	if rpcErr.Code != code || rpcErr.Message != message {
		t.Fatalf("%s: error = %d %q, want %d %q", name, rpcErr.Code, rpcErr.Message, code, message)
	}
}

func TestExecCancelErrorsAndFrozenAcknowledgement(t *testing.T) {
	for _, kind := range []struct {
		name string
		app  bool
	}{{"remote", false}, {"app", true}} {
		m, f, id := execFixture(kind.app)
		f.cancelErr = errors.New("unknown operation")
		_, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
		requireExecRPCError(t, kind.name, err, jsonrpc.CodeInvalidParams, unknownMessage)
		if _, ok := m.records[id]; ok {
			t.Fatalf("%s unknown cancel retained record", kind.name)
		}
		m, f, id = execFixture(kind.app)
		f.cancelErr = errors.New("temporary")
		_, err = m.cancel(context.Background(), &CancelParams{TaskID: id})
		requireExecRPCError(t, kind.name, err, jsonrpc.CodeInternalError, cancelFailureMessage)
		if f.cancels != 1 {
			t.Fatalf("%s ordinary cancel calls=%d, want 1", kind.name, f.cancels)
		}
		if f.cancelApp != kind.app {
			t.Fatalf("%s ordinary cancel app=%t, want %t", kind.name, f.cancelApp, kind.app)
		}
		if m.records[id] == nil || m.records[id].cancelRequested {
			t.Fatalf("%s failed cancel record state", kind.name)
		}
		f.read = remote.ReadOutput{Done: true, Error: "context canceled"}
		first, err := pollExec(m, id)
		if err != nil || first.Status != statusCancelled {
			t.Fatalf("%s freeze: %+v %v", kind.name, first, err)
		}
		beforeReads, beforeCancels := f.reads, f.cancels
		ack, err := m.cancel(context.Background(), &CancelParams{TaskID: id})
		if err != nil || ack == nil || f.cancels != beforeCancels || f.reads != beforeReads {
			t.Fatalf("%s frozen cancel: ack=%+v err=%v calls=%d/%d want cancels=%d reads=%d", kind.name, ack, err, f.cancels, f.reads, beforeCancels, beforeReads)
		}
	}
}

func TestExecUnknownReadCancelAndNilSeam(t *testing.T) {
	m, f, id := execFixture(false)
	_, err := pollExec(m, "missing")
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)
	if f.reads != 0 {
		t.Fatalf("unknown read calls=%d", f.reads)
	}
	_, err = m.cancel(context.Background(), &CancelParams{TaskID: "missing"})
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)
	if f.cancels != 0 {
		t.Fatalf("unknown cancel calls=%d", f.cancels)
	}
	clock := newTestClock()
	f = &fakeExecTools{}
	m = NewManagerWithExec(nil, f, clock.Now)
	id = m.CreateExec("expired", false).TaskID
	m.mu.Lock()
	m.records[id].freeze(statusCompleted, clock.Now().Add(-Retention))
	m.mu.Unlock()
	_, err = m.ReadExec(context.Background(), &GetParams{TaskID: id})
	requireRPCError(t, err, jsonrpc.CodeInvalidParams, unknownMessage)
	if f.reads != 0 {
		t.Fatalf("expired read called keeper %d times, want 0", f.reads)
	}
	m = NewManagerWithExec(nil, nil, nil)
	id = m.CreateExec("nil", false).TaskID
	_, err = m.ReadExec(context.Background(), &GetParams{TaskID: id})
	requireRPCError(t, err, jsonrpc.CodeInternalError, failureMessage)
	_, err = m.CancelExec(context.Background(), &CancelParams{TaskID: id})
	requireRPCError(t, err, jsonrpc.CodeInternalError, cancelFailureMessage)
}

func TestExecFrozenCancellationAndCompletionRepeat(t *testing.T) {
	for _, tc := range []struct {
		name   string
		out    remote.ReadOutput
		status string
	}{{"cancelled", remote.ReadOutput{Done: true, Error: "context canceled"}, statusCancelled}, {"completed", remote.ReadOutput{Done: true, ExitCode: 4, Stdout: []byte("abc"), StdoutOffset: 3}, statusCompleted}} {
		t.Run("case", func(t *testing.T) {
			m, f, id := execFixture(false)
			f.read = tc.out
			first, err := m.get(context.Background(), &GetParams{TaskID: id})
			if err != nil || first.Status != tc.status {
				t.Fatalf("%s first: %+v %v", tc.name, first, err)
			}
			var text string
			if tc.status == statusCancelled {
				text = first.StatusMessage
				if text != "Cancelled job "+id || first.Result != nil {
					t.Fatalf("%s answer %+v", tc.name, first)
				}
			} else {
				text = resultTextNamed(t, tc.name, first)
			}
			f.readErr = errors.New("must not read")
			second, err := m.get(context.Background(), &GetParams{TaskID: id})
			if err != nil || second.Status != first.Status || f.reads != 1 {
				t.Fatalf("%s replay: %+v %v reads=%d", tc.name, second, err, f.reads)
			}
			if tc.status == statusCancelled {
				if second.StatusMessage != text || second.Result != nil {
					t.Fatalf("%s replay %+v want %q", tc.name, second, text)
				}
			} else if resultTextNamed(t, tc.name, second) != text {
				t.Fatalf("%s replay text changed", tc.name)
			}
		})
	}
}

func TestExecRendererGolden(t *testing.T) {
	if got := renderExecResult("id", execControl{exitCode: 2, stdoutOffset: 4, stderrOffset: 9, stdoutMore: true, stderrLost: true}, ""); got != "Status: finished · exit code 2\nResume: stdout_offset=4 stderr_offset=9 · more: stdout=yes stderr=no · lost: stdout=no stderr=yes · job id" {
		t.Fatalf("renderer: %q", got)
	}
	if got := renderExecResult("id", execControl{exitCode: -1}, "runner\n failed\twith error"); got != "Status: finished · exit code -1\nError: runner failed with error\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no · job id" {
		t.Fatalf("error renderer: %q", got)
	}
	if got := oneLine("a\n b\t c"); got != "a b c" {
		t.Fatalf("oneLine: %q", got)
	}
}
