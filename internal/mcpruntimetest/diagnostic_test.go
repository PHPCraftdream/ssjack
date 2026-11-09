package mcpruntimetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type diagnosticStageID uint8

const (
	stageConnect diagnosticStageID = iota
	stageRead
	stageWrite
	stageClose
	stageServerWait
	stageLaunch
)

type diagnosticStage struct {
	entered, completed, errors int
	firstError, last           string
}

type diagnosticSnapshot struct {
	stages        [6]diagnosticStage
	launchContext string
}
type diagnosticRecorder struct {
	mu sync.Mutex
	diagnosticSnapshot
}

func diagnosticError(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected_eof"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrClosedPipe):
		return "closed_pipe"
	case errors.Is(err, net.ErrClosed):
		return "net_closed"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, mcpbridge.ErrBridge):
		return "bridge"
	default:
		return fmt.Sprintf("%T", err)
	}
}

func (r *diagnosticRecorder) begin(id diagnosticStageID) {
	r.mu.Lock()
	r.stages[id].entered++
	r.mu.Unlock()
}

func (r *diagnosticRecorder) end(id diagnosticStageID, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.stages[id]
	s.completed++
	s.last = diagnosticError(err)
	if err != nil {
		s.errors++
		if s.firstError == "" {
			s.firstError = s.last
		}
	}
}

func (r *diagnosticRecorder) snapshot() diagnosticSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.diagnosticSnapshot
}

func (r *diagnosticRecorder) recordLaunchStart(ctx context.Context) {
	r.mu.Lock()
	r.stages[stageLaunch].entered++
	r.launchContext = diagnosticContext(ctx)
	r.mu.Unlock()
}

func (r *diagnosticRecorder) recordLaunchEnd(err error) { r.end(stageLaunch, err) }

type diagnosticTransport struct {
	base     mcp.Transport
	recorder *diagnosticRecorder
}

func (t *diagnosticTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	t.recorder.begin(stageConnect)
	conn, err := t.base.Connect(ctx)
	t.recorder.end(stageConnect, err)
	if conn == nil {
		return nil, err
	}
	return &diagnosticConnection{base: conn, recorder: t.recorder}, err
}

type diagnosticConnection struct {
	base     mcp.Connection
	recorder *diagnosticRecorder
}

func (c *diagnosticConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	c.recorder.begin(stageRead)
	message, err := c.base.Read(ctx)
	c.recorder.end(stageRead, err)
	return message, err
}

func (c *diagnosticConnection) Write(ctx context.Context, message jsonrpc.Message) error {
	c.recorder.begin(stageWrite)
	err := c.base.Write(ctx, message)
	c.recorder.end(stageWrite, err)
	return err
}

func (c *diagnosticConnection) Close() error {
	c.recorder.begin(stageClose)
	err := c.base.Close()
	c.recorder.end(stageClose, err)
	return err
}

func (c *diagnosticConnection) SessionID() string { return c.base.SessionID() }

func recordServerWait(r *diagnosticRecorder, wait func() error, joined func()) {
	r.begin(stageServerWait)
	err := wait()
	r.end(stageServerWait, err)
	joined()
}

func (f *fixture) diagnosticReport(label, parentContext string) string {
	s := f.diagnostics.snapshot()
	return fmt.Sprintf("diagnostic[%s] listings=%d takes=%d launches=%d server_started=%t server_wait_closed=%t server_joined=%t launch_closed=%t close_caller_ctx=%s parent_ctx=%s launch_ctx=%s %s %s %s %s %s %s",
		label, f.listingCount(), f.stub.taken.Load(), f.closeCount.Load(), f.serverStarted.Load(), channelClosed(f.serverWait), f.joined.Load(), channelClosed(f.launchClosed), f.closeCallerCtx, parentContext, s.launchContext,
		formatDiagnosticStage("connect", s.stages[stageConnect]),
		formatDiagnosticStage("read", s.stages[stageRead]),
		formatDiagnosticStage("write", s.stages[stageWrite]),
		formatDiagnosticStage("close", s.stages[stageClose]),
		formatDiagnosticStage("server_wait", s.stages[stageServerWait]),
		formatDiagnosticStage("launch", s.stages[stageLaunch]))
}

func TestDiagnosticConnectionDelegatesAndRecordsCompletion(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "synthetic")
	sentinel := errors.New("synthetic raw diagnostic marker")
	message, response := &jsonrpc.Request{Method: "synthetic/method"}, &jsonrpc.Request{Method: "synthetic/response"}
	base := &diagnosticTestConnection{sessionID: "synthetic-session"}
	r := &diagnosticRecorder{}
	wrapped := &diagnosticConnection{base: base, recorder: r}
	operations := []struct {
		name string
		id   diagnosticStageID
		run  func() diagnosticResult
	}{
		{"Read", stageRead, func() diagnosticResult { m, e := wrapped.Read(ctx); return diagnosticResult{m, e} }},
		{"Write", stageWrite, func() diagnosticResult { return diagnosticResult{err: wrapped.Write(ctx, message)} }},
		{"Close", stageClose, func() diagnosticResult { return diagnosticResult{err: wrapped.Close()} }},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			entered := make(chan struct{})
			var forwardedCtx context.Context
			var forwardedMessage jsonrpc.Message
			gate := func(release <-chan struct{}) { close(entered); <-release }
			call := startDiagnosticCall(t, func(release <-chan struct{}) diagnosticResult {
				base.read = func(got context.Context) (jsonrpc.Message, error) {
					forwardedCtx = got
					gate(release)
					return response, sentinel
				}
				base.write = func(got context.Context, msg jsonrpc.Message) error {
					forwardedCtx, forwardedMessage = got, msg
					gate(release)
					return sentinel
				}
				base.close = func() error { gate(release); return sentinel }
				return operation.run()
			})
			if !awaitDiagnostic(t, entered, "base operation did not reach its barrier") {
				return
			}
			if got := r.snapshot().stages[operation.id]; got.entered != 1 || got.completed != 0 || got.errors != 0 {
				t.Fatalf("blocked operation recorded as completed: %+v", got)
			}
			result, ok := finishDiagnostic(t, call)
			if !ok {
				return
			}
			if result.err != sentinel || operation.id == stageRead && result.message != response || operation.id != stageClose && forwardedCtx != ctx || operation.id == stageWrite && forwardedMessage != message {
				t.Fatal("wrapper changed context, message, or error identity")
			}
			base.read = func(context.Context) (jsonrpc.Message, error) { return nil, nil }
			base.write = func(context.Context, jsonrpc.Message) error { return nil }
			base.close = func() error { return nil }
			second := startDiagnosticCall(t, func(<-chan struct{}) diagnosticResult { return operation.run() })
			secondResult, ok := finishDiagnostic(t, second)
			if !ok {
				return
			}
			if secondResult.err != nil {
				t.Fatalf("successful %s returned error: %v", operation.name, secondResult.err)
			}
			got := r.snapshot().stages[operation.id]
			if got.entered != 2 || got.completed != 2 || got.errors != 1 || got.firstError != diagnosticError(sentinel) || got.last != "ok" {
				t.Fatalf("success overwrote first error or counters: %+v", got)
			}
		})
	}

	for _, returned := range []mcp.Connection{base, nil} {
		transport := &diagnosticTestTransport{connect: func(got context.Context) (mcp.Connection, error) {
			if got != ctx {
				t.Error("Connect context identity changed")
			}
			return returned, sentinel
		}}
		conn, err := (&diagnosticTransport{base: transport, recorder: r}).Connect(ctx)
		if err != sentinel || ((returned == nil) != (conn == nil)) {
			t.Fatal("Connect changed result identity")
		}
		if returned != nil && conn.(*diagnosticConnection).SessionID() != base.sessionID {
			t.Fatal("SessionID was not delegated")
		}
	}
	if r.snapshot().stages[stageConnect].errors != 2 {
		t.Fatal("Connect failures were not recorded")
	}
	f := &fixture{stub: &stubHandle{}, diagnostics: r}
	if strings.Contains(f.diagnosticReport("synthetic", diagnosticContext(ctx)), sentinel.Error()) {
		t.Fatal("report exposed raw error")
	}
	for _, test := range []struct {
		err  error
		want string
	}{
		{io.EOF, "eof"}, {io.ErrUnexpectedEOF, "unexpected_eof"}, {io.ErrClosedPipe, "closed_pipe"},
		{net.ErrClosed, "net_closed"}, {context.Canceled, "canceled"}, {context.DeadlineExceeded, "deadline"}, {mcpbridge.ErrBridge, "bridge"},
	} {
		if got := diagnosticError(test.err); got != test.want {
			t.Errorf("classification=%q, want %q", got, test.want)
		}
	}
}

func TestDiagnosticServerWaitCompletesBeforeJoinSignal(t *testing.T) {
	r := &diagnosticRecorder{}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	joined := make(chan diagnosticSnapshot, 1)
	t.Cleanup(func() {
		unblock()
		awaitDiagnostic(t, done, "server Wait cleanup did not join")
	})
	go func() {
		defer close(done)
		recordServerWait(r, func() error { close(entered); <-release; return io.EOF }, func() { joined <- r.snapshot() })
	}()
	if !awaitDiagnostic(t, entered, "server Wait did not reach its barrier") {
		return
	}
	if got := r.snapshot().stages[stageServerWait]; got.entered != 1 || got.completed != 0 {
		t.Fatalf("Wait recorded before return: %+v", got)
	}
	unblock()
	if !awaitDiagnostic(t, done, "server Wait did not join") {
		return
	}
	select {
	case got := <-joined:
		stage := got.stages[stageServerWait]
		if stage.entered != 1 || stage.completed != 1 || stage.errors != 1 || stage.firstError != "eof" {
			t.Fatalf("Wait completion missing before join signal: %+v", stage)
		}
	case <-time.After(time.Second):
		t.Error("server Wait join signal was not reported")
	}
}
