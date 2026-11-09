package mcpruntimetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const secretLiteral = "synthetic-bridge-secret"

type fixture struct {
	runtime         *mcpbridge.Runtime
	server          *mcp.Server
	stub            *stubHandle
	listingCounter  *atomic.Int32
	serverWait      chan struct{}
	serverStarted   atomic.Bool
	launchClosed    chan struct{}
	joined          atomic.Bool
	closeCount      atomic.Int32
	closeFailure    atomic.Bool
	closeOnce       sync.Once
	diagnostics     *diagnosticRecorder
	diagnosticLabel string
	parentCtx       context.Context
	closeCallerCtx  string
}

func diagnosticContext(ctx context.Context) string {
	if ctx == nil {
		return "nil"
	}
	return diagnosticError(ctx.Err())
}

func formatDiagnosticStage(name string, s diagnosticStage) string {
	return fmt.Sprintf("%s={entered:%d completed:%d inflight:%d errors:%d first:%s last:%s}",
		name, s.entered, s.completed, s.entered-s.completed, s.errors, s.firstError, s.last)
}

type stubHandle struct {
	taken      atomic.Int32
	transport  mcp.Transport
	beforeTake func(context.Context) error
}

func (h *stubHandle) TakeTransport() (mcp.Transport, error) {
	if h.taken.Add(1) != 1 {
		return nil, errors.New("transport already taken")
	}
	if h.beforeTake != nil {
		if err := h.beforeTake(context.Background()); err != nil {
			return nil, err
		}
	}
	return h.transport, nil
}

func bindings() []mcpdirectory.Binding {
	return []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}}
}

func newServer(pageSize int, calls *atomic.Int32, blockFirst, echoSecret bool) (*mcp.Server, *atomic.Int32, <-chan struct{}) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, &mcp.ServerOptions{PageSize: pageSize})
	listings := &atomic.Int32{}
	started := make(chan struct{}, 1)
	add := func(name, description, text string, structured map[string]any, isError bool) {
		server.AddTool(&mcp.Tool{Name: name, Description: description, InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			resultText := text
			if calls != nil {
				count := calls.Add(1)
				if blockFirst && name == "echo" && count == 1 {
					started <- struct{}{}
					<-ctx.Done()
					return nil, errors.New("synthetic canceled call")
				}
			}
			if name == "echo" {
				resultText = "plain result"
				if echoSecret {
					resultText = "prefix known-startup-literal " + secretLiteral + " suffix"
				}
			}
			result := &mcp.CallToolResult{IsError: isError, StructuredContent: structured}
			if resultText != "" {
				result.Content = []mcp.Content{&mcp.TextContent{Text: resultText}}
			}
			return result, nil
		})
	}
	add("echo", "plain echo tool", "", nil, false)
	add("leak", "leaks "+secretLiteral, "leak "+secretLiteral+" inside", map[string]any{"echoed": secretLiteral, "n": 7}, false)
	add("fail", "upstream error", "error "+secretLiteral, nil, true)
	add("huge", "oversized result", strings.Repeat("x", 70<<10), nil, false)
	return server, listings, started
}

func newFixture(t *testing.T, ctx context.Context, pageSize int, blockFirst, echoSecret bool) *fixture {
	t.Helper()
	calls := &atomic.Int32{}
	server, listings, _ := newServer(pageSize, calls, blockFirst, echoSecret)
	return newFixtureWithServer(t, ctx, server, listings, calls, mustGuard(t, secretLiteral))
}

func newFixtureWithServer(t *testing.T, ctx context.Context, server *mcp.Server, listings, calls *atomic.Int32, guard *outputguard.Snapshot) *fixture {
	t.Helper()
	serverTransport, clientBase := mcp.NewInMemoryTransports()
	diagnostics := &diagnosticRecorder{}
	var clientTransport mcp.Transport = &diagnosticTransport{base: clientBase, recorder: diagnostics}
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			if method == "tools/list" && listings != nil {
				listings.Add(1)
			}
			return next(ctx, method, request)
		}
	})
	f := &fixture{server: server, listingCounter: listings, serverWait: make(chan struct{}), launchClosed: make(chan struct{}), diagnostics: diagnostics, diagnosticLabel: "fixture", parentCtx: ctx}
	f.stub = &stubHandle{transport: clientTransport, beforeTake: func(takeCtx context.Context) error {
		serverSession, err := server.Connect(takeCtx, serverTransport, nil)
		if err != nil {
			return err
		}
		f.serverStarted.Store(true)
		go func() {
			recordServerWait(diagnostics, serverSession.Wait, func() { close(f.serverWait) })
		}()
		return nil
	}}
	closeLaunch := func(closeCtx context.Context) (result error) {
		diagnostics.recordLaunchStart(closeCtx)
		defer func() { diagnostics.recordLaunchEnd(result) }()
		f.closeCount.Add(1)
		if f.serverStarted.Load() {
			select {
			case <-f.serverWait:
				f.joined.Store(true)
			case <-closeCtx.Done():
				return closeCtx.Err()
			}
		}
		if f.closeFailure.Load() {
			return errors.New("synthetic close failure")
		}
		f.closeOnce.Do(func() { close(f.launchClosed) })
		return nil
	}
	var err error
	f.runtime, err = mcpbridge.Open(ctx, []mcpbridge.UpstreamHandle{f.stub}, guard, closeLaunch, bindings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.runtime.Close(closeCtx); err != nil {
			f.closeCallerCtx = diagnosticContext(closeCtx)
			t.Errorf("fixture cleanup %s did not join: outcome=%s", f.diagnosticLabel, diagnosticError(err))
		} else {
			f.closeCallerCtx = diagnosticContext(closeCtx)
		}
		if t.Failed() {
			t.Log(f.diagnosticReport(f.diagnosticLabel, diagnosticContext(f.parentCtx)))
		}
	})
	return f
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (f *fixture) listingCount() int32 {
	if f.listingCounter == nil {
		return 0
	}
	return f.listingCounter.Load()
}

func mustGuard(t *testing.T, literals ...string) *outputguard.Snapshot {
	t.Helper()
	patterns := make([][]byte, len(literals))
	for i, literal := range literals {
		patterns[i] = []byte(literal)
	}
	guard, err := outputguard.New(patterns)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func send(t *testing.T, f *fixture, ctx context.Context, operation string, input any) (wire.Reply, bool) {
	t.Helper()
	data, err := wire.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	return f.runtime.Handle(ctx, wire.Request{Operation: operation, Data: data})
}

func reply(t *testing.T, f *fixture, ctx context.Context, operation string, input any) wire.Reply {
	t.Helper()
	result, handled := send(t, f, ctx, operation, input)
	if !handled {
		t.Fatalf("operation %q was not handled", operation)
	}
	return result
}

func decode(t *testing.T, result wire.Reply, out any) {
	t.Helper()
	if !result.OK {
		t.Fatalf("unexpected reply: %+v", result)
	}
	if err := wire.Decode(result.Data, out); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
}

type ordinalInput struct {
	Ordinal int `json:"ordinal"`
}

func inventory(t *testing.T, f *fixture, ctx context.Context) mcpbridge.InventoryOutput {
	t.Helper()
	var envelope mcpbridge.InventoryEnvelope
	decode(t, reply(t, f, ctx, mcpbridge.OpDescribe, ordinalInput{}), &envelope)
	var out mcpbridge.InventoryOutput
	decoder := json.NewDecoder(strings.NewReader(envelope.Inventory))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		t.Fatalf("decode inventory JSON: %v", err)
	}
	return out
}

func namedTool(t *testing.T, f *fixture, ctx context.Context, suffix string) string {
	t.Helper()
	for _, tool := range inventory(t, f, ctx).Tools {
		if strings.HasSuffix(tool.Name, suffix) {
			return tool.Name
		}
	}
	t.Fatalf("tool suffix %q missing", suffix)
	return ""
}

func (f *fixture) closeWithin(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return f.runtime.Close(ctx)
}
