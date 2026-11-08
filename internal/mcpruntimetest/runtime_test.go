package mcpruntimetest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestBindingsAndDescribeUseBoundIdentityAndFreezeInventory(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, false)
	var listed mcpbridge.BindingsOutput
	decode(t, reply(t, f, ctx, mcpbridge.OpBindings, struct{}{}), &listed)
	if len(listed.Ordinals) != 1 || listed.Ordinals[0] != 0 || f.stub.taken.Load() != 0 {
		t.Fatalf("unexpected bindings response or upstream access: %+v takes=%d", listed, f.stub.taken.Load())
	}
	first := inventory(t, f, ctx)
	if len(first.Tools) != 4 || first.Ordinal != 0 {
		t.Fatalf("unexpected inventory: %+v", first)
	}
	var prefix string
	for _, tool := range first.Tools {
		for _, name := range []string{"echo", "leak", "fail", "huge"} {
			if strings.HasSuffix(tool.Name, name) {
				prefix = strings.TrimSuffix(tool.Name, name)
				break
			}
		}
		if prefix != "" {
			break
		}
	}
	if !strings.HasPrefix(prefix, "mcp") || len(prefix) <= len("mcp") {
		t.Fatalf("tool lacks namespace derived from bound identity: %q", prefix)
	}
	for _, tool := range first.Tools {
		if !strings.HasPrefix(tool.Name, prefix) {
			t.Fatalf("inventory mixed binding namespaces: %q prefix=%q", tool.Name, prefix)
		}
	}
	f.server.AddTool(&mcp.Tool{Name: "later", Description: "late", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	second := inventory(t, f, ctx)
	if len(second.Tools) != 4 || f.listingCount() != 1 || f.stub.taken.Load() != 1 {
		t.Fatalf("inventory re-listed or retargeted: tools=%d lists=%d takes=%d", len(second.Tools), f.listingCount(), f.stub.taken.Load())
	}
	first.Tools[0].Description = "caller mutation"
	first.Tools[0].Schema["type"] = "caller mutation"
	third := inventory(t, f, ctx)
	if third.Tools[0].Description == "caller mutation" || third.Tools[0].Schema["type"] == "caller mutation" {
		t.Fatal("returned inventory mutation changed frozen copy")
	}
}

func TestCallMasksUpstreamOutputAndRejectsInvalidInput(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, false)
	tool := namedTool(t, f, ctx, "leak")
	var out mcpbridge.CallOutput
	decode(t, reply(t, f, ctx, mcpbridge.OpCall, mcpbridge.CallInput{Ordinal: 0, Tool: tool}), &out)
	if strings.Contains(out.Result, secretLiteral) || !strings.Contains(out.Result, outputguard.Marker) || !strings.Contains(out.Result, `"n":7`) {
		t.Fatalf("unexpected masked result: %s", out.Result)
	}
	bad := []mcpbridge.CallInput{
		{Ordinal: 0, Tool: "unknown"},
		{Ordinal: 0, Tool: tool, Arguments: "not json"},
		{Ordinal: 0, Tool: tool, Arguments: fmt.Sprintf(`{"x":%q}`, strings.Repeat("x", 100<<10))},
	}
	for _, input := range bad {
		if result := reply(t, f, ctx, mcpbridge.OpCall, input); result.OK {
			t.Fatalf("invalid call was accepted: %+v", input)
		}
	}
}

func TestCallFailurePoisonsBindingWithoutReplay(t *testing.T) {
	ctx := testContext(t)
	calls := &atomic.Int32{}
	server, listings, started := newServer(0, calls, true, false)
	f := newFixtureWithServer(t, ctx, server, listings, calls, mustGuard(t, secretLiteral))
	tool := namedTool(t, f, ctx, "echo")
	first, cancel := context.WithCancel(ctx)
	defer cancel()
	firstResult := make(chan wire.Reply, 1)
	go func() {
		firstResult <- reply(t, f, first, mcpbridge.OpCall, mcpbridge.CallInput{Ordinal: 0, Tool: tool})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("call handler did not reach its barrier")
	}
	cancel()
	select {
	case first := <-firstResult:
		if first.OK || first.Error != "remote MCP tool call failed" || calls.Load() != 1 {
			t.Fatalf("first call did not produce one fixed failure: %+v calls=%d", first, calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("canceled call did not return")
	}
	second := reply(t, f, ctx, mcpbridge.OpCall, mcpbridge.CallInput{Ordinal: 0, Tool: tool})
	if second.OK || second.Error != "remote MCP inventory is unavailable" || calls.Load() != 1 {
		t.Fatalf("poisoned binding was not refused without replay: %+v calls=%d", second, calls.Load())
	}
	if err := f.closeWithin(time.Second); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if !channelClosed(f.serverWait) {
		t.Fatal("actual SDK server session did not finish after transport cleanup")
	}
}

func TestCloseJoinsBlockedOperationBeforeRetryingCleanup(t *testing.T) {
	ctx := testContext(t)
	started, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	server := mcp.NewServer(&mcp.Implementation{Name: "blocked", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "wait", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		started <- struct{}{}
		<-release
		return &mcp.CallToolResult{}, nil
	})
	f := newFixtureWithServer(t, ctx, server, &atomic.Int32{}, &atomic.Int32{}, mustGuard(t, secretLiteral))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	tool := namedTool(t, f, ctx, "wait")
	result := make(chan wire.Reply, 1)
	go func() { result <- reply(t, f, ctx, mcpbridge.OpCall, mcpbridge.CallInput{Ordinal: 0, Tool: tool}) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("blocked tool handler did not start")
	}
	if err := f.closeWithin(20 * time.Millisecond); err == nil {
		t.Fatal("Close did not wait for the in-flight operation")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case first := <-result:
		if first.OK {
			t.Fatalf("operation succeeded after shutdown began: %+v", first)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked operation did not return")
	}
	if err := f.closeWithin(time.Second); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if !channelClosed(f.serverWait) {
		t.Fatal("cleanup returned before the SDK server session ended")
	}
}

func TestPaginationAndOversizedInventoryAreRefused(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 2, false, false)
	result := reply(t, f, ctx, mcpbridge.OpDescribe, ordinalInput{})
	if result.OK || f.listingCount() != 1 {
		t.Fatalf("pagination was accepted or listing count wrong: %+v listings=%d", result, f.listingCount())
	}
	oversized := mcp.NewServer(&mcp.Implementation{Name: "wide", Version: "0"}, nil)
	for i := 0; i <= mcpbridge.MaxInventoryTools; i++ {
		name := fmt.Sprintf("tool%02d", i)
		oversized.AddTool(&mcp.Tool{Name: name, Description: "tool", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	}
	counter := &atomic.Int32{}
	f2 := newFixtureWithServer(t, ctx, oversized, counter, &atomic.Int32{}, mustGuard(t, secretLiteral))
	tooMany := reply(t, f2, ctx, mcpbridge.OpDescribe, ordinalInput{})
	if tooMany.OK || counter.Load() != 1 {
		t.Fatalf("oversized inventory accepted or not listed once: %+v count=%d", tooMany, counter.Load())
	}
}

func TestCloseWaitsForActualSDKServerSessionAndIsIdempotent(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, false)
	_ = inventory(t, f, ctx)
	if err := f.closeWithin(time.Second); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !channelClosed(f.serverWait) || !f.joined.Load() || f.closeCount.Load() != 1 {
		t.Fatalf("launch close did not follow SDK server completion: joined=%v count=%d", f.joined.Load(), f.closeCount.Load())
	}
	if err := f.closeWithin(time.Second); err != nil || f.closeCount.Load() != 1 {
		t.Fatalf("repeated close: err=%v count=%d", err, f.closeCount.Load())
	}
}

func TestCloseFailureCanBeRetried(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, false)
	_ = inventory(t, f, ctx)
	f.closeFailure.Store(true)
	if err := f.closeWithin(time.Second); err == nil {
		t.Fatal("launch close failure was hidden")
	}
	f.closeFailure.Store(false)
	if err := f.closeWithin(time.Second); err != nil || f.closeCount.Load() != 2 {
		t.Fatalf("cleanup retry failed: err=%v count=%d", err, f.closeCount.Load())
	}
}

func TestHandleContextDoesNotOwnRuntimeLifetime(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, false)
	message, cancel := context.WithCancel(context.Background())
	if result := reply(t, f, message, mcpbridge.OpBindings, struct{}{}); !result.OK {
		t.Fatalf("bindings: %+v", result)
	}
	cancel()
	var listed mcpbridge.BindingsOutput
	decode(t, reply(t, f, ctx, mcpbridge.OpBindings, struct{}{}), &listed)
	if len(listed.Ordinals) != 1 {
		t.Fatalf("per-message cancellation shut down runtime: %+v", listed)
	}
}

func TestDisconnectSupervisionRequiresExplicitLifetimeBinding(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, false)
	_ = inventory(t, f, ctx)
	supervised, cancel := context.WithCancel(context.Background())
	f.runtime.BindLifetime(supervised)
	cancel()
	select {
	case <-f.launchClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("bound lifetime cancellation did not finish cleanup")
	}
	if !f.joined.Load() {
		t.Fatal("lifetime cleanup did not wait for actual SDK server session")
	}
	result := reply(t, f, ctx, mcpbridge.OpBindings, struct{}{})
	if result.OK || !strings.Contains(result.Error, "shutting down") {
		t.Fatalf("runtime accepted work after bound lifetime ended: %+v", result)
	}
}

func TestConfigureOutputMergesOnlyBeforeFirstMessage(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, true)
	known := mustGuard(t, "known-startup-literal")
	mandatory := mustGuard(t, secretLiteral)
	if err := f.runtime.ConfigureOutput(known, mandatory); err != nil {
		t.Fatalf("ConfigureOutput before first message: %v", err)
	}
	tool := namedTool(t, f, ctx, "echo")
	var out mcpbridge.CallOutput
	decode(t, reply(t, f, ctx, mcpbridge.OpCall, mcpbridge.CallInput{Ordinal: 0, Tool: tool}), &out)
	if strings.Count(out.Result, outputguard.Marker) != 2 || strings.Contains(out.Result, secretLiteral) || strings.Contains(out.Result, "known-startup-literal") {
		t.Fatalf("configured startup literals were not both masked: %s", out.Result)
	}
	if err := f.runtime.ConfigureOutput(known, mandatory); err == nil {
		t.Fatal("ConfigureOutput succeeded after first keeper message")
	}
}

func TestConfigureOutputWithEmptyKnownSnapshotKeepsMandatoryMasking(t *testing.T) {
	ctx := testContext(t)
	f := newFixture(t, ctx, 0, false, true)
	if err := f.runtime.ConfigureOutput(mustGuard(t), mustGuard(t, secretLiteral)); err != nil {
		t.Fatalf("ConfigureOutput with empty known snapshot: %v", err)
	}
	tool := namedTool(t, f, ctx, "echo")
	var out mcpbridge.CallOutput
	decode(t, reply(t, f, ctx, mcpbridge.OpCall, mcpbridge.CallInput{Ordinal: 0, Tool: tool}), &out)
	if strings.Count(out.Result, outputguard.Marker) != 1 || strings.Contains(out.Result, secretLiteral) || !strings.Contains(out.Result, "known-startup-literal") {
		t.Fatalf("empty known snapshot changed mandatory masking: %s", out.Result)
	}
}
