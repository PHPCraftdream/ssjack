package declarativeslice_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestScopedSyntheticNegativeAcceptance(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("CI only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, p, c := acceptancePeer(t, ctx)
	defer s.Close()
	defer p.Close()
	defer c.Close()
	before := stateDigest(t)
	bad := []map[string]any{
		{"target": "wrong", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": reference}, "request_id": "AAAAAAAAAAAAAAAAAAAAAA"},
		{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "bad", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": reference}, "request_id": "AgICAgICAgICAgICAgICAg"},
		{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": "invalid-canonical"}, "request_id": "AwMDAwMDAwMDAwMDAwMDAw"},
	}
	for _, in := range bad {
		r, e := p.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: in})
		if e == nil && r != nil && !r.IsError {
			t.Fatal("invalid plan accepted")
		}
	}
	if stateDigest(t) != before {
		t.Fatal("rejected plan mutated state")
	}
	plan := planOverMCP(t, ctx, p, "BAQEBAQEBAQEBAQEBAQEBA", true)
	res := applyOverMCP(t, ctx, p, plan.PlanID, "BQUFBQUFBQUFBQUFBQUFBQ")
	if res.State != "SUCCEEDED" {
		t.Fatal("valid second fitting operation failed")
	}
	after := stateDigest(t)
	var out map[string]any
	if c.Call(ctx, "plan_apply", map[string]any{"plan_id": plan.PlanID, "request_id": "BgYGBgYGBgYGBgYGBgYGBg", "extra": true}, &out) == nil {
		t.Fatal("unknown apply property accepted")
	}
	retry, e := p.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": plan.PlanID, "request_id": "BwcHBwcHBwcHBwcHBwcHBw"}})
	if e == nil && retry != nil && !retry.IsError {
		t.Fatal("changed request reused consumed plan")
	}
	if stateDigest(t) != after {
		t.Fatal("rejected call mutated state")
	}
	freshPlan := planOverMCP(t, ctx, p, "CQkJCQkJCQkJCQkJCQkJCQ", true)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	_, err := p.CallTool(cancelled, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": freshPlan.PlanID, "request_id": "CgoKCgoKCgoKCgoKCgoKCg"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled apply error = %v, want context.Canceled", err)
	}
	if stateDigest(t) != after {
		t.Fatal("pre-cancelled apply mutated state")
	}
	preCancelBefore := after
	preCancelledApplied := applyOverMCP(t, ctx, p, freshPlan.PlanID, "CgoKCgoKCgoKCgoKCgoKCg")
	if preCancelledApplied.State != "SUCCEEDED" {
		t.Fatal("pre-cancelled apply consumed the fresh plan or closed the broker")
	}
	after = stateDigest(t)
	if after == preCancelBefore {
		t.Fatal("positive-control apply did not persist state")
	}
	fs, fp, fc := acceptancePeer(t, ctx)
	defer fs.Close()
	defer fp.Close()
	defer fc.Close()
	foreign, e := fp.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": plan.PlanID, "request_id": "CwsLCwsLCwsLCwsLCwsLCw"}})
	if e == nil && foreign != nil && !foreign.IsError {
		t.Fatal("cross-session plan accepted")
	}
	for _, op := range []string{"start", "targets", "app_start", "app_exec", "operation_read", "secret.read"} {
		var v map[string]any
		if c.Call(ctx, op, map[string]any{}, &v) == nil {
			t.Fatalf("forbidden operation accepted: %s", op)
		}
	}
	if stateDigest(t) != after {
		t.Fatal("denial changed state")
	}
}

func TestScopedLostReplyReconcilesCommittedOperation(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("delay fixture installed only by isolated CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, peer, _ := acceptancePeer(t, ctx)
	defer s.Close()
	defer peer.Close()
	before := stateDigest(t)
	plan := planOverMCP(t, ctx, peer, "FhYWFhYWFhYWFhYWFhYWFg", true)
	started := time.Now()
	first := applyOverMCP(t, ctx, peer, plan.PlanID, "GRkZGRkZGRkZGRkZGRkZGQ")
	if time.Since(started) < 5*time.Second || first.State != "SUCCEEDED" || first.OperationID == "" {
		t.Fatalf("delayed apply was not reconciled: %+v", first)
	}
	committed := stateDigest(t)
	if committed == before {
		t.Fatal("apply did not persist state")
	}
	replay := applyOverMCP(t, ctx, peer, plan.PlanID, "GRkZGRkZGRkZGRkZGRkZGQ")
	if replay != first || stateDigest(t) != committed {
		t.Fatal("same-request retry changed operation or state")
	}
	result, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": plan.PlanID, "request_id": "GhoaGhoaGhoaGhoaGhoaGg"}})
	if err == nil && result != nil && !result.IsError {
		t.Fatal("different request id reused consumed plan")
	}
	if stateDigest(t) != committed {
		t.Fatal("different request id changed state")
	}
}
func TestScopedInFlightCancellationPreservesCommittedEffect(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("task231_lostreply fixture installed only by isolated CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, peer, _ := acceptancePeer(t, ctx)
	defer s.Close()
	defer peer.Close()
	before := stateDigest(t)
	plan := planOverMCP(t, ctx, peer, "DAwMDAwMDAwMDAwMDAwMDA", true)
	callCtx, cancelCall := context.WithCancel(ctx)
	defer cancelCall()
	type callResult struct {
		result *mcp.CallToolResult
		err    error
	}
	completed := make(chan callResult, 1)
	go func() {
		result, err := peer.CallTool(callCtx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": plan.PlanID, "request_id": "DQ0NDQ0NDQ0NDQ0NDQ0NDQ"}})
		completed <- callResult{result: result, err: err}
	}()
	deadline := time.NewTimer(4 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	var committed string
	for committed == "" {
		select {
		case result := <-completed:
			cancelCall()
			t.Fatalf("MCP apply completed before observed commit and cancellation: err=%v result=%#v", result.err, result.result)
		case <-ticker.C:
			current := stateDigest(t)
			if current != before {
				committed = current
			}
		case <-deadline.C:
			cancelCall()
			t.Fatal("driver effect was not observed before delayed reply")
		case <-ctx.Done():
			cancelCall()
			t.Fatal("context expired waiting for committed driver effect")
		}
	}
	select {
	case early := <-completed:
		cancelCall()
		t.Fatalf("MCP apply completed before cancellation: err=%v result=%#v", early.err, early.result)
	default:
	}
	cancelCall()
	var reply callResult
	select {
	case reply = <-completed:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled MCP call did not return promptly")
	}
	if !errors.Is(reply.err, context.Canceled) || reply.result != nil {
		t.Fatalf("cancelled MCP call = (result=%#v, error=%v), want nil result and context.Canceled", reply.result, reply.err)
	}
	settle := time.NewTimer(7 * time.Second)
	defer settle.Stop()
	select {
	case <-settle.C:
	case <-ctx.Done():
		t.Fatal("context expired during bounded post-cancellation observation")
	}
	if final := stateDigest(t); final != committed {
		t.Fatalf("backing state changed after cancellation: committed %s, final %s", committed, final)
	}
}

func TestScopedDriverOutputRefused(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("adversarial driver CI only")
	}
	before := stateDigest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, p, _ := acceptancePeer(t, ctx)
	defer s.Close()
	defer p.Close()
	r, e := p.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: map[string]any{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": reference}, "request_id": "BQUFBQUFBQUFBQUFBQUFBQ"}})
	if e == nil && r != nil && !r.IsError {
		t.Fatal("untrusted driver response accepted")
	}
	if stateDigest(t) != before {
		t.Fatal("invalid driver response mutated metadata state")
	}
}

func TestScopedAuthorityUnavailable(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("CI lifecycle only")
	}
	s, e := declarativeslice.New()
	if e == nil {
		s.Close()
		t.Fatal("New accepted unavailable grant")
	}
}
func TestScopedLiveAuthorityRecheck(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("CI lifecycle only")
	}
	dir, phase := os.Getenv("SSJACK_DECLARATIVE_CI_COORD_DIR"), os.Getenv("SSJACK_DECLARATIVE_CI_PHASE")
	if dir == "" || (phase != "revoke" && phase != "code") {
		t.Fatal("lifecycle barrier configuration unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, p, _ := acceptancePeer(t, ctx)
	defer s.Close()
	defer p.Close()
	plan := planOverMCP(t, ctx, p, "EBAQEBAQEBAQEBAQEBAQEA", true)
	ready, goFile := filepath.Join(dir, phase+".ready"), filepath.Join(dir, phase+".go")
	if os.WriteFile(ready, []byte("ready"), 0600) != nil {
		t.Fatal("failed to signal ready")
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(goFile); e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, e := os.Stat(goFile); e != nil {
		t.Fatal("lifecycle barrier timeout")
	}
	before := stateDigest(t)
	r, e := p.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": plan.PlanID, "request_id": "FBUVFRUVFRUVFRUVFRUVFQ"}})
	if e == nil && r != nil && !r.IsError {
		t.Fatal("live stale authority applied")
	}
	if stateDigest(t) != before {
		t.Fatal("refused live apply changed state")
	}
}
