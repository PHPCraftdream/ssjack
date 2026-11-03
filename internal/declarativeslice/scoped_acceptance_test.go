package declarativeslice_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/wire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const reference = `{"$ssjack":{"format":"ssjack-secret-ref-v1","object_id":"00000000000000000000000000000002","snapshot_id":"00000000000000000000000000000004","store_id":"00000000000000000000000000000001","version_id":"00000000000000000000000000000003"}}`

func TestScopedSyntheticBrokerAcceptance(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("disposable root CI provision required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, peer, c := acceptancePeer(t, ctx)
	defer s.Close()
	defer peer.Close()
	defer c.Close()
	list, err := peer.ListTools(ctx, nil)
	if err != nil || len(list.Tools) != 2 {
		t.Fatal("unexpected MCP tool surface")
	}
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	if !names["resource_plan"] || !names["plan_apply"] {
		t.Fatal("wrong tools")
	}
	before := stateDigest(t)
	p := planOverMCP(t, ctx, peer, "AAAAAAAAAAAAAAAAAAAAAA", true)
	stale := planOverMCP(t, ctx, peer, "AgICAgICAgICAgICAgICAg", false)
	if stateDigest(t) != before {
		t.Fatal("plan mutated state")
	}
	applied := applyOverMCP(t, ctx, peer, p.PlanID, "AQEBAQEBAQEBAQEBAQEBAQ")
	if applied.State != "SUCCEEDED" {
		t.Fatal("apply unsuccessful")
	}
	after := stateDigest(t)
	if after == before {
		t.Fatal("apply did not persist")
	}
	replay := applyOverMCP(t, ctx, peer, p.PlanID, "AQEBAQEBAQEBAQEBAQEBAQ")
	if replay != applied || stateDigest(t) != after {
		t.Fatal("replay changed operation/state")
	}
	staleResult := applyOverMCP(t, ctx, peer, stale.PlanID, "AwMDAwMDAwMDAwMDAwMDAw")
	if staleResult.State != "FAILED" || stateDigest(t) != after {
		t.Fatal("stale plan changed state")
	}
	for _, op := range []string{"targets", "start", "read", "cancel", "app_start", "app_list", "app_read", "app_cancel", "remote_exec", "remote_read", "remote_cancel"} {
		var out map[string]any
		if c.Call(ctx, op, map[string]any{}, &out) == nil {
			t.Fatalf("full op accepted: %s", op)
		}
	}
	if _, err = peer.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{}}); err == nil {
		t.Fatal("full MCP tool present")
	}
	if stateDigest(t) != after {
		t.Fatal("denied full operation changed state")
	}
}

func stateDigest(t *testing.T) string {
	t.Helper()
	b, e := os.ReadFile(declarativeauthority.StatePath + "/state.json")
	if e != nil {
		t.Fatal("state unavailable")
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func acceptancePeer(t *testing.T, ctx context.Context) (*declarativeslice.Session, *mcp.ClientSession, *broker.Client) {
	t.Helper()
	s, err := declarativeslice.New()
	if err != nil {
		t.Fatal("grant unavailable")
	}
	token, _ := wire.RandomToken()
	sid, _ := wire.RandomToken()
	h, err := broker.DispatchSynthetic(s)
	if err != nil {
		t.Fatal(err)
	}
	k, err := broker.Listen(ctx, sid, token, time.Minute, h)
	if err != nil {
		t.Fatal(err)
	}
	c, err := broker.Connect(ctx, k.Endpoint(), k.Pin(), wire.Auth{Version: 2, Session: sid, Token: token})
	if err != nil {
		k.Close()
		t.Fatal(err)
	}
	d, err := broker.Describe(ctx, c)
	if err != nil {
		c.Close()
		k.Close()
		t.Fatal(err)
	}
	r, err := bridge.NewRegistryForDescriptor(c, d)
	if err != nil {
		c.Close()
		k.Close()
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := r.Connect(ctx, st, nil)
	if err != nil {
		c.Close()
		k.Close()
		t.Fatal(err)
	}
	peer, err := mcp.NewClient(&mcp.Implementation{Name: "acceptance", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		ss.Close()
		c.Close()
		k.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close(); ss.Close(); c.Close(); k.Close() })
	return s, peer, c
}
func planOverMCP(t *testing.T, ctx context.Context, p *mcp.ClientSession, id string, enabled bool) declarativeslice.PlanResult {
	t.Helper()
	r, e := p.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: map[string]any{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": enabled, "ref": reference}, "request_id": id}})
	if e != nil || r.IsError {
		t.Fatal("plan call failed")
	}
	var out declarativeslice.PlanResult
	if decodeResult(r, &out) != nil {
		t.Fatal("bad plan result")
	}
	return out
}
func applyOverMCP(t *testing.T, ctx context.Context, p *mcp.ClientSession, id, request string) declarativeslice.ApplyResult {
	t.Helper()
	r, e := p.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": id, "request_id": request}})
	if e != nil || r.IsError {
		t.Fatal("apply call failed")
	}
	var out declarativeslice.ApplyResult
	if decodeResult(r, &out) != nil {
		t.Fatal("bad apply result")
	}
	return out
}
func decodeResult(r *mcp.CallToolResult, v any) error {
	for _, c := range r.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			return json.Unmarshal([]byte(text.Text), v)
		}
	}
	if r.StructuredContent == nil {
		return errors.New("empty result")
	}
	b, e := json.Marshal(r.StructuredContent)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}

func TestScopedPlanExpiry(t *testing.T) {
	if os.Getenv("SSJACK_DECLARATIVE_CI_ACCEPTANCE") != "1" {
		t.Skip("disposable root CI provision required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, peer, _ := acceptancePeer(t, ctx)
	defer s.Close()
	defer peer.Close()
	before := stateDigest(t)
	plan := planOverMCP(t, ctx, peer, "LS0tLS0tLS0tLS0tLS0tLQ", true)
	expires, err := time.Parse(time.RFC3339, plan.ExpiresAt)
	if err != nil {
		t.Fatal("invalid plan expiry")
	}
	if wait := time.Until(expires.Add(100 * time.Millisecond)); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("context expired waiting for plan expiry")
		}
	}
	result, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": plan.PlanID, "request_id": "MTExMTExMTExMTExMTExMQ"}})
	if err == nil && result != nil && !result.IsError {
		t.Fatal("expired plan was applied")
	}
	if stateDigest(t) != before {
		t.Fatal("expired plan changed state")
	}
}
