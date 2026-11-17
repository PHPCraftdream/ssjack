package bridge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestDeclarativeToolsAreTextOnly(t *testing.T) {
	for _, protocol := range []string{broker.SyntheticProtocol, broker.DeliveryProtocol} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			auth := wire.Auth{Version: 2, Session: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}
			revision := "rev-1"
			keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
				switch req.Operation {
				case "resource_plan":
					return broker.Result(declarativeslice.PlanResult{
						PlanID: "plan1", Digest: "d1", ExpiresAt: "2030-01-02T03:04:05Z", Precondition: &revision,
						Effects: []declarativeslice.Effect{{Class: "cache_metadata", SummaryID: "S1"}},
					}, nil)
				case "plan_apply":
					return broker.Result(declarativeslice.ApplyResult{OperationID: "op1", State: "SUCCEEDED", Delivery: "RECEIVED"}, nil)
				}
				return wire.Reply{Error: "denied"}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer keeper.Close()
			client, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			descriptor := broker.Descriptor{Protocol: protocol, Mode: broker.ModeDeclarative, Tools: []string{"resource_plan", "plan_apply"}}
			registry, err := NewRegistryForDescriptor(client, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			serverTransport, clientTransport := mcp.NewInMemoryTransports()
			serverSession, err := registry.Connect(ctx, serverTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer serverSession.Close()
			session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "dev"}, nil).Connect(ctx, clientTransport, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			tools, err := session.ListTools(ctx, nil)
			if err != nil || len(tools.Tools) != 2 {
				t.Fatalf("unexpected tool list: %+v, %v", tools, err)
			}
			for _, tool := range tools.Tools {
				if tool.OutputSchema != nil {
					t.Fatalf("%s declares an output schema: %+v", tool.Name, tool.OutputSchema)
				}
				if len(tool.Description) > 2000 || !strings.Contains(tool.Description, "plain text") {
					t.Fatalf("%s description is unbounded or does not name its text: %q", tool.Name, tool.Description)
				}
			}
			plan, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: map[string]any{
				"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic",
				"desired": map[string]any{"enabled": true, "ref": "r"}, "request_id": "AAAAAAAAAAAAAAAAAAAAAA",
			}})
			if err != nil || plan.IsError {
				t.Fatalf("resource_plan: %+v, %v", plan, err)
			}
			wantPlan := "Plan plan1 created\nDigest: d1 · Expires: 2030-01-02T03:04:05Z\nPrecondition: rev-1\nEffects: 1\n- cache_metadata: S1\n" +
				"Next: apply it with plan_apply plan_id=plan1 and a new request_id."
			if text := requireTextContract(t, "resource_plan", plan); text != wantPlan {
				t.Fatalf("resource_plan returned\n%s\nwant\n%s", text, wantPlan)
			}
			apply, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": "plan1", "request_id": "AAAAAAAAAAAAAAAAAAAAAA"}})
			if err != nil || apply.IsError {
				t.Fatalf("plan_apply: %+v, %v", apply, err)
			}
			if text := requireTextContract(t, "plan_apply", apply); text != "Operation op1: SUCCEEDED\nDelivery: RECEIVED" {
				t.Fatalf("plan_apply returned %q", text)
			}
		})
	}
}
