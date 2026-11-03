package main

// External fixture harness entry point. Provisioned CI supplies only the exact
// synthetic reference as a public argument; broker credentials arrive via the
// authenticated launcher bootstrap environment, never as model input.
import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		os.Exit(1)
	}
	mode := "golden"
	if len(os.Args) == 3 {
		mode = os.Args[2]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	client, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		os.Exit(1)
	}
	defer client.Close()
	descriptor, err := broker.Describe(ctx, client)
	if err != nil || descriptor.Mode != broker.ModeDeclarative || (descriptor.Protocol != broker.DeliveryProtocol && !(strings.HasPrefix(mode, "race-") && descriptor.Protocol == broker.SyntheticProtocol)) {
		os.Exit(1)
	}
	server, err := bridge.NewRegistryForDescriptor(client, descriptor)
	if err != nil {
		os.Exit(1)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		os.Exit(1)
	}
	defer ss.Close()
	peer, err := mcp.NewClient(&mcp.Implementation{Name: "external-delivery-harness", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		os.Exit(1)
	}
	defer peer.Close()
	tools, err := peer.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 2 {
		os.Exit(1)
	}
	seenTools := map[string]bool{}
	for _, tool := range tools.Tools {
		seenTools[tool.Name] = true
	}
	if !seenTools["resource_plan"] || !seenTools["plan_apply"] {
		os.Exit(1)
	}
	ref := os.Args[1]
	if runConcurrentMode(ctx, peer, ref, mode) {
		fmt.Fprintln(os.Stdout, "CONCURRENT_ACCEPTANCE_OK")
		fmt.Fprintln(os.Stdout, "DELIVERY_ACCEPTANCE_OK")
		return
	}
	if runForeignMode(ctx, peer, ref, mode) {
		fmt.Fprintln(os.Stdout, "DELIVERY_ACCEPTANCE_OK")
		return
	}
	firstRequest := randomID()
	first := plan(ctx, peer, ref, firstRequest)
	stale := plan(ctx, peer, ref, randomID())
	must(first.Effects != nil && len(first.Effects) == 1 && first.Effects[0].Class == "confidential_delivery" && first.Precondition != nil)
	must(stale.PlanID != first.PlanID)
	for _, op := range []string{"targets", "start", "read", "cancel", "app_list", "app_start", "app_read", "app_cancel", "remote_exec", "remote_read", "remote_cancel"} {
		err = client.Call(ctx, op, map[string]any{}, nil)
		must(err != nil)
	}
	result, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{}})
	must(err != nil || result != nil && result.IsError)
	_, err = callApply(ctx, peer, randomID(), randomID())
	must(err != nil)
	for _, args := range []map[string]any{
		{"target": "wrong", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": ref}, "request_id": randomID()},
		{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": "wrong/ref"}, "request_id": randomID()},
		{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": ref, "extra": true}, "request_id": randomID()},
		{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": false, "ref": ref}, "request_id": randomID()},
	} {
		result, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: args})
		must(err != nil || result != nil && result.IsError)
	}
	if mode == "golden" {
		got, err := callApply(ctx, peer, first.PlanID, firstRequest)
		must(err == nil && got.State == "SUCCEEDED" && got.Delivery == "RECEIVED")
		replay, err := callApply(ctx, peer, first.PlanID, firstRequest)
		must(err == nil && replay == got)
		_, err = callApply(ctx, peer, stale.PlanID, firstRequest)
		must(err != nil)
		staleResult, err := callApply(ctx, peer, stale.PlanID, randomID())
		must(err == nil && staleResult.State == "FAILED")
		second := plan(ctx, peer, ref, randomID())
		got2, err := callApply(ctx, peer, second.PlanID, randomID())
		must(err == nil && got2.State == "SUCCEEDED" && got2.Delivery == "RECEIVED" && got2.OperationID != got.OperationID)
	} else if mode == "unknown" || mode == "withheld" {
		got, err := callApply(ctx, peer, first.PlanID, firstRequest)
		must(err == nil)
		if mode == "unknown" {
			must(got.State == "UNKNOWN" && got.Delivery == "UNKNOWN")
		} else {
			must(got.State == "UNKNOWN" && got.Delivery == "WITHHELD")
		}
		if mode == "withheld" || mode == "unknown" {
			verifyTargetState(got, *first.Precondition)
		}
		replay, err := callApply(ctx, peer, first.PlanID, firstRequest)
		must(err == nil && replay == got)
		if mode == "withheld" || mode == "unknown" {
			verifyTargetState(got, *first.Precondition)
		}
	} else if mode == "cancel" {
		_ = os.Remove("/var/lib/ssjack/synthetic/cancel-ack")
		defer os.Remove("/var/lib/ssjack/synthetic/cancel-ack")
		marker := "/var/lib/ssjack/synthetic/consumer-receipt"
		before, err := os.ReadFile(marker)
		if err != nil {
			must(os.IsNotExist(err))
			before = nil
		}
		callCtx, cancelCall := context.WithCancel(ctx)
		type applyReply struct {
			result declarativeslice.ApplyResult
			err    error
		}
		reply := make(chan applyReply, 1)
		go func() {
			result, err := callApply(callCtx, peer, first.PlanID, firstRequest)
			reply <- applyReply{result, err}
		}()
		deadline, stop := context.WithTimeout(ctx, 20*time.Second)
		defer stop()
		for {
			current, readErr := os.ReadFile(marker)
			must(readErr == nil || os.IsNotExist(readErr))
			if len(current) == len(before)+48 {
				break
			}
			select {
			case <-deadline.Done():
				os.Exit(1)
			case <-time.After(10 * time.Millisecond):
			}
		}
		cancelCall()
		select {
		case got := <-reply:
			must(got.err != nil && got.result.Delivery != "RECEIVED")
		case <-deadline.Done():
			os.Exit(1)
		}
		must(os.WriteFile("/var/lib/ssjack/synthetic/cancel-ack", []byte("release"), 0600) == nil)
		for {
			_, statErr := os.Stat("/var/lib/ssjack/synthetic/cancel-ack")
			if os.IsNotExist(statErr) {
				break
			}
			must(statErr == nil)
			select {
			case <-deadline.Done():
				os.Exit(1)
			case <-time.After(10 * time.Millisecond):
			}
		}
		_, err = broker.Describe(ctx, client)
		must(err != nil)
		fmt.Fprintln(os.Stdout, "DELIVERY_CANCELLED_OUTCOME_UNKNOWN")
	} else {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "DELIVERY_ACCEPTANCE_OK")
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		os.Exit(1)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func must(ok bool) {
	if !ok {
		os.Exit(1)
	}
}
func plan(ctx context.Context, peer *mcp.ClientSession, ref, id string) declarativeslice.PlanResult {
	r, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: map[string]any{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": ref}, "request_id": id}})
	must(err == nil && r != nil && !r.IsError)
	var out declarativeslice.PlanResult
	must(decode(r, &out) == nil && out.PlanID != "")
	return out
}
func callApply(ctx context.Context, peer *mcp.ClientSession, planID, id string) (declarativeslice.ApplyResult, error) {
	if id == "" {
		id = randomID()
	}
	r, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: map[string]any{"plan_id": planID, "request_id": id}})
	if err != nil || r == nil || r.IsError {
		return declarativeslice.ApplyResult{}, fmt.Errorf("apply unavailable")
	}
	var out declarativeslice.ApplyResult
	if decode(r, &out) != nil {
		return out, fmt.Errorf("invalid result")
	}
	return out, nil
}
func decode(r *mcp.CallToolResult, v any) error {
	for _, c := range r.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			return json.Unmarshal([]byte(text.Text), v)
		}
	}
	if r.StructuredContent == nil {
		return fmt.Errorf("empty result")
	}
	b, err := json.Marshal(r.StructuredContent)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
