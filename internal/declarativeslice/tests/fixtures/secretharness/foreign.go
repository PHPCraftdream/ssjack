package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const foreignSessionPath = "/var/lib/ssjack/synthetic/foreign-session.json"

type foreignSessionMetadata struct {
	PlanID      string `json:"plan_id"`
	RequestID   string `json:"request_id"`
	OperationID string `json:"operation_id"`
}

// runForeignMode runs cross-session acceptance using only the current authenticated session.
func runForeignMode(ctx context.Context, peer *mcp.ClientSession, ref, mode string) bool {
	if mode != "export-session" && mode != "foreign-session" {
		return false
	}
	fail := func() { fmt.Fprintln(os.Stderr, "foreign-session acceptance failed"); os.Exit(1) }
	plan := func(request string) declarativeslice.PlanResult {
		r, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "resource_plan", Arguments: map[string]any{"target": "target", "driver_id": "synthetic", "kind": "cache", "schema_id": "cache.desired", "resource_id": "synthetic", "desired": map[string]any{"enabled": true, "ref": ref}, "request_id": request}})
		if err != nil || r == nil || r.IsError {
			fail()
		}
		var out declarativeslice.PlanResult
		if decode(r, &out) != nil || out.PlanID == "" {
			fail()
		}
		return out
	}
	apply := func(id, request string, extra bool) (declarativeslice.ApplyResult, error) {
		args := map[string]any{"plan_id": id, "request_id": request}
		if extra {
			args["operation_id"] = foreignMetadata().OperationID
		}
		r, err := peer.CallTool(ctx, &mcp.CallToolParams{Name: "plan_apply", Arguments: args})
		if err != nil || r == nil || r.IsError {
			return declarativeslice.ApplyResult{}, errors.New("rejected")
		}
		var out declarativeslice.ApplyResult
		if decode(r, &out) != nil {
			return out, errors.New("invalid apply result")
		}
		return out, nil
	}
	if mode == "export-session" {
		request := randomID()
		p := plan(request)
		got, err := apply(p.PlanID, request, false)
		if err != nil || got.State != "SUCCEEDED" || got.Delivery != "RECEIVED" || got.OperationID == "" {
			fail()
		}
		b, err := json.Marshal(foreignSessionMetadata{p.PlanID, request, got.OperationID})
		if err != nil {
			fail()
		}
		if err = os.WriteFile(foreignSessionPath, b, 0600); err != nil {
			fail()
		}
		if err = os.Chmod(foreignSessionPath, 0600); err != nil {
			fail()
		}
		fmt.Println("FOREIGN_SESSION_EXPORTED")
		return true
	}
	m := foreignMetadata()
	if m.PlanID == "" || m.RequestID == "" || m.OperationID == "" {
		fail()
	}
	ownRequest := randomID()
	own := plan(ownRequest)
	if _, err := apply(m.PlanID, m.RequestID, false); err == nil {
		fail()
	}
	if _, err := apply(m.OperationID, randomID(), false); err == nil {
		fail()
	}
	if _, err := apply(own.PlanID, randomID(), true); err == nil {
		fail()
	}
	got, err := apply(own.PlanID, ownRequest, false)
	if err != nil || got.State != "SUCCEEDED" || got.Delivery != "RECEIVED" {
		fail()
	}
	replay, err := apply(own.PlanID, ownRequest, false)
	if err != nil || replay != got {
		fail()
	}
	fmt.Println("FOREIGN_SESSION_ACCEPTED")
	return true
}

func foreignMetadata() foreignSessionMetadata {
	b, err := os.ReadFile(foreignSessionPath)
	if err != nil {
		return foreignSessionMetadata{}
	}
	var m foreignSessionMetadata
	if json.Unmarshal(b, &m) != nil {
		return foreignSessionMetadata{}
	}
	return m
}
