package main

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"os"
	"path/filepath"
	"time"
)

const concurrentDir = "/var/lib/ssjack/synthetic/concurrent"

// runConcurrentMode is activated only by fixture mode names; synchronization files contain metadata only.
func runConcurrentMode(ctx context.Context, peer *mcp.ClientSession, ref, mode string) bool {
	if mode != "race-secret" && mode != "race-metadata" {
		return false
	}
	side := "secret"
	if mode == "race-metadata" {
		side = "metadata"
	}
	fail := func() { os.Exit(1) }
	request := randomID()
	p := plan(ctx, peer, ref, request)
	if p.PlanID == "" || p.Precondition == nil {
		fail()
	}
	revision := ""
	if p.Precondition != nil {
		revision = *p.Precondition
	}
	boundedWrite(filepath.Join(concurrentDir, side+".planned"), map[string]string{"plan_id": p.PlanID, "revision": revision})
	waitPath(ctx, side+".apply")
	boundedWrite(filepath.Join(concurrentDir, side+".calling"), map[string]bool{"calling": true})
	got, err := callApply(ctx, peer, p.PlanID, request)
	if err != nil || (got.State != "SUCCEEDED" && got.State != "FAILED" && got.State != "UNKNOWN") {
		fail()
	}
	if mode == "race-secret" && got.Delivery == "" {
		fail()
	}
	boundedWrite(filepath.Join(concurrentDir, side+".result"), struct {
		State       string `json:"state"`
		Delivery    string `json:"delivery"`
		OperationID string `json:"operation_id"`
	}{got.State, got.Delivery, got.OperationID})
	return true
}
func boundedWrite(path string, value any) {
	b, err := json.Marshal(value)
	if err != nil || len(b) > 1024 {
		os.Exit(1)
	}
	if os.WriteFile(path, b, 0600) != nil {
		os.Exit(1)
	}
}
func waitPath(ctx context.Context, name string) {
	deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		if info, err := os.Stat(filepath.Join(concurrentDir, name)); err == nil && info.Mode().IsRegular() {
			return
		}
		select {
		case <-deadline.Done():
			os.Exit(1)
		case <-time.After(10 * time.Millisecond):
		}
	}
}
