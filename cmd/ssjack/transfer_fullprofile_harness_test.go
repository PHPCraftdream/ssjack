//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// transferHarnessScenario drives the four transfer tools through the real
// stdio bridge: a file upload round trip, a directory download round trip,
// a traversal refusal and an unregistered-root refusal. Every tool result
// is captured and checked for content leaks at the end.
func transferHarnessScenario(t *testing.T, ctx context.Context, session *mcp.ClientSession, root, sandbox string) {
	t.Helper()
	var results [][]byte
	target := transferHarnessTarget(t, ctx, session, &results)
	status := transferHarnessRun(t, ctx, session, &results, "remote_upload", map[string]any{
		"target": target, "local": "in/notes.txt", "remote": sandbox + "/in/notes.txt",
	})
	if status.State != "done" || status.Direction != "upload" || status.Kind != "file" || status.Bytes != transferFileSize(t, root, "in/notes.txt") {
		t.Fatalf("upload status = %+v", status)
	}
	transferHarnessFinished(t, ctx, session, &results, status.JobID)
	fmt.Fprintln(os.Stderr, transferObserved+"upload")
	status = transferHarnessRun(t, ctx, session, &results, "remote_download", map[string]any{
		"target": target, "remote": sandbox + "/tree", "local": "returned",
	})
	if status.State != "done" || status.Direction != "download" || status.Kind != "directory" || status.ManifestSHA256 == "" {
		t.Fatalf("download status = %+v", status)
	}
	fmt.Fprintln(os.Stderr, transferObserved+"download")
	status = transferHarnessRun(t, ctx, session, &results, "remote_upload", map[string]any{
		"target": target, "local": "../escape.txt", "remote": sandbox + "/in/escape.txt",
	})
	if status.State != "failed" || status.ErrorClass != "refused_path" {
		t.Fatalf("traversal upload status = %+v", status)
	}
	if _, err := os.Stat(filepath.Join(root, "..", "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("traversing upload escaped the root")
	}
	if _, err := os.Stat(sandbox + "/in/escape.txt"); !os.IsNotExist(err) {
		t.Fatal("traversing upload published a destination")
	}
	fmt.Fprintln(os.Stderr, transferObserved+"refused-path")
	denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_download", Arguments: map[string]any{
		"target": target, "remote": sandbox + "/tree", "local": "denied", "root": "no-such-root",
	}})
	if err != nil || denied == nil || !denied.IsError {
		t.Fatal("unregistered root was not refused at start time")
	}
	results = append(results, transferHarnessEncoded(t, denied))
	if text := transferHarnessText(denied); text != "transfer root was not registered" {
		t.Fatalf("unregistered root refusal = %q", text)
	}
	fmt.Fprintln(os.Stderr, transferObserved+"unregistered-root")
	for _, encoded := range results {
		if bytes.Contains(encoded, []byte(transferSecret)) {
			t.Fatal("a tool result disclosed file content")
		}
	}
}

// transferHarnessTarget lists the approved targets and requires exactly one.
func transferHarnessTarget(t *testing.T, ctx context.Context, session *mcp.ClientSession, results *[][]byte) string {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_targets", Arguments: map[string]any{}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("remote_targets failed: %v", err)
	}
	*results = append(*results, transferHarnessEncoded(t, result))
	var out remote.TargetsOutput
	transferHarnessStructured(t, result, &out)
	if len(out.Targets) != 1 || out.Targets[0] == "" {
		t.Fatalf("expected exactly one approved target, got %+v", out.Targets)
	}
	return out.Targets[0]
}

// transferHarnessRun starts a job and polls transfer_status to completion.
func transferHarnessRun(t *testing.T, ctx context.Context, session *mcp.ClientSession, results *[][]byte, tool string, args map[string]any) transferStatus {
	t.Helper()
	started, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil || started == nil || started.IsError {
		t.Fatalf("%s was refused: %v", tool, err)
	}
	*results = append(*results, transferHarnessEncoded(t, started))
	var job transfer.StartOutput
	transferHarnessStructured(t, started, &job)
	if job.JobID == "" {
		t.Fatalf("%s returned no job id", tool)
	}
	budget := 2 * time.Minute
	var lastStatus transferStatus
	statusDone, _, statusErr := flakediag.WaitForDesc(t, "transfer job "+job.JobID+" completion", budget, func() (string, bool, error) {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "transfer_status", Arguments: map[string]any{"job_id": job.JobID}})
		if err != nil || result == nil {
			return "transfer_status call failed", false, err
		}
		*results = append(*results, transferHarnessEncoded(t, result))
		var status transferStatus
		transferHarnessStructured(t, result, &status)
		lastStatus = status
		if status.State != "running" {
			return "", true, nil
		}
		return "state=running", false, nil
	})
	if statusErr != nil {
		t.Fatalf("transfer_status failed: %v", statusErr)
	}
	if !statusDone {
		t.Fatalf("job %s never finished: %+v", job.JobID, lastStatus)
	}
	return lastStatus
}

// transferHarnessFinished cancels a finished job and requires cancelled=false.
func transferHarnessFinished(t *testing.T, ctx context.Context, session *mcp.ClientSession, results *[][]byte, job string) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "transfer_cancel", Arguments: map[string]any{"job_id": job}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("transfer_cancel failed: %v", err)
	}
	*results = append(*results, transferHarnessEncoded(t, result))
	var out transfer.CancelOutput
	transferHarnessStructured(t, result, &out)
	if out.Cancelled {
		t.Fatal("cancelling a finished job claimed success")
	}
}

type transferStatus = transfer.StatusOutput

func transferHarnessEncoded(t *testing.T, result *mcp.CallToolResult) []byte {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("tool result encoding: %v", err)
	}
	return data
}

// transferHarnessStructured reads the plain-text result of a bridge tool.
func transferHarnessStructured(t *testing.T, result *mcp.CallToolResult, out any) {
	t.Helper()
	text, err := bridge.ResultText(result)
	if err != nil {
		t.Fatalf("tool result is not the plain-text contract: %v", err)
	}
	if err := bridge.ParseResult(text, out); err != nil {
		t.Fatalf("tool result text did not parse: %v", err)
	}
}

func transferHarnessText(result *mcp.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			return text.Text
		}
	}
	return ""
}

func transferFileSize(t *testing.T, root, name string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
