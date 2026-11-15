//go:build linux

package transferacceptance

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callTool invokes one bridge tool and fails on a transport error.
func callTool(t *testing.T, s *stack, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	deadline, cancel := context.WithTimeout(s.ctx, waitBudget)
	defer cancel()
	result, err := s.session.CallTool(deadline, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s call failed: %v", name, err)
	}
	if result == nil {
		t.Fatalf("%s returned no result", name)
	}
	return result
}

// captured is the running list of encoded tool results a scenario checks
// for secrecy at the end.
type captured [][]byte

func (c *captured) add(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("tool result encoding: %v", err)
	}
	*c = append(*c, data)
}

// startUpload starts an upload job and returns its job id.
func startUpload(t *testing.T, s *stack, c *captured, args map[string]any) string {
	t.Helper()
	result := callTool(t, s, "remote_upload", args)
	c.add(t, result)
	return jobID(t, result)
}

// startDownload starts a download job and returns its job id.
func startDownload(t *testing.T, s *stack, c *captured, args map[string]any) string {
	t.Helper()
	result := callTool(t, s, "remote_download", args)
	c.add(t, result)
	return jobID(t, result)
}

func jobID(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result.IsError {
		t.Fatalf("start call was refused: %s", resultText(result))
	}
	var out struct {
		JobID string `json:"job_id"`
	}
	structured(t, result, &out)
	if out.JobID == "" {
		t.Fatal("start call returned an empty job id")
	}
	return out.JobID
}

// waitStatus polls transfer_status until the job leaves the running state.
func waitStatus(t *testing.T, s *stack, c *captured, job string) statusOutput {
	t.Helper()
	deadline := time.Now().Add(waitBudget)
	for {
		result := callTool(t, s, "transfer_status", map[string]any{"job_id": job})
		c.add(t, result)
		var out statusOutput
		structured(t, result, &out)
		if out.State != "running" {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s never left the running state: %+v", job, out)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// structured decodes the structured content of a tool result.
func structured(t *testing.T, result *mcp.CallToolResult, out any) {
	t.Helper()
	if result.StructuredContent == nil {
		t.Fatal("tool result omitted structured output")
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("structured result encoding: %v", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("structured result did not decode: %v", err)
	}
}

// refusal asserts a refused tool call and returns its fixed text.
func refusal(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if !result.IsError {
		t.Fatal("expected a refused tool call")
	}
	return resultText(result)
}

func resultText(result *mcp.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			return text.Text
		}
	}
	return ""
}

// statusOutput mirrors the transfer_status record.
type statusOutput struct {
	JobID          string `json:"job_id"`
	State          string `json:"state"`
	Direction      string `json:"direction"`
	Kind           string `json:"kind"`
	Files          int    `json:"files"`
	Dirs           int    `json:"dirs"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ErrorClass     string `json:"error_class"`
	Message        string `json:"message"`
}
