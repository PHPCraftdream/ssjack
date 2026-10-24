package hooks

import (
	"encoding/json"
	"strings"
	"testing"
)

func display(t *testing.T, action string, event any) string {
	t.Helper()
	input, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Run(action, input)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	if _, ok := output["hookSpecificOutput"]; ok {
		t.Fatal("display hook must not alter permissions or tool inputs")
	}
	text, _ := output["systemMessage"].(string)
	return text
}

func TestPreShowsTargetAndExactCommand(t *testing.T) {
	command := "printf '%s\\n' 'hello world'\nid"
	text := display(t, "pre", map[string]any{
		"tool_name":  "mcp__ssjack__remote_exec",
		"tool_input": map[string]any{"target": "storagehost", "command": command},
		"env":        map[string]any{"SSJACK_ENV_TOKEN": "must-not-be-printed"},
	})
	if !strings.Contains(text, "storagehost") || !strings.Contains(text, command) || strings.Contains(text, "must-not-be-printed") {
		t.Fatalf("unexpected command display: %q", text)
	}
}

func TestPostSupportsMCPResultShapes(t *testing.T) {
	result := map[string]any{"job_id": "job-1", "stdout": "hello\n", "stderr": "warning\n", "done": true, "exit_code": 7, "stdout_more": true}
	encoded, _ := json.Marshal(result)
	for _, response := range []any{
		result,
		map[string]any{"structuredContent": result},
		map[string]any{"content": []any{map[string]any{"type": "text", "text": string(encoded)}}},
	} {
		text := display(t, "post", map[string]any{"tool_name": "mcp__ssjack__remote_read", "tool_response": response})
		for _, want := range []string{"job-1", "stdout:\nhello", "stderr:\nwarning", "done=true", "exit=7", "More output"} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing %q in %q", want, text)
			}
		}
	}
}

func TestPostShowsErrorsWithoutClaimingSuccess(t *testing.T) {
	text := display(t, "post", map[string]any{
		"tool_name":     "mcp__ssjack__remote_exec",
		"tool_response": map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "target is not allowed"}}},
	})
	if !strings.Contains(text, "failed") || !strings.Contains(text, "target is not allowed") || strings.Contains(text, "started job") {
		t.Fatal(text)
	}
	failure := display(t, "failure", map[string]any{"tool_name": "mcp__ssjack__remote_exec", "error": "connection closed"})
	if !strings.Contains(failure, "connection closed") {
		t.Fatal(failure)
	}
}

func TestHookBoundsAndControlEscaping(t *testing.T) {
	text := display(t, "pre", map[string]any{"tool_name": "mcp__ssjack__remote_exec", "tool_input": map[string]any{"target": "test", "command": "printf '\u001b[2J'\r\u202e"}})
	if strings.ContainsRune(text, '\u001b') || strings.ContainsRune(text, '\r') || strings.ContainsRune(text, '\u202e') {
		t.Fatal("terminal control characters were not escaped")
	}
	text = display(t, "pre", map[string]any{"tool_name": "mcp__ssjack__remote_exec", "tool_input": map[string]any{"target": "test", "command": strings.Repeat("x", 20000)}})
	if !strings.Contains(text, "truncated") || len(text) > 7500 {
		t.Fatal("message was not bounded")
	}
	if _, err := Run("pre", []byte("{")); err == nil {
		t.Fatal("invalid event accepted")
	}
	if _, err := Run("pre", make([]byte, MaxInput+1)); err == nil {
		t.Fatal("oversized event accepted")
	}
	if _, err := Run("invalid", []byte("{}")); err == nil {
		t.Fatal("invalid hook action accepted")
	}
}

func TestUnrelatedCallsAreIgnored(t *testing.T) {
	for _, action := range []string{"pre", "post", "failure"} {
		if text := display(t, action, map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "id"}}); text != "" {
			t.Fatal("unrelated tool was displayed")
		}
	}
}
