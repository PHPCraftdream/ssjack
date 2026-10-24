package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveDisplayPreservesUnrelatedHooksAndSettings(t *testing.T) {
	root := t.TempDir()
	if err := Install(root, filepath.Join(root, "ssjack-next.exe")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".claude", "settings.local.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings["enabledMcpjsonServers"] = []string{"ssjack"}
	events := settings["hooks"].(map[string]any)
	events["Stop"] = []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "clock"}}}}
	group := events["PreToolUse"].([]any)[0].(map[string]any)
	group["custom"] = "preserve"
	group["hooks"] = append(group["hooks"].([]any), map[string]any{"type": "command", "command": "other-program", "args": []string{"hook", "pre"}})
	data, err = json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDisplay(root); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(first, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["enabledMcpjsonServers"] == nil {
		t.Fatal("MCP approvals were removed")
	}
	events = settings["hooks"].(map[string]any)
	if events["Stop"] == nil {
		t.Fatal("unrelated Stop hooks were removed")
	}
	if events["PostToolUse"] != nil || events["PostToolUseFailure"] != nil {
		t.Fatal("obsolete ssjack display hooks remain")
	}
	group = events["PreToolUse"].([]any)[0].(map[string]any)
	remaining := group["hooks"].([]any)
	if len(remaining) != 1 || remaining[0].(map[string]any)["command"] != "other-program" || group["custom"] != "preserve" {
		t.Fatal("unrelated hook metadata was changed")
	}
	if err := RemoveDisplay(root); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("cleanup was not idempotent")
	}
}

func TestRemoveDisplayDoesNotCreateMissingSettings(t *testing.T) {
	root := t.TempDir()
	if err := RemoveDisplay(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".claude")); !os.IsNotExist(err) {
		t.Fatal("cleanup created settings")
	}
}
