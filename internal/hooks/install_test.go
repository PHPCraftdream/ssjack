package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallPreservesSettingsAndOtherHooks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".claude")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.local.json")
	original := []byte(`{
  "enabledMcpjsonServers": ["ssjack"],
  "permissions": {"deny": ["Bash(rm *)"]},
  "hooks": {
    "Stop": [{"hooks": [{"type": "command", "command": "other-stop-hook"}]}],
    "PreToolUse": [{"matcher": "^mcp__ssjack__remote_exec$", "custom": true, "hooks": [{"type": "command", "command": "other-hook"}]}]
  }
}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "bin with spaces", "ssjack.exe")
	if err := Install(root, executable); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(first, &got); err != nil {
		t.Fatal(err)
	}
	if got["permissions"] == nil || got["enabledMcpjsonServers"] == nil {
		t.Fatal("unrelated settings were removed")
	}
	events := got["hooks"].(map[string]any)
	if len(events["Stop"].([]any)) != 1 {
		t.Fatal("Stop hooks were changed")
	}
	group := events["PreToolUse"].([]any)[0].(map[string]any)
	if group["custom"] != true {
		t.Fatal("group metadata was lost")
	}
	entries := group["hooks"].([]any)
	if len(entries) != 2 || entries[0].(map[string]any)["command"] != "other-hook" {
		t.Fatal("existing hook was replaced")
	}
	own := entries[1].(map[string]any)
	if own["command"] != executable || own["args"].([]any)[0] != "hook" {
		t.Fatal("hook must use executable and arguments separately")
	}
	if err := Install(root, executable); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("installation was not idempotent")
	}
}

func TestInstallCreatesSettingsAndRejectsInvalidInput(t *testing.T) {
	root := t.TempDir()
	if err := Install(root, filepath.Join(root, "ssjack")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".claude", "settings.local.json")
	for _, original := range [][]byte{[]byte("{"), []byte("null"), []byte(""), []byte(`{"hooks":{"PreToolUse":null}}`)} {
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := Install(root, filepath.Join(root, "ssjack")); err == nil {
			t.Fatal("invalid settings were accepted")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("invalid existing settings were overwritten")
		}
	}
}
