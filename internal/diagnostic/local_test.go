package diagnostic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectIsReadOnlyAndValidatesMCP(t *testing.T) {
	root := t.TempDir()
	vault := filepath.Join(root, "vault")
	executable := filepath.Join(root, "ssjack")
	for _, path := range []string{vault, executable} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	registration := filepath.Join(root, ".mcp.json")
	valid := []byte(`{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"]}}}`)
	if err := os.WriteFile(registration, valid, 0600); err != nil {
		t.Fatal(err)
	}
	paths := Paths{Root: root, Vault: vault, Executable: executable, PathExecutable: executable}
	before, _ := os.ReadDir(root)
	findings := Inspect(paths)
	if err := Failed(findings); err != nil {
		t.Fatalf("valid local configuration: %v: %+v", err, findings)
	}
	after, _ := os.ReadDir(root)
	if len(before) != len(after) {
		t.Fatal("doctor installed or created files")
	}
	for _, bad := range []string{
		`{"mcpServers":{"ssjack":{"type":"stdio","command":"other","args":["mcp"]}}}`,
		`{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"],"env":{"SSJACK_ENV_TOKEN":"test-only"}}}}`,
		`invalid`,
	} {
		if err := os.WriteFile(registration, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Failed(Inspect(paths)); err == nil {
			t.Fatal("invalid MCP configuration was accepted")
		}
	}
}

func TestMissingVaultIsFailureWithoutCreatingIt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "absent")
	if err := Failed(Inspect(Paths{Root: root, Vault: path})); err == nil {
		t.Fatal("missing vault was accepted")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("readiness inspection changed an empty project")
	}
}
