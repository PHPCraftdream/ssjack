package uiplugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDoesNotInstallAndDetectsModifiedAssets(t *testing.T) {
	root := t.TempDir()
	if err := Check(root); !os.IsNotExist(err) {
		t.Fatalf("missing UI: %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("check installed files")
	}
	installed, err := Install(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, "hooks", "format.ts"), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Check(root); err == nil {
		t.Fatal("modified managed assets were accepted")
	}
}
