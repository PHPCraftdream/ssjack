package uiplugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallIsLocalIdempotentAndDetectsEdits(t *testing.T) {
	root := t.TempDir()
	dir, err := Install(root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, filepath.Join(root, ".claude", "ssjack-ui")+string(os.PathSeparator)) {
		t.Fatal("plugin was installed outside the project")
	}
	for _, name := range assetNames {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	metadata := filepath.Join(dir, ".claude-plugin", "types")
	if err := os.Mkdir(metadata, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadata, "generated.d.ts"), []byte("// engine-generated metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := Install(root)
	if err != nil || again != dir {
		t.Fatalf("installation was not idempotent: %s %v", again, err)
	}
	path := filepath.Join(dir, "hooks", "format.ts")
	if err := os.WriteFile(path, []byte("user changes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(root); err == nil {
		t.Fatal("modified runtime assets were silently overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "user changes" {
		t.Fatal("modified assets were not preserved")
	}
}

func TestEnvironmentPreservesOtherPluginsAndParent(t *testing.T) {
	sep := string(os.PathListSeparator)
	base := []string{"KEEP=value", EnvDirectories + "=first" + sep + "second"}
	out := Environment(base, "third")
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "KEEP=value") || !strings.Contains(joined, EnvDirectories+"=first"+sep+"second"+sep+"third") {
		t.Fatal("existing plugin paths were lost")
	}
	if base[1] != EnvDirectories+"=first"+sep+"second" {
		t.Fatal("parent environment slice was changed")
	}
	again := Environment(out, "third")
	if strings.Join(again, "\n") != joined {
		t.Fatal("plugin environment was not idempotent")
	}
}
