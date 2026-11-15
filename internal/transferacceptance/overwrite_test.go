//go:build linux

package transferacceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// scenarioSecrets plants secret-like content and asserts no status, tool
// result or error text ever carries it or an absolute local path.
func scenarioSecrets(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	secret := []byte("SYNTHETIC-SECRET-never-return-9f2c1e7b4a6d")
	source := append(secret, SeedPayload(64*1024, 3)...)
	WriteTree(t, s.rootDir, map[string][]byte{"vault.txt": source}, nil)
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "vault.txt", "remote": s.sandbox + "/in/vault.txt",
	}))
	if out.State != "done" {
		t.Fatalf("upload status = %+v", out)
	}
	bad := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/vault.txt", "local": "missing-parent/dest.txt",
	}))
	if bad.State != "failed" || bad.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("refused download status = %+v", bad)
	}
	assertNoLeaks(t, c, secret)
	for _, data := range c {
		if bytes.Contains(data, []byte(s.rootDir)) || bytes.Contains(data, []byte(s.sandbox)) {
			t.Fatalf("status disclosed an absolute local path: %s", data)
		}
	}
}

// scenarioOverwrite replaces an existing remote file, an existing remote
// directory and an existing local file only when requested and confirmed.
func scenarioOverwrite(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	old := SeedPayload(96*1024, 5)
	next := SeedPayload(48*1024, 6)
	WriteTree(t, s.rootDir, map[string][]byte{
		"new/blob.bin":       next,
		"new/tree/inner.txt": []byte("replacement"),
	}, []string{"new", "new/tree"})
	WriteTree(t, s.sandbox, map[string][]byte{
		"dest/blob.bin":           old,
		"dest/old-tree/stale.txt": []byte("stale"),
	}, []string{"dest", "dest/old-tree"})
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "new/blob.bin", "remote": s.sandbox + "/dest/blob.bin",
		"overwrite": true, "confirm": true,
	}))
	if out.State != "done" || out.Kind != "file" {
		t.Fatalf("file overwrite status = %+v", out)
	}
	stored, err := os.ReadFile(s.sandbox + "/dest/blob.bin")
	if err != nil || !bytes.Equal(stored, next) {
		t.Fatal("overwrite did not replace the remote file")
	}
	tree := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "new/tree", "remote": s.sandbox + "/dest/old-tree",
		"overwrite": true, "confirm": true,
	}))
	if tree.State != "done" || tree.Kind != "directory" {
		t.Fatalf("directory overwrite status = %+v", tree)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "new/tree"), s.sandbox+"/dest/old-tree")
	local := filepath.Join(s.rootDir, "existing.bin")
	if err := os.WriteFile(local, old, 0o600); err != nil {
		t.Fatal(err)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/dest/blob.bin", "local": "existing.bin",
		"overwrite": true, "confirm": true,
	}))
	if down.State != "done" || down.Kind != "file" {
		t.Fatalf("local overwrite status = %+v", down)
	}
	stored, err = os.ReadFile(local)
	if err != nil || !bytes.Equal(stored, next) {
		t.Fatal("download overwrite did not replace the local file")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioOverwriteFailure refuses an overwrite whose destination has the
// wrong type and requires the old destination to stay intact.
func scenarioOverwriteFailure(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{"src/file.bin": SeedPayload(32*1024, 8)}, []string{"src"})
	WriteTree(t, s.sandbox, map[string][]byte{"guard/keep.txt": []byte("precious")}, []string{"guard"})
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "src/file.bin", "remote": s.sandbox + "/guard",
		"overwrite": true, "confirm": true,
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("overwrite onto a directory status = %+v", out)
	}
	stored, err := os.ReadFile(filepath.Join(s.sandbox, "guard", "keep.txt"))
	if err != nil || !bytes.Equal(stored, []byte("precious")) {
		t.Fatal("failed overwrite damaged the old destination")
	}
	WriteTree(t, s.rootDir, map[string][]byte{"local-guard/keep.txt": []byte("precious")}, []string{"local-guard"})
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/guard/keep.txt", "local": "local-guard",
		"overwrite": true, "confirm": true,
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("download overwrite onto a directory status = %+v", down)
	}
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "local-guard", "keep.txt"))
	if err != nil || !bytes.Equal(stored, []byte("precious")) {
		t.Fatal("failed download overwrite damaged the old destination")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}
