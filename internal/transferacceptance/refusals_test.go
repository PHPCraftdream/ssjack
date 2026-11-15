//go:build linux

package transferacceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// scenarioRefuseTraversal refuses a root-relative traversal on the local and
// the remote side before anything is mutated.
func scenarioRefuseTraversal(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{"inside.txt": []byte("kept")}, nil)
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "../escape.txt", "remote": s.sandbox + "/in/ok.txt",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("traversal upload status = %+v", out)
	}
	if _, err := os.Stat(filepath.Join(s.rootDir, "..", "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal upload escaped the root")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/../outside.txt", "local": "ok.txt",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("traversal remote path status = %+v", down)
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRefuseAbsoluteAndDrive refuses absolute, drive-letter and relative
// remote paths.
func scenarioRefuseAbsoluteAndDrive(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	cases := []struct {
		name string
		args map[string]any
	}{
		{"absolute local", map[string]any{"target": targetName, "local": "/etc/passwd", "remote": s.sandbox + "/in/x.txt"}},
		{"drive local", map[string]any{"target": targetName, "local": "C:/temp/payload.bin", "remote": s.sandbox + "/in/x.txt"}},
	}
	for _, testCase := range cases {
		out := waitStatus(t, s, &c, startUpload(t, s, &c, testCase.args))
		if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRefusedPath) {
			t.Fatalf("%s upload status = %+v", testCase.name, out)
		}
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": "relative/path.txt", "local": "ok.txt",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("relative remote path status = %+v", down)
	}
	AssertNoStaging(t, s.rootDir)
}

// scenarioRefuseSymlinkSource refuses a symlink inside a source tree and a
// symlink as the uploaded source file.
func scenarioRefuseSymlinkSource(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	mkdirAll(t, filepath.Join(s.rootDir, "tree"))
	if err := os.WriteFile(filepath.Join(s.rootDir, "tree", "keep.txt"), []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(s.rootDir, "tree", "keep.txt"), filepath.Join(s.rootDir, "tree", "link.txt")); err != nil {
		t.Fatal(err)
	}
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "tree", "remote": s.sandbox + "/in/tree",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("symlinked source tree status = %+v", out)
	}
	if _, err := os.Lstat(filepath.Join(s.rootDir, "tree", "link.txt")); err != nil {
		t.Fatal("refusal removed or rewrote the source symlink")
	}
	file := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "tree/link.txt", "remote": s.sandbox + "/in/link.txt",
	}))
	if file.State != "failed" || file.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("symlink source file status = %+v", file)
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRefuseSymlinkDestination refuses a symlink as the remote and as
// the local destination and leaves both symlinks untouched.
func scenarioRefuseSymlinkDestination(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{"blob.bin": SeedPayload(16*1024, 9)}, nil)
	WriteTree(t, s.sandbox, map[string][]byte{"real.txt": []byte("target of link")}, nil)
	if err := os.Symlink(filepath.Join(s.sandbox, "real.txt"), filepath.Join(s.sandbox, "alias.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nowhere.txt", filepath.Join(s.rootDir, "local-alias.txt")); err != nil {
		t.Fatal(err)
	}
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "blob.bin", "remote": s.sandbox + "/alias.txt",
		"overwrite": true, "confirm": true,
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("remote symlink destination status = %+v", out)
	}
	if link, err := os.Readlink(filepath.Join(s.sandbox, "alias.txt")); err != nil || filepath.Base(link) != "real.txt" {
		t.Fatalf("remote symlink changed: %q %v", link, err)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/real.txt", "local": "local-alias.txt",
		"overwrite": true, "confirm": true,
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("local symlink destination status = %+v", down)
	}
	if _, err := os.Readlink(filepath.Join(s.rootDir, "local-alias.txt")); err != nil {
		t.Fatal("local symlink was replaced")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRefuseForbiddenDestination refuses a forbidden control directory
// as download destination and as an extracted entry.
func scenarioRefuseForbiddenDestination(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.sandbox, map[string][]byte{
		"keep.txt":         []byte("repo"),
		"repo/.git/config": []byte("gitdir"),
	}, []string{"repo", "repo/.git"})
	out := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/keep.txt", "local": ".git/config",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("forbidden destination status = %+v", out)
	}
	if _, err := os.Stat(filepath.Join(s.rootDir, ".git")); !os.IsNotExist(err) {
		t.Fatal("forbidden destination directory was created")
	}
	tree := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/repo", "local": "repo",
	}))
	if tree.State != "failed" || tree.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatalf("forbidden extracted entry status = %+v", tree)
	}
	if _, err := os.Stat(filepath.Join(s.rootDir, "repo")); !os.IsNotExist(err) {
		t.Fatal("tree with a forbidden entry was published")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRefuseDestinationExists refuses an existing destination without
// overwrite in both directions and leaves the old content intact.
func scenarioRefuseDestinationExists(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{
		"new/blob.bin": SeedPayload(16*1024, 5),
		"have.txt":     []byte("old local"),
	}, []string{"new"})
	WriteTree(t, s.sandbox, map[string][]byte{"in/exists.bin": []byte("old remote")}, []string{"in"})
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "new/blob.bin", "remote": s.sandbox + "/in/exists.bin",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassExists) {
		t.Fatalf("existing remote destination status = %+v", out)
	}
	stored, err := os.ReadFile(filepath.Join(s.sandbox, "in", "exists.bin"))
	if err != nil || !bytes.Equal(stored, []byte("old remote")) {
		t.Fatal("refused upload changed the existing destination")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/exists.bin", "local": "have.txt",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassExists) {
		t.Fatalf("existing local destination status = %+v", down)
	}
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "have.txt"))
	if err != nil || !bytes.Equal(stored, []byte("old local")) {
		t.Fatal("refused download changed the existing destination")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}
