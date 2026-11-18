//go:build linux || darwin

package transferacceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// scenarioRoundTripFile copies a binary file up and back and requires both
// sides byte-exact with content-free results.
func scenarioRoundTripFile(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	source := SeedPayload(1024*1024, 7)
	WriteTree(t, s.rootDir, map[string][]byte{"data/blob.bin": source}, []string{"data"})
	mkdirAll(t, filepath.Join(s.rootDir, "copy"))
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	remote := s.sandbox + "/in/blob.bin"
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "data/blob.bin", "remote": remote,
	}))
	if out.State != "done" || out.Direction != "upload" || out.Kind != "file" || out.Files != 1 || out.Dirs != 0 || out.Bytes != int64(len(source)) {
		t.Fatalf("upload status = %+v", out)
	}
	assertSHA(t, source, out.SHA256)
	AssertNoStaging(t, s.sandbox)
	stored, err := os.ReadFile(remote)
	if err != nil || !bytes.Equal(stored, source) {
		t.Fatalf("remote copy differs: %v", err)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": remote, "local": "copy/blob.bin",
	}))
	if down.State != "done" || down.Kind != "file" || down.Bytes != int64(len(source)) || down.SHA256 != out.SHA256 {
		t.Fatalf("download status = %+v", down)
	}
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "copy", "blob.bin"))
	if err != nil || !bytes.Equal(stored, source) {
		t.Fatalf("downloaded copy differs: %v", err)
	}
	AssertNoStaging(t, s.rootDir)
	assertNoLeaks(t, c, source)
}

func setTime(t *testing.T, path string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func assertTime(t *testing.T, path string, want time.Time) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.ModTime().Equal(want) {
		t.Fatalf("modification time of %s is %v, want %v (%v)", filepath.Base(path), info.ModTime(), want, err)
	}
}

// assertSameMode requires a published root to look like its subdirectories.
func assertSameMode(t *testing.T, root, sub string) {
	t.Helper()
	rootInfo, rootErr := os.Stat(root)
	subInfo, subErr := os.Stat(sub)
	if rootErr != nil || subErr != nil || rootInfo.Mode().Perm() != subInfo.Mode().Perm() {
		t.Fatalf("published root mode %v differs from its subdirectory mode %v (%v %v)", rootInfo.Mode().Perm(), subInfo.Mode().Perm(), rootErr, subErr)
	}
}

// scenarioRoundTripDirectory copies a nested tree up and back and requires
// equal trees, equal counts and an equal manifest digest.
func scenarioRoundTripDirectory(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	binary := SeedPayload(384*1024, 11)
	WriteTree(t, s.rootDir, map[string][]byte{
		"tree/README.md":     []byte("synthetic tree with regular files only"),
		"tree/data/blob.bin": binary,
		"tree/sub/inner.txt": []byte("nested"),
	}, []string{"tree/data", "tree/sub", "tree/sub/deeper"})
	fileTime := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	dirTime := time.Date(2019, 8, 9, 10, 11, 12, 0, time.UTC)
	setTime(t, filepath.Join(s.rootDir, "tree", "sub", "inner.txt"), fileTime)
	setTime(t, filepath.Join(s.rootDir, "tree", "sub"), dirTime)
	mkdirAll(t, filepath.Join(s.sandbox, "out"))
	remote := s.sandbox + "/out/tree"
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "tree", "remote": remote,
	}))
	if out.State != "done" || out.Kind != "directory" || out.Files != 3 || out.Dirs != 3 || out.SHA256 != "" || out.ManifestSHA256 == "" {
		t.Fatalf("upload status = %+v", out)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "tree"), remote)
	// Modification times survive the upload, and the published root has the
	// mode its subdirectories got from tar instead of the private staging mode.
	assertTime(t, filepath.Join(remote, "sub", "inner.txt"), fileTime)
	assertTime(t, filepath.Join(remote, "sub"), dirTime)
	assertSameMode(t, remote, filepath.Join(remote, "sub"))
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": remote, "local": "came-back",
	}))
	if down.State != "done" || down.Kind != "directory" || down.Files != 3 || down.Dirs != 3 || down.ManifestSHA256 != out.ManifestSHA256 {
		t.Fatalf("download status = %+v", down)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "tree"), filepath.Join(s.rootDir, "came-back"))
	assertTime(t, filepath.Join(s.rootDir, "came-back", "sub", "inner.txt"), fileTime)
	assertTime(t, filepath.Join(s.rootDir, "came-back", "sub"), dirTime)
	assertSameMode(t, filepath.Join(s.rootDir, "came-back"), filepath.Join(s.rootDir, "came-back", "sub"))
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
	assertNoLeaks(t, c, binary)
}

// scenarioRoundTripEmpty copies a zero-byte file and an empty directory in
// both directions and requires zero counts with the empty-file digest.
func scenarioRoundTripEmpty(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{"empty/zero.bin": {}}, []string{"empty", "hollow"})
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "empty/zero.bin", "remote": s.sandbox + "/in/zero.bin",
	}))
	if out.State != "done" || out.Kind != "file" || out.Files != 1 || out.Bytes != 0 {
		t.Fatalf("zero-byte upload status = %+v", out)
	}
	assertSHA(t, nil, out.SHA256)
	stored, err := os.ReadFile(s.sandbox + "/in/zero.bin")
	if err != nil || len(stored) != 0 {
		t.Fatalf("remote zero-byte copy: %v (%d bytes)", err, len(stored))
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/zero.bin", "local": "empty/again.bin",
	}))
	if down.State != "done" || down.Bytes != 0 {
		t.Fatalf("zero-byte download status = %+v", down)
	}
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "empty", "again.bin"))
	if err != nil || len(stored) != 0 {
		t.Fatalf("downloaded zero-byte copy: %v (%d bytes)", err, len(stored))
	}
	hollow := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "hollow", "remote": s.sandbox + "/in/hollow",
	}))
	if hollow.State != "done" || hollow.Kind != "directory" || hollow.Files != 0 || hollow.Dirs != 0 {
		t.Fatalf("empty directory upload status = %+v", hollow)
	}
	if info, err := os.Stat(s.sandbox + "/in/hollow"); err != nil || !info.IsDir() {
		t.Fatal("empty directory was not published remotely")
	}
	back := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/hollow", "local": "back-from-empty",
	}))
	if back.State != "done" || back.Kind != "directory" || back.Files != 0 || back.Dirs != 0 {
		t.Fatalf("empty directory download status = %+v", back)
	}
	if info, err := os.Stat(filepath.Join(s.rootDir, "back-from-empty")); err != nil || !info.IsDir() {
		t.Fatal("empty directory download was not published")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRoundTripNames copies trees whose names contain spaces and
// non-ASCII characters in both directions, byte-exactly.
func scenarioRoundTripNames(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	binary := SeedPayload(128*1024, 17)
	WriteTree(t, s.rootDir, map[string][]byte{
		"отчёт за год/данные 2.txt": []byte("кириллица и пробелы"),
		"report final/draft v2.bin": binary,
	}, []string{"отчёт за год", "report final"})
	mkdirAll(t, filepath.Join(s.sandbox, "remote names"))
	tree := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "report final", "remote": s.sandbox + "/remote names/дерево целиком",
	}))
	if tree.State != "done" || tree.Kind != "directory" || tree.Files != 1 || tree.Dirs != 0 {
		t.Fatalf("names upload status = %+v", tree)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "report final"), s.sandbox+"/remote names/дерево целиком")
	file := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "отчёт за год/данные 2.txt", "remote": s.sandbox + "/remote names/файл с именем.bin",
	}))
	if file.State != "done" || file.Kind != "file" {
		t.Fatalf("non-ASCII file upload status = %+v", file)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/remote names/дерево целиком", "local": "папка возврата",
	}))
	if down.State != "done" || down.Kind != "directory" {
		t.Fatalf("names download status = %+v", down)
	}
	CompareTrees(t, filepath.Join(s.rootDir, "report final"), filepath.Join(s.rootDir, "папка возврата"))
	back := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/remote names/файл с именем.bin", "local": "папка возврата/файл.txt",
	}))
	if back.State != "done" || back.Kind != "file" {
		t.Fatalf("non-ASCII file download status = %+v", back)
	}
	stored, err := os.ReadFile(filepath.Join(s.rootDir, "папка возврата", "файл.txt"))
	if err != nil || !bytes.Equal(stored, []byte("кириллица и пробелы")) {
		t.Fatalf("non-ASCII file round trip differs: %v", err)
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
	assertNoLeaks(t, c, binary)
}

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

// scenarioRefuseOverwriteWithoutConfirm refuses overwrite without
// confirm=true at the manager boundary, before any job exists.
func scenarioRefuseOverwriteWithoutConfirm(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	result := callTool(t, s, "remote_upload", map[string]any{
		"target": targetName, "local": "x.txt", "remote": s.sandbox + "/in/x.txt", "overwrite": true,
	})
	c.add(t, result)
	if text := refusal(t, result); text != "overwrite requires confirm=true" {
		t.Fatalf("upload refusal = %q", text)
	}
	denied := callTool(t, s, "remote_download", map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/x.txt", "local": "x.txt", "overwrite": true,
	})
	c.add(t, denied)
	if text := refusal(t, denied); text != "overwrite requires confirm=true" {
		t.Fatalf("download refusal = %q", text)
	}
}

// scenarioRefuseUnknownRoot refuses an unregistered root name in both
// directions at start time.
func scenarioRefuseUnknownRoot(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	for _, tool := range []string{"remote_upload", "remote_download"} {
		result := callTool(t, s, tool, map[string]any{
			"target": targetName, "root": "missing", "local": "x.txt", "remote": s.sandbox + "/in/x.txt",
		})
		c.add(t, result)
		if text := refusal(t, result); text != "transfer root was not registered" {
			t.Fatalf("%s refusal = %q", tool, text)
		}
	}
}

// scenarioRefuseNoRoots fails closed: without a registered root every
// transfer operation refuses.
func scenarioRefuseNoRoots(t *testing.T) {
	s := newStackRoots(t, transfercore.DefaultLimits(), nil, false)
	var c captured
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"remote_upload", map[string]any{"target": targetName, "local": "x.txt", "remote": "/srv/x.txt"}},
		{"remote_download", map[string]any{"target": targetName, "remote": "/srv/x.txt", "local": "x.txt"}},
		{"transfer_status", map[string]any{"job_id": "whatever"}},
		{"transfer_cancel", map[string]any{"job_id": "whatever"}},
	}
	for _, call := range calls {
		result := callTool(t, s, call.tool, call.args)
		c.add(t, result)
		if text := refusal(t, result); text != "no transfer roots are registered; the owner registers one with --transfer-root when starting the keeper" {
			t.Fatalf("%s refusal = %q", call.tool, text)
		}
	}
}

// scenarioRefuseOverLimit refuses over-limit size and entry counts in both
// directions before any mutation.
func scenarioRefuseOverLimit(t *testing.T) {
	limits := transfercore.Limits{MaxBytes: 4096, MaxEntries: 2, MaxPathBytes: 1024, MaxDepth: 64}
	s := newStack(t, limits, nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{
		"big.bin":    SeedPayload(8192, 6),
		"many/1.txt": []byte("a"),
		"many/2.txt": []byte("b"),
		"many/3.txt": []byte("c"),
	}, []string{"many"})
	WriteTree(t, s.sandbox, map[string][]byte{
		"in/big.bin": SeedPayload(8192, 6),
		"tree/1.txt": []byte("a"),
		"tree/2.txt": []byte("b"),
		"tree/3.txt": []byte("c"),
	}, []string{"in", "tree"})
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "big.bin", "remote": s.sandbox + "/in/big.bin",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit upload status = %+v", out)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/big.bin", "local": "big.bin",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit download status = %+v", down)
	}
	dir := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "many", "remote": s.sandbox + "/in/many",
	}))
	if dir.State != "failed" || dir.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit entry upload status = %+v", dir)
	}
	tree := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/tree", "local": "tree",
	}))
	if tree.State != "failed" || tree.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit entry download status = %+v", tree)
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRefuseUnapprovedTarget refuses a target that is not approved.
func scenarioRefuseUnapprovedTarget(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	result := callTool(t, s, "remote_upload", map[string]any{
		"target": "other-target", "local": "x.txt", "remote": "/srv/x.txt",
	})
	c.add(t, result)
	if text := refusal(t, result); text != "target is not allowed" {
		t.Fatalf("unapproved target refusal = %q", text)
	}
}

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
	var out transfer.StartOutput
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

// structured reads the plain-text result of a bridge tool into its keeper
// result type; the tools carry no structured content.
func structured(t *testing.T, result *mcp.CallToolResult, out any) {
	t.Helper()
	text, err := bridge.ResultText(result)
	if err != nil {
		t.Fatalf("tool result is not the plain-text contract: %v", err)
	}
	if err := bridge.ParseResult(text, out); err != nil {
		t.Fatalf("tool result text did not parse: %v", err)
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

// statusOutput is the transfer_status record read back from its text.
type statusOutput = transfer.StatusOutput
