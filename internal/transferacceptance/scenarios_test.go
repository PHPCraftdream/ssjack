//go:build linux || darwin

package transferacceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// checkStatusEnum only echoes values from the field's allowlist, never raw tool text.
func checkStatusEnum(t *testing.T, label, field, got, want string, allowed ...string) {
	t.Helper()
	if got == want {
		return
	}
	for _, value := range allowed {
		if got == value {
			t.Fatalf("%s status %s: got %q, want %q", label, field, value, want)
		}
	}
	t.Fatalf("%s status %s: got unrecognized value (len=%d), want %q", label, field, len(got), want)
}

func checkStatusState(t *testing.T, label string, out statusOutput, want string) {
	t.Helper()
	checkStatusEnum(t, label, "state", out.State, want, "running", "done", "failed", "cancelled")
}

func checkStatusKind(t *testing.T, label string, out statusOutput, want string) {
	t.Helper()
	checkStatusEnum(t, label, "kind", out.Kind, want, "file", "directory")
}

func checkFailedStatus(t *testing.T, label string, out statusOutput, want transfercore.Class) {
	t.Helper()
	checkStatusState(t, label, out, "failed")
	checkStatusEnum(t, label, "error class", out.ErrorClass, string(want), "",
		string(transfercore.ClassRefusedPath), string(transfercore.ClassExists), string(transfercore.ClassLimit),
		string(transfercore.ClassUnsupportedRemote), string(transfercore.ClassIntegrity), string(transfercore.ClassRemoteFailed),
		string(transfercore.ClassLinkUnstable), string(transfercore.ClassCancelled), string(transfercore.ClassInternal))
}

func checkStatusCount[N int | int64](t *testing.T, label, field string, got, want N) {
	t.Helper()
	if got != want {
		t.Fatalf("%s status %s: got %d, want %d", label, field, got, want)
	}
}

func checkStatusDigest(t *testing.T, label, field, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s status %s mismatch: got len=%d short=%s, want len=%d short=%s", label, field,
			len(got), flakediag.Short([]byte(got)), len(want), flakediag.Short([]byte(want)))
	}
}

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
	checkStatusState(t, "upload", out, "done")
	checkStatusEnum(t, "upload", "direction", out.Direction, "upload", "upload", "download")
	checkStatusKind(t, "upload", out, "file")
	checkStatusCount(t, "upload", "files", out.Files, 1)
	checkStatusCount(t, "upload", "dirs", out.Dirs, 0)
	checkStatusCount(t, "upload", "bytes", out.Bytes, int64(len(source)))
	assertSHA(t, source, out.SHA256)
	AssertNoStaging(t, s.sandbox)
	stored, err := os.ReadFile(remote)
	if err != nil {
		t.Fatal("remote copy: read failed")
	}
	if !bytes.Equal(stored, source) {
		t.Fatal("remote copy: not byte-exact")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": remote, "local": "copy/blob.bin",
	}))
	checkStatusState(t, "download", down, "done")
	checkStatusKind(t, "download", down, "file")
	checkStatusCount(t, "download", "bytes", down.Bytes, int64(len(source)))
	checkStatusDigest(t, "download", "sha256", down.SHA256, out.SHA256)
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "copy", "blob.bin"))
	if err != nil {
		t.Fatal("downloaded copy: read failed")
	}
	if !bytes.Equal(stored, source) {
		t.Fatal("downloaded copy: not byte-exact")
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
	if rootErr != nil {
		t.Fatal("published root: stat failed")
	}
	if subErr != nil {
		t.Fatal("published subdirectory: stat failed")
	}
	if rootInfo.Mode().Perm() != subInfo.Mode().Perm() {
		t.Fatalf("published permissions differ: root=%#o subdirectory=%#o", rootInfo.Mode().Perm(), subInfo.Mode().Perm())
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
	checkStatusState(t, "directory upload", out, "done")
	checkStatusKind(t, "directory upload", out, "directory")
	checkStatusCount(t, "directory upload", "files", out.Files, 3)
	checkStatusCount(t, "directory upload", "dirs", out.Dirs, 3)
	if out.SHA256 != "" {
		t.Fatalf("directory upload status sha256: got len=%d, want absent", len(out.SHA256))
	}
	if out.ManifestSHA256 == "" {
		t.Fatal("directory upload status manifest_sha256: got absent, want present")
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
	checkStatusState(t, "directory download", down, "done")
	checkStatusKind(t, "directory download", down, "directory")
	checkStatusCount(t, "directory download", "files", down.Files, 3)
	checkStatusCount(t, "directory download", "dirs", down.Dirs, 3)
	checkStatusDigest(t, "directory download", "manifest_sha256", down.ManifestSHA256, out.ManifestSHA256)
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
	checkStatusState(t, "zero-byte upload", out, "done")
	checkStatusKind(t, "zero-byte upload", out, "file")
	checkStatusCount(t, "zero-byte upload", "files", out.Files, 1)
	checkStatusCount(t, "zero-byte upload", "bytes", out.Bytes, 0)
	assertSHA(t, nil, out.SHA256)
	stored, err := os.ReadFile(s.sandbox + "/in/zero.bin")
	if err != nil {
		t.Fatal("remote zero-byte copy: read failed")
	}
	if len(stored) != 0 {
		t.Fatalf("remote zero-byte copy: got %d bytes, want 0", len(stored))
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/zero.bin", "local": "empty/again.bin",
	}))
	checkStatusState(t, "zero-byte download", down, "done")
	checkStatusCount(t, "zero-byte download", "bytes", down.Bytes, 0)
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "empty", "again.bin"))
	if err != nil {
		t.Fatal("downloaded zero-byte copy: read failed")
	}
	if len(stored) != 0 {
		t.Fatalf("downloaded zero-byte copy: got %d bytes, want 0", len(stored))
	}
	hollow := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "hollow", "remote": s.sandbox + "/in/hollow",
	}))
	checkStatusState(t, "empty directory upload", hollow, "done")
	checkStatusKind(t, "empty directory upload", hollow, "directory")
	checkStatusCount(t, "empty directory upload", "files", hollow.Files, 0)
	checkStatusCount(t, "empty directory upload", "dirs", hollow.Dirs, 0)
	if info, err := os.Stat(s.sandbox + "/in/hollow"); err != nil || !info.IsDir() {
		t.Fatal("empty directory was not published remotely")
	}
	back := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/hollow", "local": "back-from-empty",
	}))
	checkStatusState(t, "empty directory download", back, "done")
	checkStatusKind(t, "empty directory download", back, "directory")
	checkStatusCount(t, "empty directory download", "files", back.Files, 0)
	checkStatusCount(t, "empty directory download", "dirs", back.Dirs, 0)
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
	checkStatusState(t, "names upload", tree, "done")
	checkStatusKind(t, "names upload", tree, "directory")
	checkStatusCount(t, "names upload", "files", tree.Files, 1)
	checkStatusCount(t, "names upload", "dirs", tree.Dirs, 0)
	CompareTrees(t, filepath.Join(s.rootDir, "report final"), s.sandbox+"/remote names/дерево целиком")
	file := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "отчёт за год/данные 2.txt", "remote": s.sandbox + "/remote names/файл с именем.bin",
	}))
	checkStatusState(t, "non-ASCII file upload", file, "done")
	checkStatusKind(t, "non-ASCII file upload", file, "file")
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/remote names/дерево целиком", "local": "папка возврата",
	}))
	checkStatusState(t, "names download", down, "done")
	checkStatusKind(t, "names download", down, "directory")
	CompareTrees(t, filepath.Join(s.rootDir, "report final"), filepath.Join(s.rootDir, "папка возврата"))
	back := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/remote names/файл с именем.bin", "local": "папка возврата/файл.txt",
	}))
	checkStatusState(t, "non-ASCII file download", back, "done")
	checkStatusKind(t, "non-ASCII file download", back, "file")
	stored, err := os.ReadFile(filepath.Join(s.rootDir, "папка возврата", "файл.txt"))
	if err != nil {
		t.Fatal("non-ASCII file round trip: read failed")
	}
	if !bytes.Equal(stored, []byte("кириллица и пробелы")) {
		t.Fatal("non-ASCII file round trip: not byte-exact")
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
		t.Fatal("secrecy upload did not reach the done state")
	}
	bad := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/vault.txt", "local": "missing-parent/dest.txt",
	}))
	if bad.State != "failed" {
		t.Fatal("secrecy download did not reach the failed state")
	}
	if bad.ErrorClass != string(transfercore.ClassRefusedPath) {
		t.Fatal("secrecy download did not report the refused_path error class")
	}
	assertNoLeaks(t, c, secret)
	for _, data := range c {
		if bytes.Contains(data, []byte(s.rootDir)) || bytes.Contains(data, []byte(s.sandbox)) {
			t.Fatal("status disclosed an absolute local path")
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
	checkStatusState(t, "file overwrite", out, "done")
	checkStatusKind(t, "file overwrite", out, "file")
	stored, err := os.ReadFile(s.sandbox + "/dest/blob.bin")
	if err != nil {
		t.Fatal("remote overwrite: read failed")
	}
	if !bytes.Equal(stored, next) {
		t.Fatal("remote overwrite: not byte-exact")
	}
	tree := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "new/tree", "remote": s.sandbox + "/dest/old-tree",
		"overwrite": true, "confirm": true,
	}))
	checkStatusState(t, "directory overwrite", tree, "done")
	checkStatusKind(t, "directory overwrite", tree, "directory")
	CompareTrees(t, filepath.Join(s.rootDir, "new/tree"), s.sandbox+"/dest/old-tree")
	local := filepath.Join(s.rootDir, "existing.bin")
	if err := os.WriteFile(local, old, 0o600); err != nil {
		t.Fatal(err)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/dest/blob.bin", "local": "existing.bin",
		"overwrite": true, "confirm": true,
	}))
	checkStatusState(t, "local overwrite", down, "done")
	checkStatusKind(t, "local overwrite", down, "file")
	stored, err = os.ReadFile(local)
	if err != nil {
		t.Fatal("local overwrite: read failed")
	}
	if !bytes.Equal(stored, next) {
		t.Fatal("local overwrite: not byte-exact")
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
	checkFailedStatus(t, "overwrite onto a directory", out, transfercore.ClassRefusedPath)
	stored, err := os.ReadFile(filepath.Join(s.sandbox, "guard", "keep.txt"))
	if err != nil {
		t.Fatal("remote destination after failed overwrite: read failed")
	}
	if !bytes.Equal(stored, []byte("precious")) {
		t.Fatal("remote destination after failed overwrite: not byte-exact")
	}
	WriteTree(t, s.rootDir, map[string][]byte{"local-guard/keep.txt": []byte("precious")}, []string{"local-guard"})
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/guard/keep.txt", "local": "local-guard",
		"overwrite": true, "confirm": true,
	}))
	checkFailedStatus(t, "download overwrite onto a directory", down, transfercore.ClassRefusedPath)
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "local-guard", "keep.txt"))
	if err != nil {
		t.Fatal("local destination after failed overwrite: read failed")
	}
	if !bytes.Equal(stored, []byte("precious")) {
		t.Fatal("local destination after failed overwrite: not byte-exact")
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
	checkFailedStatus(t, "traversal upload", out, transfercore.ClassRefusedPath)
	if _, err := os.Stat(filepath.Join(s.rootDir, "..", "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal upload escaped the root")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/../outside.txt", "local": "ok.txt",
	}))
	checkFailedStatus(t, "traversal remote path", down, transfercore.ClassRefusedPath)
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
		checkFailedStatus(t, testCase.name+" upload", out, transfercore.ClassRefusedPath)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": "relative/path.txt", "local": "ok.txt",
	}))
	checkFailedStatus(t, "relative remote path", down, transfercore.ClassRefusedPath)
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
	checkFailedStatus(t, "symlinked source tree", out, transfercore.ClassRefusedPath)
	if _, err := os.Lstat(filepath.Join(s.rootDir, "tree", "link.txt")); err != nil {
		t.Fatal("refusal removed or rewrote the source symlink")
	}
	file := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "tree/link.txt", "remote": s.sandbox + "/in/link.txt",
	}))
	checkFailedStatus(t, "symlink source file", file, transfercore.ClassRefusedPath)
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
	checkFailedStatus(t, "remote symlink destination", out, transfercore.ClassRefusedPath)
	link, err := os.Readlink(filepath.Join(s.sandbox, "alias.txt"))
	if err != nil {
		t.Fatal("remote symlink: read failed")
	}
	if filepath.Base(link) != "real.txt" {
		t.Fatal("remote symlink: target basename changed")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/real.txt", "local": "local-alias.txt",
		"overwrite": true, "confirm": true,
	}))
	checkFailedStatus(t, "local symlink destination", down, transfercore.ClassRefusedPath)
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
	checkFailedStatus(t, "forbidden destination", out, transfercore.ClassRefusedPath)
	if _, err := os.Stat(filepath.Join(s.rootDir, ".git")); !os.IsNotExist(err) {
		t.Fatal("forbidden destination directory was created")
	}
	tree := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/repo", "local": "repo",
	}))
	checkFailedStatus(t, "forbidden extracted entry", tree, transfercore.ClassRefusedPath)
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
	checkFailedStatus(t, "existing remote destination", out, transfercore.ClassExists)
	stored, err := os.ReadFile(filepath.Join(s.sandbox, "in", "exists.bin"))
	if err != nil {
		t.Fatal("existing destination after refused upload: read failed")
	}
	if !bytes.Equal(stored, []byte("old remote")) {
		t.Fatal("existing destination after refused upload: not byte-exact")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/exists.bin", "local": "have.txt",
	}))
	checkFailedStatus(t, "existing local destination", down, transfercore.ClassExists)
	stored, err = os.ReadFile(filepath.Join(s.rootDir, "have.txt"))
	if err != nil {
		t.Fatal("existing destination after refused download: read failed")
	}
	if !bytes.Equal(stored, []byte("old local")) {
		t.Fatal("existing destination after refused download: not byte-exact")
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
		t.Fatalf("upload refusal text mismatch: got len=%d short=%s", len(text), flakediag.Short([]byte(text)))
	}
	denied := callTool(t, s, "remote_download", map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/x.txt", "local": "x.txt", "overwrite": true,
	})
	c.add(t, denied)
	if text := refusal(t, denied); text != "overwrite requires confirm=true" {
		t.Fatalf("download refusal text mismatch: got len=%d short=%s", len(text), flakediag.Short([]byte(text)))
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
			t.Fatalf("%s refusal text mismatch: got len=%d short=%s", tool, len(text), flakediag.Short([]byte(text)))
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
			t.Fatalf("%s refusal text mismatch: got len=%d short=%s", call.tool, len(text), flakediag.Short([]byte(text)))
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
	checkFailedStatus(t, "over-limit upload", out, transfercore.ClassLimit)
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/big.bin", "local": "big.bin",
	}))
	checkFailedStatus(t, "over-limit download", down, transfercore.ClassLimit)
	dir := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "many", "remote": s.sandbox + "/in/many",
	}))
	checkFailedStatus(t, "over-limit entry upload", dir, transfercore.ClassLimit)
	tree := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/tree", "local": "tree",
	}))
	checkFailedStatus(t, "over-limit entry download", tree, transfercore.ClassLimit)
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
		t.Fatalf("unapproved target refusal text mismatch: got len=%d short=%s", len(text), flakediag.Short([]byte(text)))
	}
}

// callTool invokes one bridge tool and fails on a transport error.
func callTool(t *testing.T, s *stack, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	deadline, cancel := context.WithTimeout(s.ctx, waitBudget)
	defer cancel()
	result, err := s.session.CallTool(deadline, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s call failed", name)
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
		t.Fatal("tool result encoding failed")
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
		t.Fatal("start call was refused")
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
	const timeoutFailure = "transfer_status did not observe a terminal state before its deadline"
	started := time.Now()
	ctx, cancel := context.WithTimeout(s.ctx, waitBudget)
	defer cancel()
	deadline, _ := ctx.Deadline()
	params := &mcp.CallToolParams{Name: "transfer_status", Arguments: map[string]any{"job_id": job}}
	var last statusOutput
	var observed bool
	var attempts int
	defer func() {
		elapsed, polls := time.Since(started), attempts
		if !observed {
			flakediag.OnFailure(t, func() string {
				return fmt.Sprintf("transfer_status last status: none decoded budget=%s elapsed=%s attempts=%d", waitBudget, elapsed, polls)
			})
			return
		}
		state := "unknown"
		switch last.State {
		case "running":
			state = "running"
		case "done":
			state = "done"
		case "failed":
			state = "failed"
		case "cancelled":
			state = "cancelled"
		}
		class := transfercore.Class(last.ErrorClass)
		switch class {
		case "":
			class = "none"
		case transfercore.ClassRefusedPath, transfercore.ClassExists, transfercore.ClassLimit,
			transfercore.ClassUnsupportedRemote, transfercore.ClassIntegrity, transfercore.ClassRemoteFailed,
			transfercore.ClassLinkUnstable, transfercore.ClassCancelled, transfercore.ClassInternal:
			// The parsed class may share storage with the complete reply text.
			class = transfercore.Class(strings.Clone(string(class)))
		default:
			class = "unknown"
		}
		byteCount := last.Bytes
		flakediag.OnFailure(t, func() string {
			return fmt.Sprintf("transfer_status last status: state=%s error_class=%s bytes=%d budget=%s elapsed=%s attempts=%d",
				state, class, byteCount, waitBudget, elapsed, polls)
		})
	}()

	// Poll locally so status timeouts do not emit a second, unredacted stack dump.
	var timer *time.Timer
	for {
		if time.Until(deadline) <= 0 {
			t.Fatal(timeoutFailure)
		}
		attempts++
		result, err := s.session.CallTool(ctx, params)
		if err != nil {
			if time.Until(deadline) <= 0 {
				t.Fatal(timeoutFailure)
			}
			t.Fatal("transfer_status RPC failed")
		}
		if result == nil {
			t.Fatal("transfer_status returned no result")
		}
		c.add(t, result)
		text, err := bridge.ResultText(result)
		if err != nil {
			t.Fatal("transfer_status result is not the plain-text contract")
		}
		var out statusOutput
		if err := bridge.ParseResult(text, &out); err != nil {
			t.Fatal("transfer_status result text did not decode")
		}
		last, observed = out, true
		if out.State != "running" {
			return out
		}
		if timer == nil {
			timer = time.NewTimer(5 * time.Millisecond)
			defer timer.Stop()
		} else {
			timer.Reset(5 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatal(timeoutFailure)
			}
			t.Fatal("transfer_status RPC failed")
		case <-timer.C:
		}
	}
}

// structured reads the plain-text result of a bridge tool into its keeper
// result type; the tools carry no structured content.
func structured(t *testing.T, result *mcp.CallToolResult, out any) {
	t.Helper()
	text, err := bridge.ResultText(result)
	if err != nil {
		t.Fatal("tool result is not the plain-text contract")
	}
	if err := bridge.ParseResult(text, out); err != nil {
		t.Fatal("tool result text did not parse")
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
