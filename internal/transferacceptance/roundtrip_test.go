//go:build linux || darwin

package transferacceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

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
