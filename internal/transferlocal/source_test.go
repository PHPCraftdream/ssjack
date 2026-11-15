package transferlocal

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func sampleTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	top := make([]byte, 200)
	for i := range top {
		top[i] = byte(i * 37)
	}
	top[10] = 0x00
	top[11] = 0xff
	files := map[string][]byte{
		"top.txt":                top,
		"docs/read me.md":        []byte("read me contents"),
		"docs/данные данные.bin": []byte("данные \x00\xff bytes"),
		"bin/tool":               []byte("#!/bin/sh\nexit 0\n"),
	}
	for rel, content := range files {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), content)
	}
	if err := os.Chmod(filepath.Join(dir, "bin", "tool"), 0700); err != nil {
		t.Fatal(err)
	}
	return files
}

func sameManifest(a, b transfercore.Manifest) bool {
	a.Normalize()
	b.Normalize()
	if len(a.Dirs) != len(b.Dirs) || len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Dirs {
		if a.Dirs[i] != b.Dirs[i] {
			return false
		}
	}
	for i := range a.Files {
		if a.Files[i] != b.Files[i] {
			return false
		}
	}
	return true
}

func TestWalkSourceManifest(t *testing.T) {
	root, dir := testRoot(t)
	files := sampleTree(t, dir)
	m, err := root.WalkSource("", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dirs) != 2 || m.Dirs[0] != "bin" || m.Dirs[1] != "docs" {
		t.Fatalf("dirs: %v", m.Dirs)
	}
	if len(m.Files) != 4 {
		t.Fatalf("files: %d", len(m.Files))
	}
	for i, rel := range []string{"bin/tool", "docs/read me.md", "docs/данные данные.bin", "top.txt"} {
		got := m.Files[i]
		if got.Path != rel {
			t.Fatalf("entry %d path: %q want %q", i, got.Path, rel)
		}
		if got.Size != int64(len(files[rel])) {
			t.Fatalf("entry %q size: %d", rel, got.Size)
		}
		if got.SHA256 != sha256.Sum256(files[rel]) {
			t.Fatalf("entry %q digest mismatch", rel)
		}
	}
	sub, err := root.WalkSource("docs", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Dirs) != 0 {
		t.Fatalf("subtree dirs: %v", sub.Dirs)
	}
	if len(sub.Files) != 2 {
		t.Fatalf("subtree files: %d", len(sub.Files))
	}
	for i, c := range []struct{ wantPath, key string }{
		{"read me.md", "docs/read me.md"},
		{"данные данные.bin", "docs/данные данные.bin"},
	} {
		if sub.Files[i].Path != c.wantPath {
			t.Fatalf("subtree entry %d: %q", i, sub.Files[i].Path)
		}
		if sub.Files[i].SHA256 != sha256.Sum256(files[c.key]) {
			t.Fatalf("subtree entry %q digest mismatch", c.wantPath)
		}
	}
	single, err := root.WalkSource("top.txt", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(single.Files) != 1 || single.Files[0].Path != "top.txt" {
		t.Fatalf("single-file manifest: %+v", single.Files)
	}
}

func TestWalkSourceLimits(t *testing.T) {
	cases := []struct {
		name   string
		limits transfercore.Limits
		class  transfercore.Class
	}{
		{"max bytes", transfercore.Limits{MaxBytes: 25, MaxEntries: 100, MaxPathBytes: 1024, MaxDepth: 64}, transfercore.ClassLimit},
		{"max entries", transfercore.Limits{MaxBytes: 1 << 20, MaxEntries: 2, MaxPathBytes: 1024, MaxDepth: 64}, transfercore.ClassLimit},
		{"max depth", transfercore.Limits{MaxBytes: 1 << 20, MaxEntries: 100, MaxPathBytes: 1024, MaxDepth: 1}, transfercore.ClassRefusedPath},
		{"max path bytes", transfercore.Limits{MaxBytes: 1 << 20, MaxEntries: 100, MaxPathBytes: 8, MaxDepth: 64}, transfercore.ClassRefusedPath},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			root, dir := testRoot(t)
			for _, rel := range []string{"a.txt", "b.txt", "c.txt", "docs/x.txt", "longname.txt"} {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), bytes.Repeat([]byte("0123456789"), 1))
			}
			_, err := root.WalkSource("", c.limits)
			requireClass(t, err, c.class, dir)
		})
	}
}

func TestWalkSourceSingleFileBudget(t *testing.T) {
	root, dir := testRoot(t)
	writeFile(t, filepath.Join(dir, "big.bin"), bytes.Repeat([]byte("a"), 100))
	_, err := root.WalkSource("", transfercore.Limits{MaxBytes: 50, MaxEntries: 100, MaxPathBytes: 1024, MaxDepth: 64})
	requireClass(t, err, transfercore.ClassLimit, dir)
}

func TestWalkSourceAllowsControlDirectory(t *testing.T) {
	root, dir := testRoot(t)
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"))
	m, err := root.WalkSource("", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range m.Files {
		if entry.Path == ".git/HEAD" {
			found = true
		}
	}
	if !found {
		t.Fatalf("source walk dropped .git/HEAD: %v", m.Files)
	}
}

func TestRoundTrip(t *testing.T) {
	root, dir := testRoot(t)
	files := sampleTree(t, dir)
	walked, err := root.WalkSource("", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var tarBytes bytes.Buffer
	if err := root.BuildTar(&tarBytes, "", walked); err != nil {
		t.Fatal(err)
	}
	staging, err := NewStaging("out", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	computed, err := ExtractTar(bytes.NewReader(tarBytes.Bytes()), staging, &walked, transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !sameManifest(computed, walked) {
		t.Fatal("computed manifest differs from walked manifest")
	}
	if err := staging.Publish(KindDir); err != nil {
		t.Fatal(err)
	}
	requireNoPath(t, staging.Path())
	for rel, content := range files {
		got, err := os.ReadFile(filepath.Join(dir, "out", filepath.FromSlash(rel)))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("published file %q differs", rel)
		}
	}
	for _, rel := range []string{"bin", "docs"} {
		info, err := os.Stat(filepath.Join(dir, "out", filepath.FromSlash(rel)))
		if err != nil || !info.IsDir() {
			t.Fatalf("published dir %q missing", rel)
		}
	}
	second, err := ParseRoot(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	republished, err := second.WalkSource("out", transfercore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !sameManifest(republished, computed) {
		t.Fatal("walking the published tree differs from the computed manifest")
	}
}

func TestBuildTarDetectsChangedFile(t *testing.T) {
	t.Run("same length different bytes", func(t *testing.T) {
		root, dir := testRoot(t)
		writeFile(t, filepath.Join(dir, "one.txt"), []byte("aaaaaaaaaa"))
		writeFile(t, filepath.Join(dir, "two.txt"), []byte("bbbbbbbbbb"))
		m, err := root.WalkSource("", transfercore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte("cccccccccc"), 0600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = root.BuildTar(&buf, "", m)
		requireClass(t, err, transfercore.ClassIntegrity, dir)
	})
	t.Run("different length", func(t *testing.T) {
		root, dir := testRoot(t)
		writeFile(t, filepath.Join(dir, "one.txt"), []byte("aaaaaaaaaa"))
		m, err := root.WalkSource("", transfercore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte("bb"), 0600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = root.BuildTar(&buf, "", m)
		requireClass(t, err, transfercore.ClassIntegrity, dir)
	})
	t.Run("deleted file", func(t *testing.T) {
		root, dir := testRoot(t)
		writeFile(t, filepath.Join(dir, "one.txt"), []byte("aaaaaaaaaa"))
		writeFile(t, filepath.Join(dir, "two.txt"), []byte("bbbbbbbbbb"))
		m, err := root.WalkSource("", transfercore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "two.txt")); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = root.BuildTar(&buf, "", m)
		requireClass(t, err, transfercore.ClassIntegrity, dir)
	})
	t.Run("replaced by directory", func(t *testing.T) {
		root, dir := testRoot(t)
		writeFile(t, filepath.Join(dir, "one.txt"), []byte("aaaaaaaaaa"))
		m, err := root.WalkSource("", transfercore.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "one.txt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "one.txt"), 0700); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		err = root.BuildTar(&buf, "", m)
		requireClass(t, err, transfercore.ClassIntegrity, dir)
	})
}

func TestOpenSourceFile(t *testing.T) {
	root, dir := testRoot(t)
	content := []byte("open me \x00\xff")
	writeFile(t, filepath.Join(dir, "file.bin"), content)
	file, size, err := root.OpenSourceFile("file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(content)) {
		t.Fatalf("size: %d", size)
	}
	if file == nil {
		t.Fatal("nil file handle")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0700); err != nil {
		t.Fatal(err)
	}
	_, _, err = root.OpenSourceFile("adir")
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	_, _, err = root.OpenSourceFile("missing.bin")
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}
