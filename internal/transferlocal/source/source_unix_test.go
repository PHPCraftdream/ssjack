//go:build !windows

package source_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

func TestSymlinkLeafRefusedUnix(t *testing.T) {
	root, dir := testRoot(t)
	target := filepath.Join(dir, "target.txt")
	writeFile(t, target, []byte("target"))
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(link)
	_, err := root.WalkSource("link.txt", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	if _, _, err := root.OpenSourceFile("link.txt"); err == nil {
		t.Fatal("OpenSourceFile(link.txt) succeeded, want refused")
	}
	requireClass(t, err, transfercore.ClassRefusedPath, dir, "target")
}

func TestSymlinkComponentRefusedUnix(t *testing.T) {
	root, dir := testRoot(t)
	real := filepath.Join(dir, "sub")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeFile(t, filepath.Join(real, "file.txt"), []byte("file"))
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(link)
	_, err := root.WalkSource("link/file.txt", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	_, err = root.WalkSource("link", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}

func TestParseRootRefusesSymlinkedAncestorUnix(t *testing.T) {
	_, dir := testRoot(t)
	inner := filepath.Join(dir, "inner")
	if err := os.Mkdir(inner, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	link := filepath.Join(dir, "innerlink")
	if err := os.Symlink(inner, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	defer os.Remove(link)
	_, err := ParseRoot(link, "")
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}

func TestFifoRefusedUnix(t *testing.T) {
	root, dir := testRoot(t)
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	defer os.Remove(fifo)
	_, err := root.WalkSource("", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	if _, _, err := root.OpenSourceFile("pipe"); err == nil {
		t.Fatal("OpenSourceFile(pipe) succeeded, want refused without blocking")
	}
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}

func TestHardLinkRefusedUnix(t *testing.T) {
	root, dir := testRoot(t)
	original := filepath.Join(dir, "original.txt")
	writeFile(t, original, []byte("shared"))
	second := filepath.Join(dir, "second.txt")
	if err := os.Link(original, second); err != nil {
		t.Fatalf("Link: %v", err)
	}
	defer os.Remove(second)
	// Both single-file entry points (WalkSource and OpenSourceFile) refuse
	// multi-linked files, as does the directory walk.
	_, err := root.WalkSource("", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
	if _, _, err := root.OpenSourceFile("original.txt"); err == nil {
		t.Fatal("OpenSourceFile(original.txt) succeeded, want refused")
	}
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}

func TestControlCharacterNameRefusedUnix(t *testing.T) {
	root, dir := testRoot(t)
	bad := filepath.Join(dir, "a\x01b")
	if err := os.WriteFile(bad, []byte("x"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	defer os.Remove(bad)
	_, err := root.WalkSource("", transfercore.DefaultLimits())
	requireClass(t, err, transfercore.ClassRefusedPath, dir)
}

func TestParseRootRefusesFilesystemRootUnix(t *testing.T) {
	_, err := ParseRoot("/", "")
	requireClass(t, err, transfercore.ClassRefusedPath)
}

func TestForbiddenControlDirAllowedAsSourceUnix(t *testing.T) {
	root, dir := testRoot(t)
	gitDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeFile(t, filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"))
	m, err := root.WalkSource("", transfercore.DefaultLimits())
	if err != nil {
		t.Fatalf("WalkSource: %v", err)
	}
	found := false
	for _, f := range m.Files {
		if f.Path == ".git/HEAD" {
			found = true
		}
	}
	if !found {
		t.Fatalf("manifest does not include .git/HEAD: %+v", m.Files)
	}
}
