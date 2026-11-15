//go:build linux

package transferremote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// linuxBuildTree creates a fixed fixture tree under root and returns the
// local manifest computed by walking the filesystem (the test oracle).
func linuxBuildTree(t *testing.T, root string) transfercore.Manifest {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "sub", "deep"), 0o755); err != nil {
		t.Fatalf("create fixture dirs: %v", err)
	}
	bin := make([]byte, 64*1024)
	for i := range bin {
		bin[i] = byte(i % 249)
	}
	bin[0] = 0x00
	bin[1] = 0xFF
	bin[2] = '\n'
	bin[3] = 0xFF
	files := map[string][]byte{
		"root file.bin":        bin,
		"sub/ünïcode ñame.txt": []byte("unicode content\n"),
		"sub/deep/data.bin":    {0x00, 0xFF, '\n', 0x00, 0xFF},
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatalf("create fixture file %s: %v", name, err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "root file.bin"), 0o755); err != nil {
		t.Fatalf("chmod fixture file: %v", err)
	}

	var m transfercore.Manifest
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			m.Dirs = append(m.Dirs, rel)
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, transfercore.Entry{
			Path:   rel,
			Size:   int64(len(data)),
			SHA256: sha256.Sum256(data),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixture tree: %v", err)
	}
	m.Normalize()
	return m
}

// linuxTreesEqual asserts that a and b hold the identical sets of relative
// file and directory names and byte-identical file contents.
func linuxTreesEqual(t *testing.T, a, b string) {
	t.Helper()
	collect := func(root string) (dirs map[string]bool, files map[string]bool) {
		dirs = map[string]bool{}
		files = map[string]bool{}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			if d.IsDir() {
				dirs[rel] = true
			} else {
				files[rel] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk tree %s: %v", root, err)
		}
		return dirs, files
	}
	aDirs, aFiles := collect(a)
	bDirs, bFiles := collect(b)
	for rel := range aDirs {
		if !bDirs[rel] {
			t.Fatalf("directory %q exists in %s but not in %s", rel, a, b)
		}
	}
	for rel := range bDirs {
		if !aDirs[rel] {
			t.Fatalf("directory %q exists in %s but not in %s", rel, b, a)
		}
	}
	for rel := range aFiles {
		if !bFiles[rel] {
			t.Fatalf("file %q exists in %s but not in %s", rel, a, b)
		}
		dataA, err := os.ReadFile(filepath.Join(a, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		dataB, err := os.ReadFile(filepath.Join(b, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !bytes.Equal(dataA, dataB) {
			t.Fatalf("file %q content differs between %s and %s", rel, a, b)
		}
	}
	for rel := range bFiles {
		if !aFiles[rel] {
			t.Fatalf("file %q exists in %s but not in %s", rel, b, a)
		}
	}
}

func TestPreflightLinux(t *testing.T) {
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
	tmp := t.TempDir()
	remote := tmp + "/remote"
	want := linuxBuildTree(t, remote)

	got, err := r.PreflightTree(ctx, remote)
	if err != nil {
		t.Fatalf("PreflightTree: %v", err)
	}
	if strings.Join(got.Dirs, "|") != strings.Join(want.Dirs, "|") {
		t.Fatalf("PreflightTree dirs = %v, want %v", got.Dirs, want.Dirs)
	}
	if len(got.Files) != len(want.Files) {
		t.Fatalf("PreflightTree returned %d files, want %d", len(got.Files), len(want.Files))
	}
	for i := range got.Files {
		g, w := got.Files[i], want.Files[i]
		if g.Path != w.Path {
			t.Fatalf("PreflightTree file %d path = %q, want %q", i, g.Path, w.Path)
		}
		if g.Size != w.Size {
			t.Fatalf("PreflightTree file %q size = %d, want %d", g.Path, g.Size, w.Size)
		}
		if g.SHA256 != w.SHA256 {
			t.Fatalf("PreflightTree file %q hash mismatch with the local sha256", g.Path)
		}
	}
}

func TestPreflightRefusalsLinux(t *testing.T) {
	ctx := context.Background()
	base := func(t *testing.T) Remote {
		r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
		if err := r.Probe(ctx); err != nil {
			t.Fatalf("Probe: %v", err)
		}
		return r
	}

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(root+"/real.txt", []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(root+"/real.txt", root+"/link.txt"); err != nil {
			t.Fatal(err)
		}
		_, err := base(t).PreflightTree(ctx, root)
		linuxTestError(t, err, transfercore.ClassRefusedPath)
	})
	t.Run("fifo", func(t *testing.T) {
		root := t.TempDir()
		if err := syscall.Mkfifo(root+"/pipe", 0o600); err != nil {
			t.Fatalf("mkfifo: %v", err)
		}
		_, err := base(t).PreflightTree(ctx, root)
		linuxTestError(t, err, transfercore.ClassRefusedPath)
	})
	t.Run("newline name", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(root+"/we\nird", []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := base(t).PreflightTree(ctx, root)
		linuxTestError(t, err, transfercore.ClassRefusedPath)
	})
	t.Run("tab name", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(root+"/ta\tb", []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := base(t).PreflightTree(ctx, root)
		linuxTestError(t, err, transfercore.ClassRefusedPath)
	})
	t.Run("over limit", func(t *testing.T) {
		root := t.TempDir()
		linuxBuildTree(t, root)
		r := New(linuxShRunner(), "t", transfercore.Limits{
			MaxBytes: 1 << 30, MaxEntries: 1, MaxPathBytes: 1024, MaxDepth: 64,
		})
		_, err := r.PreflightTree(ctx, root)
		linuxTestError(t, err, transfercore.ClassLimit)
	})
}

func TestVerifyTreeLinux(t *testing.T) {
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())

	root := t.TempDir()
	manifest := linuxBuildTree(t, root)
	if err := r.VerifyTree(ctx, root, manifest); err != nil {
		t.Fatalf("VerifyTree on an intact tree: %v", err)
	}

	corrupt := t.TempDir()
	corruptManifest := linuxBuildTree(t, corrupt)
	f, err := os.OpenFile(corrupt+"/sub/deep/data.bin", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("corruption")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = r.VerifyTree(ctx, corrupt, corruptManifest)
	linuxTestError(t, err, transfercore.ClassIntegrity)

	extra := t.TempDir()
	extraManifest := linuxBuildTree(t, extra)
	if err := os.WriteFile(extra+"/extra.bin", []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = r.VerifyTree(ctx, extra, extraManifest)
	linuxTestError(t, err, transfercore.ClassIntegrity)

	removed := t.TempDir()
	removedManifest := linuxBuildTree(t, removed)
	if err := os.Remove(removed + "/sub/ünïcode ñame.txt"); err != nil {
		t.Fatal(err)
	}
	err = r.VerifyTree(ctx, removed, removedManifest)
	linuxTestError(t, err, transfercore.ClassIntegrity)

	emptyDir := t.TempDir()
	emptyManifest := linuxBuildTree(t, emptyDir)
	if err := os.Mkdir(emptyDir+"/extra-dir", 0o755); err != nil {
		t.Fatal(err)
	}
	err = r.VerifyTree(ctx, emptyDir, emptyManifest)
	linuxTestError(t, err, transfercore.ClassIntegrity)

	sym := t.TempDir()
	symManifest := linuxBuildTree(t, sym)
	if err := os.Symlink(sym+"/root file.bin", sym+"/sub/link"); err != nil {
		t.Fatal(err)
	}
	err = r.VerifyTree(ctx, sym, symManifest)
	var e *transfercore.Error
	if !errors.As(err, &e) || e.Class != transfercore.ClassIntegrity {
		t.Fatalf("symlink inside the tree under verification: got %v, want ClassIntegrity", err)
	}
	if e.ExitCode != exitIntegrity {
		t.Fatalf("symlink under verification exited %d, want %d", e.ExitCode, exitIntegrity)
	}
}
