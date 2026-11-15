//go:build linux

package transferremote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestPublishFileLinux(t *testing.T) {
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
	tmp := t.TempDir()
	parent := tmp + "/parent"
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload\x00\xff\nwith bytes")
	staged := parent + "/payload.bin"
	if _, err := r.WriteFile(ctx, staged, strings.NewReader(string(payload)), false); err != nil {
		t.Fatalf("stage payload: %v", err)
	}

	destDir := tmp + "/destdir"
	if err := os.Mkdir(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := destDir + "/final.bin"
	if err := r.PublishFile(ctx, staged, dest, false); err != nil {
		t.Fatalf("PublishFile no-overwrite: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("published file missing: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("published file content differs from the payload")
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("staged file %s still exists after publication: %v", staged, err)
	}

	// Publish again without overwrite: dest exists -> ClassExists, unchanged.
	staged2 := parent + "/payload2.bin"
	if _, err := r.WriteFile(ctx, staged2, strings.NewReader("other"), false); err != nil {
		t.Fatalf("stage second payload: %v", err)
	}
	err = r.PublishFile(ctx, staged2, dest, false)
	linuxTestError(t, err, transfercore.ClassExists)
	if got, err := os.ReadFile(dest); err != nil || string(got) != string(payload) {
		t.Fatalf("destination changed after a refused no-overwrite publish: %v", err)
	}

	// Overwrite replaces the content.
	if err := r.PublishFile(ctx, staged2, dest, true); err != nil {
		t.Fatalf("PublishFile overwrite: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "other" {
		t.Fatalf("overwrite did not replace the destination content: %v", err)
	}

	// Overwrite onto a symlink is refused.
	link := destDir + "/link.bin"
	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}
	staged3 := parent + "/payload3.bin"
	if _, err := r.WriteFile(ctx, staged3, strings.NewReader("third"), false); err != nil {
		t.Fatalf("stage third payload: %v", err)
	}
	err = r.PublishFile(ctx, staged3, link, true)
	linuxTestError(t, err, transfercore.ClassRefusedPath)

	// Overwrite onto a directory is refused.
	err = r.PublishFile(ctx, staged3, destDir, true)
	linuxTestError(t, err, transfercore.ClassRefusedPath)

	// No-overwrite onto a symlink reports ClassExists.
	err = r.PublishFile(ctx, staged3, link, false)
	linuxTestError(t, err, transfercore.ClassExists)

	// Overwrite onto an absent destination publishes directly.
	absentFile := destDir + "/absent.bin"
	if err := r.PublishFile(ctx, staged3, absentFile, true); err != nil {
		t.Fatalf("PublishFile overwrite with absent destination: %v", err)
	}
	if got, err := os.ReadFile(absentFile); err != nil || string(got) != "third" {
		t.Fatalf("absent-destination overwrite content: %v", err)
	}
}

func TestPublishDirLinux(t *testing.T) {
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
	tmp := t.TempDir()
	destParent := tmp + "/parent"
	if err := os.Mkdir(destParent, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := destParent + "/tree"

	// No-overwrite with an absent destination succeeds.
	staged := tmp + "/staged"
	linuxBuildTree(t, staged)
	if err := r.PublishDir(ctx, staged, dest, false); err != nil {
		t.Fatalf("PublishDir no-overwrite: %v", err)
	}
	ref := tmp + "/ref"
	linuxBuildTree(t, ref)
	linuxTreesEqual(t, ref, dest)

	// No-overwrite onto an existing destination is refused, dest unchanged.
	stagedA := tmp + "/stagedA"
	linuxBuildTree(t, stagedA)
	err := r.PublishDir(ctx, stagedA, dest, false)
	linuxTestError(t, err, transfercore.ClassExists)
	linuxTreesEqual(t, ref, dest)

	// Overwrite replaces the whole tree and leaves no staging leftovers.
	staged2 := tmp + "/staged2"
	linuxBuildTree(t, staged2)
	if err := os.WriteFile(filepath.Join(staged2, "root file.bin"), []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.PublishDir(ctx, staged2, dest, true); err != nil {
		t.Fatalf("PublishDir overwrite: %v", err)
	}
	ref2 := tmp + "/ref2"
	linuxBuildTree(t, ref2)
	if err := os.WriteFile(filepath.Join(ref2, "root file.bin"), []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	linuxTreesEqual(t, ref2, dest)
	entries, err := os.ReadDir(destParent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			t.Fatalf("destination parent retains staging leftover %q", e.Name())
		}
	}

	// Failed overwrite: the source path missing after the rename-aside makes
	// the second rename fail; the old tree must be restored (exit 24).
	staged3 := tmp + "/staged3"
	linuxBuildTree(t, staged3)
	hidden := tmp + "/hidden"
	if err := os.Rename(staged3, hidden); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "sentinel.txt"), []byte("old content"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = r.PublishDir(ctx, staged3, dest, true)
	var e *transfercore.Error
	if !errors.As(err, &e) || e.Class != transfercore.ClassRemoteFailed {
		t.Fatalf("failed overwrite restore: got %v, want ClassRemoteFailed", err)
	}
	if e.ExitCode != exitRemoteFailed {
		t.Fatalf("failed overwrite restore exited %d, want %d", e.ExitCode, exitRemoteFailed)
	}
	if _, err := os.Stat(filepath.Join(dest, "sentinel.txt")); err != nil {
		t.Fatalf("old destination content was not restored: %v", err)
	}
	entries, err = os.ReadDir(destParent)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), stagingPrefix) {
			t.Fatalf("destination parent retains leftover %q after failed overwrite", en.Name())
		}
	}

	// Overwrite with dest a symlink is refused.
	link := destParent + "/link"
	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}
	err = r.PublishDir(ctx, stagedA, link, true)
	linuxTestError(t, err, transfercore.ClassRefusedPath)

	// Overwrite with dest a regular file is refused.
	regular := destParent + "/regular.txt"
	if err := os.WriteFile(regular, []byte("not a tree"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = r.PublishDir(ctx, stagedA, regular, true)
	linuxTestError(t, err, transfercore.ClassRefusedPath)

	// Overwrite with an absent destination publishes like no-overwrite.
	absent := destParent + "/absent"
	refA := tmp + "/refA"
	linuxBuildTree(t, refA)
	if err := r.PublishDir(ctx, stagedA, absent, true); err != nil {
		t.Fatalf("PublishDir overwrite with absent destination: %v", err)
	}
	linuxTreesEqual(t, refA, absent)
}
