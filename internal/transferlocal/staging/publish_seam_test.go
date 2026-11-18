package staging

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/localtest"
)

// withRenameFunc swaps the rename seam for the duration of the test.
func withRenameFunc(t *testing.T, fn func(string, string) error) {
	t.Helper()
	old := renameFunc
	renameFunc = fn
	t.Cleanup(func() { renameFunc = old })
}

func TestPublishDirOverwriteRestoresWhenRenameInFails(t *testing.T) {
	dir := localtest.TempDir(t)
	localtest.WriteFile(t, filepath.Join(dir, "dest", "old.txt"), []byte("old"))
	staging, err := NewStaging("dest", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	localtest.WriteFile(t, filepath.Join(staging.Path(), "new.txt"), []byte("new"))
	stagingPath := staging.Path()
	withRenameFunc(t, func(source, destination string) error {
		if source == stagingPath {
			return errors.New("forced")
		}
		return os.Rename(source, destination)
	})
	err = staging.Publish(KindDir)
	localtest.RequireClass(t, err, transfercore.ClassInternal, dir)
	got, err := os.ReadFile(filepath.Join(dir, "dest", "old.txt"))
	if err != nil || string(got) != "old" {
		t.Fatal("old destination content was not preserved")
	}
	localtest.RequireNoPath(t, filepath.Join(dir, "dest", "new.txt"))
	if _, err := os.Stat(stagingPath); err != nil {
		t.Fatalf("staging path missing after failed publish: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(stagingPath, "new.txt")); err != nil || string(got) != "new" {
		t.Fatal("staged content was damaged by the failed publish")
	}
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishDirOverwriteRestoreAlsoFails(t *testing.T) {
	dir := localtest.TempDir(t)
	destAbs := filepath.Join(dir, "dest")
	localtest.WriteFile(t, filepath.Join(destAbs, "old.txt"), []byte("old"))
	staging, err := NewStaging("dest", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	localtest.WriteFile(t, filepath.Join(staging.Path(), "new.txt"), []byte("new"))
	withRenameFunc(t, func(source, destination string) error {
		if destination == destAbs {
			return errors.New("forced")
		}
		return os.Rename(source, destination)
	})
	err = staging.Publish(KindDir)
	localtest.RequireClass(t, err, transfercore.ClassInternal, dir)
	localtest.RequireNoPath(t, destAbs)
	if err := staging.Abort(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var asides []os.DirEntry
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ssjack-transfer-") {
			asides = append(asides, entry)
		}
	}
	if len(asides) != 1 {
		t.Fatalf("expected exactly one aside leftover, got %d", len(asides))
	}
	if !asides[0].IsDir() {
		t.Fatalf("aside leftover is not a directory: %s", asides[0].Name())
	}
	aside := filepath.Join(dir, asides[0].Name())
	got, err := os.ReadFile(filepath.Join(aside, "old.txt"))
	if err != nil || string(got) != "old" {
		t.Fatal("aside leftover does not contain the old destination content")
	}
	if err := os.RemoveAll(aside); err != nil {
		t.Fatal(err)
	}
}
