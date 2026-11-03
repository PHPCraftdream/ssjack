package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func migrationPublicationFixture(t *testing.T) (*DirectoryMigrationPlan, string) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	previous := []byte("authenticated original ciphertext")
	if err := os.WriteFile(source, previous, 0600); err != nil {
		t.Fatal(err)
	}
	return &DirectoryMigrationPlan{source: source, revision: sha256.Sum256(previous), replacement: []byte("verified migrated ciphertext")}, filepath.Join(dir, "destination")
}

func TestDirectoryMigrationPublishesExclusivelyAndPreservesSource(t *testing.T) {
	plan, destination := migrationPublicationFixture(t)
	before, err := os.ReadFile(plan.source)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Commit(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{plan.source: before, destination: plan.replacement} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("migration publication changed verified bytes")
		}
	}
	if err := plan.Commit(context.Background(), destination); err == nil {
		t.Fatal("migration overwrote an existing destination")
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 2 {
		t.Fatal("migration left staging or lock files")
	}
}

func TestDirectoryMigrationRefusalsPreserveFiles(t *testing.T) {
	for _, mode := range []string{"cancel", "stale", "locked", "existing", "same-source", "missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			plan, destination := migrationPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "cancel":
				cancel()
			case "stale":
				if err := os.WriteFile(plan.source, []byte("newer ciphertext"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				if err := os.WriteFile(plan.source+".lock", []byte("another owner"), 0600); err != nil {
					t.Fatal(err)
				}
			case "existing":
				if err := os.WriteFile(destination, []byte("existing output"), 0600); err != nil {
					t.Fatal(err)
				}
			case "same-source":
				destination = plan.source
			case "missing-parent":
				destination = filepath.Join(filepath.Dir(destination), "absent", "destination")
			}
			before, err := os.ReadFile(plan.source)
			if err != nil {
				t.Fatal(err)
			}
			err = plan.Commit(ctx, destination)
			if err == nil || (mode == "cancel" && !errors.Is(err, context.Canceled)) {
				t.Fatal("invalid migration publication succeeded")
			}
			after, err := os.ReadFile(plan.source)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refused migration changed the source")
			}
			if mode == "existing" {
				got, err := os.ReadFile(destination)
				if err != nil || string(got) != "existing output" {
					t.Fatal("migration changed existing output")
				}
			} else if mode != "same-source" {
				if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Fatal("failed migration published output")
				}
			}
			lock, err := os.ReadFile(plan.source + ".lock")
			if mode == "locked" {
				if err != nil || string(lock) != "another owner" {
					t.Fatal("migration removed another operation's lock")
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("failed migration retained its lock")
			}
		})
	}
}

func TestCancelledDirectoryMigrationPreparationDoesNotRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PrepareDirectoryMigration(ctx, "missing", []byte("synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled preparation did not stop before reading")
	}
}
