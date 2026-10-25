package vault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradePublicationPreservesOriginalAndRejectsStalePlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous, replacement := []byte("verified v1 ciphertext"), []byte("verified v2 ciphertext")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	plan := &UpgradePlan{path: path, previous: previous, replacement: replacement}
	backup, err := plan.Commit(context.Background())
	if err != nil || backup == "" {
		t.Fatalf("upgrade: %q %v", backup, err)
	}
	for file, want := range map[string][]byte{path: replacement, backup: previous} {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("upgrade changed verified encrypted bytes")
		}
	}
	if _, err := plan.Commit(context.Background()); err == nil {
		t.Fatal("stale upgrade accepted")
	}
}

func TestUpgradeCancellationAndFailedPublication(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "vault")
		previous := []byte("verified original")
		if err := commit(path, previous, nil); err != nil {
			t.Fatal(err)
		}
		plan := &UpgradePlan{path: path, previous: previous, replacement: []byte("replacement")}
		ctx, cancel := context.WithCancel(context.Background())
		if blocked {
			if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			cancel()
		}
		backup, err := plan.Commit(ctx)
		cancel()
		if err == nil {
			t.Fatal("failed upgrade succeeded")
		}
		if !blocked && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, previous) {
			t.Fatal("failed upgrade modified original")
		}
		if blocked {
			got, readErr = os.ReadFile(backup)
			if backup == "" || readErr != nil || !bytes.Equal(got, previous) {
				t.Fatal("failed publication lost recovery copy")
			}
		} else if backup != "" {
			t.Fatal("cancelled upgrade created recovery copy")
		}
	}
}

func TestAlreadyOpaqueUpgradeIsNoOpButChecksRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous := []byte("authenticated opaque ciphertext")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	plan := &UpgradePlan{path: path, previous: previous}
	if plan.Needed() {
		t.Fatal("opaque format needs an upgrade")
	}
	if backup, err := plan.Commit(context.Background()); err != nil || backup != "" {
		t.Fatalf("no-op: %q %v", backup, err)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatal("no-op upgrade created a file")
	}
	if err := os.WriteFile(path, []byte("newer ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := plan.Commit(context.Background()); err == nil {
		t.Fatal("stale no-op plan accepted")
	}
}

func TestCancelledUpgradePreparationDoesNotReadVault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PrepareUpgrade(ctx, "missing", []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepare: %v", err)
	}
}
