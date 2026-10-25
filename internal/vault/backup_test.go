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

func TestRestoreRetainsPreviousEncryptedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous := []byte("opaque previous ciphertext")
	replacement := []byte("opaque replacement ciphertext")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	backup, err := restoreVerified(context.Background(), path, replacement, previous)
	if err != nil || backup == "" {
		t.Fatalf("restore: %q %v", backup, err)
	}
	for file, want := range map[string][]byte{path: replacement, backup: previous} {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encrypted bytes changed: %s", filepath.Base(file))
		}
	}
	if _, err := restoreVerified(context.Background(), path, previous, previous); err == nil {
		t.Fatal("stale restore overwrote the new revision")
	}
}

func TestRestoreFailureAndCancellationPreserveCurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous := []byte("opaque ciphertext")
	if err := commit(path, previous, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := restoreVerified(ctx, path, []byte("replacement"), previous); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled restore: %v", err)
	}
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := restoreVerified(context.Background(), path, []byte("replacement"), previous)
	if err == nil || backup == "" {
		t.Fatal("failed commit did not retain recovery snapshot")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, previous) {
		t.Fatal("failed restore modified the working database")
	}
	got, readErr = os.ReadFile(backup)
	if readErr != nil || !bytes.Equal(got, previous) {
		t.Fatal("failed restore lost the previous encrypted data")
	}
}

func TestCancelledWritesDoNotDeriveOrCreateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := New()
	defer v.Close()
	if err := CreateContext(ctx, path, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled creation was accepted")
	}
	if err := SaveContext(ctx, path, v, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled save was accepted")
	}
	if err := Backup(ctx, "missing", path, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled backup read or wrote credentials")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled operation created a database")
	}
}

func TestSnapshotRejectsRevisionChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	data := []byte("authenticated ciphertext fixture")
	if err := commit(path, data, nil); err != nil {
		t.Fatal(err)
	}
	v := New()
	defer v.Close()
	v.revision = sha256.Sum256(data)
	backup, err := Snapshot(path, v)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, data) {
		t.Fatal("snapshot bytes changed")
	}
	if err := os.WriteFile(path, []byte("newer revision"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Snapshot(path, v); err == nil {
		t.Fatal("unauthenticated newer revision was snapshotted")
	}
}
