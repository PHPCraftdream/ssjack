package recovery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
)

func TestRestoreRetainsPreviousEncryptedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous := []byte("opaque previous ciphertext")
	replacement := []byte("opaque replacement ciphertext")
	if err := store.Commit(path, previous, nil); err != nil {
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
	if err := store.Commit(path, previous, nil); err != nil {
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
	v := core.New()
	defer v.Close()
	if err := core.CreateContext(ctx, path, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled creation was accepted")
	}
	if err := core.SaveContext(ctx, path, v, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled save was accepted")
	}
	if err := Backup(ctx, "missing", path, []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled backup read or wrote credentials")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled operation created a database")
	}
}

func TestUpgradePublicationPreservesOriginalAndRejectsStalePlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	previous, replacement := []byte("verified v1 ciphertext"), []byte("verified v2 ciphertext")
	if err := store.Commit(path, previous, nil); err != nil {
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
		if err := store.Commit(path, previous, nil); err != nil {
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
	if err := store.Commit(path, previous, nil); err != nil {
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

func TestVaultFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("full 1 GiB profile runs in its dedicated GitHub CI job")
	}
	path := filepath.Join(t.TempDir(), "credentials.ssjack.ktav")
	password := []byte("full-profile integration test secret")
	if err := core.Create(path, password); err != nil {
		t.Fatal(err)
	}
	v, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	target := vaulttest.Target(t)
	v.Targets["selected"] = target
	if err := core.SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{[]byte(target.Address), []byte("BEGIN OPENSSH PRIVATE KEY"), target.PrivateKey, []byte("argon2id-"), []byte("memory_kib:")} {
		if bytes.Contains(encoded, plain) {
			t.Fatal("credential data was stored outside encryption")
		}
	}
	reopened, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := reopened.Targets["selected"]
	if len(reopened.Targets) != 1 || got.Address != target.Address || got.User != target.User || !bytes.Equal(got.PrivateKey, target.PrivateKey) {
		t.Fatal("production KDF/container round trip changed the credential record")
	}
	if _, err := got.ClientConfig(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(filepath.Dir(path), "backup.ssjack.ktav")
	if err := Backup(context.Background(), path, backup, password); err != nil {
		t.Fatal(err)
	}
	changed := v.Targets["selected"]
	changed.User = "changed-user"
	v.Targets["selected"] = changed
	if err := core.SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	previous, err := Restore(context.Background(), path, backup, password, password)
	if err != nil || previous == "" {
		t.Fatalf("production restore: %q %v", previous, err)
	}
	restored, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.Targets["selected"].User != target.User {
		t.Fatal("production restore did not recover the original record")
	}
}
