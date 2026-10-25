package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func TestVaultFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("full 1 GiB profile runs in its dedicated GitHub CI job")
	}
	path := filepath.Join(t.TempDir(), "credentials.ssjack.ktav")
	password := []byte("full-profile integration test secret")
	if err := Create(path, password); err != nil {
		t.Fatal(err)
	}
	v, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	target := testTarget(t)
	v.Targets["selected"] = target
	if err := SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	encoded, err := readEncoded(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{[]byte(target.Address), []byte("BEGIN OPENSSH PRIVATE KEY"), target.PrivateKey, []byte("argon2id-"), []byte("memory_kib:")} {
		if bytes.Contains(encoded, plain) {
			t.Fatal("credential data was stored outside encryption")
		}
	}
	reopened, err := Load(path, password)
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
	if err := SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	previous, err := Restore(context.Background(), path, backup, password, password)
	if err != nil || previous == "" {
		t.Fatalf("production restore: %q %v", previous, err)
	}
	restored, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.Targets["selected"].User != target.User {
		t.Fatal("production restore did not recover the original record")
	}
}

func TestVaultUpgradeFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	path := filepath.Join(t.TempDir(), "legacy")
	password := []byte("production upgrade fixture secret")
	v := New()
	defer v.Close()
	v.Targets["main"] = testTarget(t)
	plaintext, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	legacy, err := keyfile.SealVersion(plaintext, password, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := commit(path, legacy, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if err := SaveUnlocked(context.Background(), path, loaded); err != nil {
		t.Fatal(err)
	}
	legacy, err = readEncoded(path)
	if err != nil {
		t.Fatal(err)
	}
	if version, err := keyfile.Format(legacy); err != nil || version != 1 {
		t.Fatal("ordinary save silently upgraded v1")
	}
	oldBackup := filepath.Join(filepath.Dir(path), "v1-backup")
	if err := Backup(context.Background(), path, oldBackup, password); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(oldBackup); err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("backup rewrote v1 bytes")
	}
	if _, err := PrepareUpgrade(context.Background(), path, []byte("wrong")); err == nil {
		t.Fatal("wrong secret accepted")
	}
	plan, err := PrepareUpgrade(context.Background(), path, password)
	if err != nil || !plan.Needed() {
		t.Fatalf("prepare upgrade: %v", err)
	}
	backup, err := plan.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("original v1 not preserved exactly")
	}
	upgraded, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if upgraded.format != 2 || !bytes.Equal(upgraded.Targets["main"].PrivateKey, loaded.Targets["main"].PrivateKey) {
		t.Fatal("upgrade changed format or SSH identity")
	}
	again, err := PrepareUpgrade(context.Background(), path, password)
	if err != nil || again.Needed() {
		t.Fatalf("idempotent prepare: %v", err)
	}
	if _, err := again.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), path, oldBackup, password, password); err != nil {
		t.Fatal(err)
	}
	if got, err := readEncoded(path); err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("rollback did not restore exact v1 bytes")
	}
}

func TestVaultCachedRekeyFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	path := filepath.Join(t.TempDir(), "rekey")
	password, replacement := []byte("old fixture secret"), []byte("new fixture secret")
	if err := Create(path, password); err != nil {
		t.Fatal(err)
	}
	v, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	old := v.unlocked
	if err := SaveContext(context.Background(), path, v, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Seal([]byte("late old-key write")); err == nil {
		t.Fatal("successful rekey retained old master")
	}
	v.Targets["main"] = testTarget(t)
	if err := SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path, replacement)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.Targets) != 1 {
		t.Fatal("cached post-rekey write lost data")
	}
	if stale, err := Load(path, password); err == nil {
		stale.Close()
		t.Fatal("cached write reverted the vault secret")
	}
	owned := v.unlocked
	v.Close()
	if _, err := owned.Seal([]byte("after close")); err == nil {
		t.Fatal("vault Close retained master")
	}
}

func TestVaultGeneratedProfileFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "generated.ssjack.ktav")
	password := []byte("production generated profile fixture")
	v, err := NewUnlocked(password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	public, private, err := v.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	target := testTarget(t)
	clear(target.PrivateKey)
	target.PrivateKey = append([]byte(nil), private...)
	v.Targets["generated"] = target
	if err := CreateUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "generated.ssjack.ktav" {
		t.Fatal("generation wrote extra key or public files")
	}
	reopened, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := keyfile.PublicSSH(reopened.Targets["generated"].PrivateKey)
	if err != nil || !bytes.Equal(got, public) {
		t.Fatal("stored generated identity changed")
	}
	encoded, err := readEncoded(path)
	if err != nil || bytes.Contains(encoded, private) || bytes.Contains(encoded, public) {
		t.Fatal("key material appeared outside encryption")
	}
}
