package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestVaultDirectoryFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in its dedicated GitHub CI job")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "directory")
	password := []byte("synthetic directory fixture")
	defer clear(password)
	v, server := directoryFixture(t)
	other := ownTarget(v.Targets["production"])
	defer clear(other.PrivateKey)
	other.User, other.Usage = "another-user", "human"
	if _, err := v.AddServer("same-endpoint", "main", other); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	if invalid, err := Load(path, []byte("wrong password")); err == nil {
		invalid.Close()
		t.Fatal("directory accepted a wrong database password")
	}
	loaded, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Version != 2 || loaded.format != 2 || len(loaded.Servers) != 2 || !reflect.DeepEqual(v.Targets, loaded.Targets) || !reflect.DeepEqual(v.Servers, loaded.Servers) {
		t.Fatal("directory lost credentials, metadata or container format")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range v.Targets {
		if bytes.Contains(encoded, target.PrivateKey) || bytes.Contains(encoded, []byte(target.Address)) {
			t.Fatal("directory persisted plaintext credentials")
		}
	}
	verifySessionFullProfile(t, path, password, server)
}

func verifySessionFullProfile(t *testing.T, path string, password []byte, server string) {
	t.Helper()
	ctx := context.Background()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	session, err := OpenSession(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Discard()
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, original) {
		t.Fatal("opening the owner session rewrote the database")
	}
	digest, err := session.SavedCipherDigest()
	if err != nil || digest != sha256.Sum256(original) {
		t.Fatal("session handoff changed or misidentified the loaded ciphertext")
	}
	for _, name := range []string{"first-save", "second-save"} {
		if err := session.Apply(func(v *Vault) error { return v.RenameServer(server, name) }); err != nil {
			t.Fatal(err)
		}
		if err := session.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := session.SavedCipherDigest()
		if err != nil || digest != sha256.Sum256(encoded) {
			t.Fatal("saved session revision did not identify the actual ciphertext")
		}
	}
	verifyOwnerExportFullProfile(t, session, password, server, path)
	if err := session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Version != 2 || loaded.format != 2 || loaded.Servers[server].Name != "second-save" || len(loaded.Targets) != 2 {
		t.Fatal("background encrypted saves lost the latest revision or credentials")
	}
	verifyPasswordBindingFullProfile(t, path, password, loaded, server)
}

func verifyPasswordBindingFullProfile(t *testing.T, path string, password []byte, v *Vault, server string) {
	t.Helper()
	target := v.Targets["production"]
	target.PrivateKey, target.Password, target.User = nil, []byte("synthetic SSH password"), "password-user"
	defer clear(target.Password)
	if err := v.SetAccount(server, "password", target); err != nil {
		t.Fatal(err)
	}
	profile, err := v.AccountProfile(server, "password")
	if err != nil {
		t.Fatal(err)
	}
	before, err := v.PasswordCredentialIdentity(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.PasswordCredentialIdentity(profile)
	if err != nil || before != after {
		t.Fatal("password grant binding changed after encrypted reopen")
	}
	target.Password = []byte("changed synthetic SSH password")
	defer clear(target.Password)
	if err := reopened.SetAccount(server, "password", target); err != nil {
		t.Fatal(err)
	}
	changed, err := reopened.PasswordCredentialIdentity(profile)
	if err != nil || changed == before {
		t.Fatal("password change retained the old grant binding")
	}
}
