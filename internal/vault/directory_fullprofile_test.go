package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestVaultDirectoryMigrationFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in its dedicated GitHub CI job")
	}
	ctx := context.Background()
	source := filepath.Join(t.TempDir(), "original")
	destination := source + "-directory"
	password := []byte("synthetic directory migration fixture")
	defer clear(password)
	v := New()
	defer v.Close()
	v.Targets["production"] = testTarget(t)
	other := ownTarget(v.Targets["production"])
	other.User, other.Usage = "another-user", "human"
	v.Targets["same-endpoint"] = other
	if err := CreateWithRecords(ctx, source, v, password); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareDirectoryMigration(ctx, source, []byte("wrong password")); err == nil {
		t.Fatal("migration accepted a wrong database password")
	}
	plan, err := PrepareDirectoryMigration(ctx, source, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Commit(ctx, destination); err != nil {
		t.Fatal(err)
	}
	migrated, err := Load(destination, password)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if migrated.Version != 2 || migrated.format != 2 || len(migrated.Servers) != 2 || !reflect.DeepEqual(v.Targets, migrated.Targets) {
		t.Fatal("migration lost credentials, metadata, profiles, or container format")
	}
	for name := range v.Targets {
		server, err := migrated.ServerID(name)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := migrated.AccountProfile(server, "main")
		if err != nil || profile != name {
			t.Fatal("migration changed legacy account identity")
		}
	}
	encoded, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range v.Targets {
		if bytes.Contains(encoded, target.PrivateKey) || bytes.Contains(encoded, []byte(target.Address)) {
			t.Fatal("migration persisted plaintext credentials")
		}
	}
	if after, err := os.ReadFile(source); err != nil || !bytes.Equal(after, original) {
		t.Fatal("migration rewrote the original database")
	}
	legacy, err := Load(source, password)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if legacy.Version != 1 || !reflect.DeepEqual(v.Targets, legacy.Targets) {
		t.Fatal("original database cannot be used for rollback")
	}
	server, err := migrated.ServerID("production")
	if err != nil {
		t.Fatal(err)
	}
	verifySessionFullProfile(t, destination, password, server)
}

func verifySessionFullProfile(t *testing.T, path string, password []byte, server string) {
	t.Helper()
	ctx := context.Background()
	session, err := OpenSession(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Discard()
	for _, name := range []string{"first-save", "second-save"} {
		if err := session.Apply(func(v *Vault) error { return v.RenameServer(server, name) }); err != nil {
			t.Fatal(err)
		}
		if err := session.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
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
