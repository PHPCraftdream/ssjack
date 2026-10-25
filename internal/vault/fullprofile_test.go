package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
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
	if err := Save(path, v, password); err != nil {
		t.Fatal(err)
	}
	encoded, err := readEncoded(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{[]byte(target.Address), []byte("BEGIN OPENSSH PRIVATE KEY"), target.PrivateKey} {
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
	if err := Save(path, v, password); err != nil {
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
