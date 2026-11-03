package vault

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func directoryFixture(t *testing.T) (*Vault, string) {
	t.Helper()
	v := New()
	v.Targets["production"] = testTarget(t)
	if err := v.UpgradeDirectory(); err != nil {
		v.Close()
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	id, err := v.ServerID("production")
	if err != nil {
		t.Fatal(err)
	}
	return v, id
}

func directoryRef(t *testing.T, version byte) string {
	t.Helper()
	r, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{version}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestDirectoryMigrationPreservesEveryProfile(t *testing.T) {
	v := New()
	defer v.Close()
	first := testTarget(t)
	first.Usage = "human"
	v.Targets["production"] = first
	second := ownTarget(first)
	second.User = "another-user"
	v.Targets["same-address"] = second
	before := make(map[string]Target)
	for name, target := range v.Targets {
		before[name] = ownTarget(target)
		defer clear(before[name].PrivateKey)
	}
	if err := v.UpgradeDirectory(); err != nil {
		t.Fatal(err)
	}
	if v.Version != 2 || len(v.Servers) != 2 || !reflect.DeepEqual(before, v.Targets) {
		t.Fatal("migration merged profiles or changed credential metadata")
	}
	for name := range before {
		id, err := v.ServerID(name)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := v.AccountProfile(id, "main")
		if err != nil || profile != name {
			t.Fatal("legacy profile selection changed")
		}
	}
	if err := v.UpgradeDirectory(); err == nil {
		t.Fatal("repeated migration was accepted")
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if !reflect.DeepEqual(decoded.Targets, v.Targets) || !reflect.DeepEqual(decoded.Servers, v.Servers) {
		t.Fatal("version 2 roundtrip lost credentials or account metadata")
	}
}

func TestDirectoryAccountsAndStableRename(t *testing.T) {
	v, id := directoryFixture(t)
	target := ownTarget(v.Targets["production"])
	defer clear(target.PrivateKey)
	target.User = "operator"
	if err := v.SetAccount(id, "operator", target); err != nil {
		t.Fatal(err)
	}
	profile, err := v.AccountProfile(id, "operator")
	if err != nil || profile == "production" || v.Targets[profile].User != "operator" {
		t.Fatal("second account did not retain its separate identity")
	}
	clear(target.PrivateKey)
	if v.Targets[profile].Validate() != nil {
		t.Fatal("account retained caller-owned key memory")
	}
	if err := v.RenameServer(id, "renamed"); err != nil {
		t.Fatal(err)
	}
	got, err := v.ServerID("renamed")
	if err != nil || got != id {
		t.Fatal("rename changed server identity")
	}
	if _, err := v.ServerID("production"); err == nil {
		t.Fatal("old name still resolved")
	}
	if _, err := v.AccountProfile(id, "missing"); err == nil {
		t.Fatal("missing account silently selected another identity")
	}
}

func TestDirectoryNamedSecretScopesAndVersions(t *testing.T) {
	v, server := directoryFixture(t)
	global := SecretBinding{Name: "token", Ref: directoryRef(t, 3)}
	globalID, err := v.BindSecret("", global)
	if err != nil {
		t.Fatal(err)
	}
	local := SecretBinding{Name: "token", ServerID: server, Ref: directoryRef(t, 5)}
	localID, err := v.BindSecret("", local)
	if err != nil {
		t.Fatal(err)
	}
	for scope, want := range map[string]string{"": global.Ref, server: local.Ref} {
		got, err := v.NamedReference(scope, "token")
		if err != nil || got != want {
			t.Fatal("scope selected the wrong immutable reference")
		}
	}
	if _, err := v.BindSecret("", local); err == nil {
		t.Fatal("duplicate scoped name was accepted")
	}
	local.Name, local.Ref = "renamed", directoryRef(t, 6)
	gotID, err := v.BindSecret(localID, local)
	if err != nil || gotID != localID || v.Secrets[globalID] != global {
		t.Fatal("secret edit changed identity or another scope")
	}
	if _, err := v.NamedReference(server, "token"); err == nil {
		t.Fatal("missing local secret fell back to a global value")
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if !reflect.DeepEqual(decoded.Secrets, v.Secrets) {
		t.Fatal("named reference roundtrip changed metadata")
	}
}

func TestDirectoryPasswordRoundtripAndCleanup(t *testing.T) {
	v, server := directoryFixture(t)
	target := v.Targets["production"]
	target.PrivateKey, target.Password, target.User = nil, []byte("synthetic-password"), "password-user"
	defer clear(target.Password)
	if err := v.SetAccount(server, "password", target); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := decoded.AccountProfile(server, "password")
	if err != nil {
		decoded.Close()
		t.Fatal(err)
	}
	got := decoded.Targets[profile]
	if !bytes.Equal(got.Password, target.Password) || len(got.PrivateKey) != 0 {
		decoded.Close()
		t.Fatal("password authentication changed during serialization")
	}
	decoded.Close()
	if !bytes.Equal(got.Password, make([]byte, len(got.Password))) {
		t.Fatal("password memory was not cleared")
	}
}
