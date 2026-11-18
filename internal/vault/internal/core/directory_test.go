package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/ktav-lang/golang/pure"
)

func directoryFixture(t *testing.T) (*Vault, string) {
	t.Helper()
	v := New()
	target := testTarget(t)
	defer clear(target.PrivateKey)
	if err := v.InitializeDirectory("production", target); err != nil {
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

func TestDirectoryInitializationPreservesProfileAndRefusesExistingRecords(t *testing.T) {
	v, server := directoryFixture(t)
	profile, err := v.AccountProfile(server, "main")
	if err != nil || profile != "production" || v.Version != 2 {
		t.Fatal("initial directory changed the selected profile identity")
	}
	before := record.OwnTarget(v.Targets[profile])
	defer clear(before.PrivateKey)
	if err := v.InitializeDirectory("another", before); err == nil {
		t.Fatal("initialization replaced an existing directory")
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if !reflect.DeepEqual(decoded.Targets[profile], before) || !reflect.DeepEqual(decoded.Servers, v.Servers) {
		t.Fatal("version 2 roundtrip lost initial credentials or account metadata")
	}
	legacy := New()
	defer legacy.Close()
	legacy.Targets["existing"] = record.OwnTarget(before)
	if err := legacy.InitializeDirectory("another", before); err == nil || legacy.Version != 1 || len(legacy.Targets) != 1 {
		t.Fatal("initialization converted or modified a populated legacy database")
	}
}

func TestDirectoryInitializationValidatesAndOwnsCredentials(t *testing.T) {
	v := New()
	defer v.Close()
	target := testTarget(t)
	defer clear(target.PrivateKey)
	if err := v.InitializeDirectory("invalid/name", target); err == nil || v.Version != 1 || len(v.Targets) != 0 || v.Servers != nil || v.Secrets != nil {
		t.Fatal("invalid initialization changed the database")
	}
	if err := v.InitializeDirectory("initial", target); err != nil {
		t.Fatal(err)
	}
	owned := v.Targets["initial"].PrivateKey
	before := append([]byte(nil), owned...)
	defer clear(before)
	clear(target.PrivateKey)
	if !bytes.Equal(v.Targets["initial"].PrivateKey, before) {
		t.Fatal("initial directory retained caller-owned credential bytes")
	}
	v.Close()
	if len(v.Targets) != 0 || !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("closed directory retained credential records or private bytes")
	}
}

func TestDirectoryAccountsAndStableRename(t *testing.T) {
	v, id := directoryFixture(t)
	target := record.OwnTarget(v.Targets["production"])
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
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := Unmarshal(encoded)
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
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := Unmarshal(encoded)
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

// TestEmptyDirectoryRoundtrip proves a version 2 database with zero servers,
// credentials and secrets survives the codec: Ktav writes "{}" and decoding must
// yield non-nil empty maps, which validate requires for version 2.
func TestEmptyDirectoryRoundtrip(t *testing.T) {
	v := NewDirectory()
	defer v.Close()
	link := OwnerStore{Directory: t.TempDir(), StoreID: ownerID(1), Master: []byte("synthetic empty master")}
	for _, linked := range []bool{false, true} {
		if linked {
			if err := v.LinkOwnerStore(link); err != nil {
				t.Fatal(err)
			}
		}
		encoded, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Unmarshal(encoded)
		clear(encoded)
		if err != nil {
			t.Fatal("empty version 2 database did not decode")
		}
		if decoded.Version != 2 || decoded.Targets == nil || decoded.Servers == nil || decoded.Secrets == nil ||
			len(decoded.Targets) != 0 || len(decoded.Servers) != 0 || len(decoded.Secrets) != 0 {
			decoded.Close()
			t.Fatal("empty version 2 database lost its non-nil empty maps")
		}
		if err := decoded.validate(); err != nil {
			decoded.Close()
			t.Fatal(err)
		}
		if linked && (decoded.OwnerStore == nil || decoded.OwnerStore.Directory != link.Directory || decoded.OwnerStore.StoreID != link.StoreID) {
			decoded.Close()
			t.Fatal("empty linked database lost its owner store link")
		}
		decoded.Close()
	}
}

// TestEmptyVersionOneKeepsNilDirectory keeps the version 1 contract: no
// directory maps may appear when decoding a database without them.
func TestEmptyVersionOneKeepsNilDirectory(t *testing.T) {
	v := New()
	defer v.Close()
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Unmarshal(encoded)
	clear(encoded)
	if err != nil {
		t.Fatal("empty version 1 database did not decode")
	}
	defer decoded.Close()
	if decoded.Version != 1 || decoded.Targets == nil || decoded.Servers != nil || decoded.Secrets != nil {
		t.Fatal("version 1 decoding gained directory maps")
	}
}

func TestDirectoryRejectsInvalidMetadata(t *testing.T) {
	v, server := directoryFixture(t)
	for name, mutate := range map[string]func(*Vault){
		"unassigned": func(v *Vault) { v.Servers = map[string]Server{} },
		"duplicate-name": func(v *Vault) {
			v.Servers["00000000000000000000000000000002"] = Server{Name: "production", Accounts: map[string]string{"other": "production"}}
		},
		"invalid-id":        func(v *Vault) { v.Servers["invalid"] = v.Servers[server]; delete(v.Servers, server) },
		"missing-account":   func(v *Vault) { v.Servers[server].Accounts["missing"] = "missing" },
		"duplicate-account": func(v *Vault) { v.Servers[server].Accounts["duplicate"] = "production" },
		"unknown-scope": func(v *Vault) {
			v.Secrets["00000000000000000000000000000003"] = SecretBinding{Name: "token", ServerID: "missing", Ref: directoryRef(t, 3)}
		},
		"invalid-reference": func(v *Vault) {
			v.Secrets["00000000000000000000000000000003"] = SecretBinding{Name: "token", Ref: "latest"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy, err := v.directoryCopy()
			if err != nil {
				t.Fatal(err)
			}
			mutate(copy)
			if _, err := Marshal(copy); err == nil {
				t.Fatal("invalid directory was serialized")
			}
		})
	}
}

func TestDirectoryInvalidEditsLeaveOriginalUntouched(t *testing.T) {
	v, server := directoryFixture(t)
	before, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	target := record.OwnTarget(v.Targets["production"])
	defer clear(target.PrivateKey)
	target.Address = "other.test:22"
	if err := v.SetAccount(server, "other", target); err == nil {
		t.Fatal("account redirected a server to a different endpoint")
	}
	if err := v.RenameServer(server, "invalid name"); err == nil {
		t.Fatal("invalid rename was accepted")
	}
	if _, err := v.AddServer("production", "main", v.Targets["production"]); err == nil {
		t.Fatal("duplicate server name was accepted")
	}
	if _, err := v.BindSecret("", SecretBinding{Name: "token", Ref: "not-a-reference"}); err == nil {
		t.Fatal("invalid secret reference was accepted")
	}
	after, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("failed edit mutated the database")
	}
}

func TestDirectoryRejectsUnknownWireFields(t *testing.T) {
	v, server := directoryFixture(t)
	if _, err := v.BindSecret("", SecretBinding{Name: "token", Ref: directoryRef(t, 3)}); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	for name, mutate := range map[string]func(map[string]any){
		"root": func(root map[string]any) { root["unexpected"] = true },
		"server": func(root map[string]any) {
			root["servers"].(map[string]any)[server].(map[string]any)["unexpected"] = true
		},
		"secret": func(root map[string]any) {
			for _, value := range root["secrets"].(map[string]any) {
				value.(map[string]any)["unexpected"] = true
			}
		},
		"version":           func(root map[string]any) { root["version"] = 1 },
		"missing-directory": func(root map[string]any) { delete(root, "servers"); delete(root, "secrets") },
		"missing-name": func(root map[string]any) {
			record := root["servers"].(map[string]any)[server].(map[string]any)
			delete(record, "name")
			record["unexpected"] = "production"
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := pure.LoadsStrict(string(encoded))
			if err != nil {
				t.Fatal(err)
			}
			root := value.(map[string]any)
			mutate(root)
			text, err := pure.EmitCanonical(root)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := Unmarshal([]byte(text))
			if err == nil {
				loaded.Close()
				t.Fatal("invalid directory wire fields were accepted")
			}
		})
	}
}

func TestDirectoryAuthenticationExclusivity(t *testing.T) {
	key := testTarget(t)
	defer clear(key.PrivateKey)
	password := key
	password.PrivateKey, password.Password = nil, []byte("synthetic-password")
	defer clear(password.Password)
	config, err := password.ClientConfig()
	if err != nil || config.User != password.User || len(config.Auth) != 1 {
		t.Fatal("password client configuration failed")
	}
	pin, err := record.ParseHostKey([]byte(password.HostKeys[0]))
	if err != nil || config.HostKeyCallback(password.Address, nil, pin) != nil {
		t.Fatal("password authentication lost host-key verification")
	}
	both := key
	both.Password = password.Password
	if both.Validate() == nil {
		t.Fatal("mixed authentication was accepted")
	}
	neither := password
	neither.Password = nil
	if neither.Validate() == nil {
		t.Fatal("missing authentication was accepted")
	}
	v := New()
	defer v.Close()
	v.Targets["password"] = password
	if _, err := Marshal(v); err == nil {
		t.Fatal("legacy database silently adopted password authentication")
	}
}

func TestRotationCodecRejectsMalformedPrivateKeyTypeWithoutPanic(t *testing.T) {
	state, server := directoryFixture(t)
	original := record.OwnTarget(state.Targets["production"])
	defer clear(original.PrivateKey)
	public, private := rotationTestIdentity(t)
	defer clear(public)
	defer clear(private)
	record := rotationRecord(&RotationJournal{
		ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 1, BaseRevision: 0,
		Phase: RotationPrepared, ServerID: server, Account: "main", Profile: "production",
		Original: original, NewPrivate: private, NewPublic: public,
		OldPublic: testPublic(t, original.PrivateKey),
	})
	target := record["original"].(map[string]any)
	hostKeys := make([]any, len(target["host_keys"].([]string)))
	for index, key := range target["host_keys"].([]string) {
		hostKeys[index] = key
	}
	target["host_keys"] = hostKeys
	if err := validateRotationRecord(record); err != nil {
		t.Fatalf("valid prepared rotation record rejected: %v", err)
	}
	malformed := make(map[string]any, len(record))
	for field, value := range record {
		malformed[field] = value
	}
	malformedTarget := make(map[string]any, len(target))
	for field, value := range target {
		malformedTarget[field] = value
	}
	malformedTarget["private_key"] = int64(7)
	malformed["original"] = malformedTarget
	if err := validateRotationRecord(malformed); err == nil || err.Error() != "invalid key rotation target key" {
		t.Fatalf("malformed private key error = %v, want invalid key rotation target key", err)
	}
}

func rotationTestIdentity(t *testing.T) ([]byte, []byte) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "rotation-test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(public), pem.EncodeToMemory(block)
}

func testPublic(t *testing.T, private []byte) []byte {
	t.Helper()
	key, err := ssh.ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(key.PublicKey())
}

func proxyFixture(t *testing.T) (*Vault, string, string) {
	t.Helper()
	v, server := directoryFixture(t)
	first := v.Servers[server].Accounts["main"]
	target := record.OwnTarget(v.Targets[first])
	target.PrivateKey, target.Password, target.User = nil, []byte("synthetic SSH password"), "second"
	defer clear(target.Password)
	if err := v.SetAccount(server, "second", target); err != nil {
		t.Fatal(err)
	}
	return v, server, first
}

func TestServerProxyIsSharedOwnedAndInherited(t *testing.T) {
	v, server, first := proxyFixture(t)
	route := &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "proxy.invalid:1080", Username: "operator", Password: []byte("synthetic proxy password")}
	if err := v.SetServerProxy(server, route); err != nil {
		t.Fatal(err)
	}
	route.Clear()
	for _, profile := range v.Servers[server].Accounts {
		if got := v.Targets[profile].Proxy; got == nil || string(got.Password) != "synthetic proxy password" {
			t.Fatal("server proxy borrowed caller credentials")
		}
	}
	target := record.OwnTarget(v.Targets[first])
	defer target.Proxy.Clear()
	target.User, target.Proxy = "third", nil
	if err := v.SetAccount(server, "third", target); err != nil {
		t.Fatal(err)
	}
	third, _ := v.AccountProfile(server, "third")
	if !sshproxy.Equal(v.Targets[first].Proxy, v.Targets[third].Proxy) || v.Targets[first].Proxy == v.Targets[third].Proxy {
		t.Fatal("new SSH account did not inherit an independently owned server route")
	}
	target = record.OwnTarget(v.Targets[first])
	defer target.Proxy.Clear()
	target.Proxy.Address = "other.invalid:1080"
	if err := v.SetAccount(server, "main", target); err == nil {
		t.Fatal("account edit changed a server-owned proxy")
	}
	original := v.Targets[first].Proxy
	if err := v.SetServerProxy(server, &sshproxy.Config{Type: "unknown", Address: "proxy.invalid:80"}); err == nil || original != v.Targets[first].Proxy {
		t.Fatal("invalid proxy edit partially changed the directory")
	}
	if err := v.SetServerProxy(server, nil); err != nil {
		t.Fatal(err)
	}
	for _, profile := range v.Servers[server].Accounts {
		if v.Targets[profile].Proxy != nil {
			t.Fatal("direct selection left a proxy on another account")
		}
	}
	if len(original.Password) != 0 {
		t.Fatal("replaced proxy retained owned password bytes")
	}
}

func TestProxyCodecRejectsUnknownFieldsAndLegacyPayloads(t *testing.T) {
	v, server, first := proxyFixture(t)
	if err := v.SetServerProxy(server, &sshproxy.Config{Type: sshproxy.HTTP, Address: "proxy.invalid:8080", Username: "operator", Password: []byte("synthetic proxy password")}); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if !sshproxy.Equal(v.Targets[first].Proxy, decoded.Targets[first].Proxy) {
		t.Fatal("proxy settings did not round trip")
	}
	for _, mode := range []string{"unknown", "missing-password", "null", "legacy", "different-account"} {
		raw, err := pure.LoadsStrict(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		root := raw.(map[string]any)
		target := root["targets"].(map[string]any)[first].(map[string]any)
		proxy := target["proxy"].(map[string]any)
		switch mode {
		case "unknown":
			proxy["unexpected"] = "field"
		case "missing-password":
			delete(proxy, "password")
		case "null":
			target["proxy"] = nil
		case "legacy":
			root = map[string]any{"version": 1, "targets": map[string]any{first: target}}
		case "different-account":
			proxy["address"] = "different.invalid:80"
		}
		broken, err := pure.EmitCanonical(root)
		if err != nil {
			t.Fatal(err)
		}
		if bad, err := Unmarshal([]byte(broken)); err == nil {
			bad.Close()
			t.Fatalf("invalid proxy schema accepted: %s", mode)
		}
	}
}

func ownerID(value byte) string {
	id := [16]byte{value}
	return hex.EncodeToString(id[:])
}

func ownerReference(t *testing.T, object, version, snapshot byte) appstoreref.Ref {
	t.Helper()
	reference, err := appstoreref.New([16]byte{1}, [16]byte{object}, [16]byte{version}, [16]byte{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func ownerReferenceText(t *testing.T, reference appstoreref.Ref) string {
	t.Helper()
	text, err := appstoreplaceholder.Encode(reference)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func ownerStoreFixture(t *testing.T) (*Vault, string) {
	t.Helper()
	v, server := directoryFixture(t)
	master := []byte("synthetic linked-store master")
	if err := v.LinkOwnerStore(OwnerStore{Directory: t.TempDir(), StoreID: ownerID(1), Master: master}); err != nil {
		t.Fatal(err)
	}
	clear(master)
	if !bytes.Equal(v.OwnerStore.Master, []byte("synthetic linked-store master")) {
		t.Fatal("owner-store link borrowed the input master buffer")
	}
	return v, server
}

func TestOwnerStoreDraftRoundtripAndCleanup(t *testing.T) {
	v, server := ownerStoreFixture(t)
	value := []byte("synthetic pending value")
	operation, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", ServerID: server, MediaType: "text/plain", Value: value})
	if err != nil {
		t.Fatal(err)
	}
	clear(value)
	if v.OwnerStore.Pending.ID != operation || v.OwnerStore.Pending.Phase != "draft" || len(v.Secrets) != 0 || !bytes.Equal(v.OwnerStore.Pending.Change.Value, []byte("synthetic pending value")) {
		t.Fatal("draft changed aliases or lost its owned value")
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v.OwnerStore, decoded.OwnerStore) {
		decoded.Close()
		t.Fatal("owner-store draft changed during roundtrip")
	}
	master, pending := decoded.OwnerStore.Master, decoded.OwnerStore.Pending.Change.Value
	decoded.Close()
	if !bytes.Equal(master, make([]byte, len(master))) || !bytes.Equal(pending, make([]byte, len(pending))) {
		t.Fatal("owner unlock material or pending input was not cleared")
	}
	if _, err := v.BindSecret("", SecretBinding{Name: "racing", Ref: directoryRef(t, 3)}); err == nil {
		t.Fatal("a binding edit raced with a pending owner operation")
	}
	if err := v.RenameServer(server, "renamed-server"); err != nil {
		t.Fatal("unrelated server metadata could not be edited")
	}
	pending = v.OwnerStore.Pending.Change.Value
	if err := v.CancelOwnerDraft(operation); err != nil || v.OwnerStore.Pending != nil || !bytes.Equal(pending, make([]byte, len(pending))) {
		t.Fatal("cancelling a pre-dispatch draft did not clear its private input")
	}
}

func TestOwnerStoreProposalAndReceiptPreserveUnrelatedAliases(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	old := ownerReferenceText(t, ownerReference(t, 2, 3, 4))
	selected, err := v.BindSecret("", SecretBinding{Name: "token", Ref: old})
	if err != nil {
		t.Fatal(err)
	}
	other, err := v.BindSecret("", SecretBinding{Name: "other", Ref: ownerReferenceText(t, ownerReference(t, 9, 10, 4))})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := v.StageOwnerChange(OwnerChange{Action: "update", AliasID: selected, Name: "renamed", PreviousReference: old, MediaType: "text/plain", Value: []byte("new synthetic value")})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{ownerID(2): ownerID(5)}); err == nil || v.OwnerStore.Pending.Phase != "draft" {
		t.Fatal("proposal dropped an unrelated alias or mutated a refused draft")
	}
	versions := map[string]string{ownerID(2): ownerID(5), ownerID(9): ownerID(6)}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), versions); err != nil {
		t.Fatal(err)
	}
	versions[ownerID(2)] = ownerID(99)
	if v.OwnerStore.Pending.Versions[ownerID(2)] != ownerID(5) {
		t.Fatal("prepared version map borrowed caller storage")
	}
	if err := v.CancelOwnerDraft(operation); err == nil {
		t.Fatal("prepared intent was erased without reconciliation")
	}
	references := []appstoreref.Ref{ownerReference(t, 2, 5, 7), ownerReference(t, 9, 6, 7)}
	if err := v.FinishOwnerChange(operation, ownerID(99), ownerID(7), references); err == nil || v.Secrets[selected].Ref != old {
		t.Fatal("mismatched receipt changed aliases")
	}
	pending := v.OwnerStore.Pending.Change.Value
	if err := v.FinishOwnerChange(operation, ownerID(8), ownerID(7), references); err != nil {
		t.Fatal(err)
	}
	if v.OwnerStore.Pending != nil || !bytes.Equal(pending, make([]byte, len(pending))) || v.Secrets[selected].Name != "renamed" || v.Secrets[selected].Ref != ownerReferenceText(t, references[0]) || v.Secrets[other].Ref != ownerReferenceText(t, references[1]) {
		t.Fatal("verified metadata finalization lost names, versions or input cleanup")
	}
}

func TestOwnerStorePreparedRoundtripAndNewAlias(t *testing.T) {
	v, server := ownerStoreFixture(t)
	operation, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", ServerID: server, MediaType: "text/plain", Value: []byte("synthetic")})
	if err != nil {
		t.Fatal(err)
	}
	alias := v.OwnerStore.Pending.Change.AliasID
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{ownerID(2): ownerID(5)}); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := Unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	reference := ownerReference(t, 2, 5, 7)
	if err := decoded.FinishOwnerChange(operation, ownerID(8), ownerID(7), []appstoreref.Ref{reference}); err != nil {
		t.Fatal(err)
	}
	if decoded.Secrets[alias] != (SecretBinding{Name: "token", ServerID: server, Ref: ownerReferenceText(t, reference)}) {
		t.Fatal("reopened prepared intent did not restore its exact named binding")
	}
}

func TestVerifiedNoCommitRecoveryPreservesTheDraftValue(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	operation, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", MediaType: "text/plain", Value: []byte("retained pending value")})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{ownerID(2): ownerID(5)}); err != nil {
		t.Fatal(err)
	}
	if err := v.ReopenOwnerDraft(operation, ownerID(99), ownerID(7)); err == nil || v.OwnerStore.Pending.Phase != "prepared" {
		t.Fatal("uncorrelated recovery changed the prepared intent")
	}
	if err := v.ReopenOwnerDraft(operation, ownerID(8), ownerID(7)); err != nil {
		t.Fatal(err)
	}
	if v.OwnerStore.Pending.Phase != "draft" || v.OwnerStore.Pending.TransactionID != "" || !bytes.Equal(v.OwnerStore.Pending.Change.Value, []byte("retained pending value")) || len(v.Secrets) != 0 {
		t.Fatal("no-commit recovery lost private input or fabricated a committed alias")
	}
}

func TestOwnerStoreRemovalFinalizesWithoutAnotherObject(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	old := ownerReferenceText(t, ownerReference(t, 2, 3, 4))
	alias, err := v.BindSecret("", SecretBinding{Name: "token", Ref: old})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := v.StageOwnerChange(OwnerChange{Action: "remove", AliasID: alias, Name: "token", PreviousReference: old})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PrepareOwnerChange(operation, ownerID(8), ownerID(7), strings.Repeat("a", 64), ownerID(2), map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if err := v.FinishOwnerChange(operation, ownerID(8), ownerID(7), nil); err != nil || len(v.Secrets) != 0 || v.OwnerStore.Pending != nil {
		t.Fatal("owner removal did not finish the exact prepared alias change")
	}
}

func TestOwnerStoreRejectsUnknownOrMissingWireFields(t *testing.T) {
	v, _ := ownerStoreFixture(t)
	if _, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "token", MediaType: "text/plain", Value: []byte("synthetic")}); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	for _, mutate := range []func(map[string]any){
		func(owner map[string]any) { owner["approved"] = true },
		func(owner map[string]any) { owner["master"] = nil },
		func(owner map[string]any) { owner["pending"].(map[string]any)["approved"] = true },
		func(owner map[string]any) { owner["pending"].(map[string]any)["phase"] = "received" },
		func(owner map[string]any) {
			owner["pending"].(map[string]any)["change"].(map[string]any)["extra"] = true
		},
		func(owner map[string]any) {
			delete(owner["pending"].(map[string]any)["change"].(map[string]any), "value")
		},
	} {
		value, err := pure.LoadsStrict(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		root := value.(map[string]any)
		mutate(root["owner_store"].(map[string]any))
		text, err := pure.EmitCanonical(root)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Unmarshal([]byte(text))
		if err == nil {
			decoded.Close()
			t.Fatal("owner-store schema accepted an unknown or missing field")
		}
	}
}
