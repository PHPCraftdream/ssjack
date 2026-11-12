package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ktav-lang/golang/pure"
)

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
			if _, err := marshal(copy); err == nil {
				t.Fatal("invalid directory was serialized")
			}
		})
	}
}

func TestDirectoryInvalidEditsLeaveOriginalUntouched(t *testing.T) {
	v, server := directoryFixture(t)
	before, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	target := ownTarget(v.Targets["production"])
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
	after, err := marshal(v)
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
	encoded, err := marshal(v)
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
			loaded, err := unmarshal([]byte(text))
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
	pin, err := ParseHostKey([]byte(password.HostKeys[0]))
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
	if _, err := marshal(v); err == nil {
		t.Fatal("legacy database silently adopted password authentication")
	}
}

func TestRotationCodecRejectsMalformedPrivateKeyTypeWithoutPanic(t *testing.T) {
	state, server := directoryFixture(t)
	original := ownTarget(state.Targets["production"])
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
