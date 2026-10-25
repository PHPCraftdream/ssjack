package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testTarget(t *testing.T) Target {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "test")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return Target{Address: "example.test:22", User: "test", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(public))}}
}

func TestVaultPayloadRoundTripAndCleanup(t *testing.T) {
	for _, populated := range []bool{false, true} {
		v := New()
		if populated {
			v.Targets["test"] = testTarget(t)
		}
		encoded, err := marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := unmarshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Version != 1 || len(decoded.Targets) != len(v.Targets) ||
			!bytes.Equal(decoded.Targets["test"].PrivateKey, v.Targets["test"].PrivateKey) {
			t.Fatal("vault payload changed")
		}
		private := decoded.Targets["test"].PrivateKey
		decoded.Close()
		if len(decoded.Targets) != 0 || !bytes.Equal(private, make([]byte, len(private))) {
			t.Fatal("private key buffers were not cleared")
		}
		v.Close()
	}
}

func TestVaultStrictFieldsAndValidation(t *testing.T) {
	v := New()
	v.Targets["test"] = testTarget(t)
	defer v.Close()
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"\nunknown: true\n", "\ntargets.test.unknown: true\n", "\nversion: 1\n"} {
		if loaded, err := unmarshal(append(append([]byte(nil), encoded...), []byte(extra)...)); err == nil {
			loaded.Close()
			t.Fatal("unknown or duplicate fields were accepted")
		}
	}
	for _, name := range []string{"", "-name", "a b", "../name", strings.Repeat("x", 65), "name\n"} {
		if err := ValidateName(name); err == nil {
			t.Fatal("invalid target name was accepted")
		}
	}
	for _, mutate := range []func(*Target){
		func(v *Target) { v.Address = "missing-port" },
		func(v *Target) { v.Address = ":22" },
		func(v *Target) { v.User = "" },
		func(v *Target) { v.PrivateKey = []byte("invalid") },
		func(v *Target) { v.HostKeys = nil },
		func(v *Target) { v.HostKeys = []string{"invalid"} },
		func(v *Target) { v.HostKeys = []string{v.HostKeys[0], v.HostKeys[0]} },
	} {
		changed := v.Targets["test"]
		mutate(&changed)
		if err := changed.Validate(); err == nil {
			t.Fatal("invalid target credentials were accepted")
		}
	}
}

func TestSSHPortValidation(t *testing.T) {
	target := testTarget(t)
	defer clear(target.PrivateKey)
	for _, address := range []string{"example.test:0", "example.test:65536", "example.test:ssh", "example.test:+22"} {
		target.Address = address
		if err := target.Validate(); err == nil {
			t.Fatalf("invalid port was accepted: %s", address)
		}
	}
	for _, address := range []string{"example.test:22", "[::1]:65535"} {
		target.Address = address
		if err := target.Validate(); err != nil {
			t.Fatalf("valid port was rejected: %s: %v", address, err)
		}
	}
}

func TestImportedKeyPreservesMetadataAndOwnsBytes(t *testing.T) {
	v := New()
	defer v.Close()
	original := testTarget(t)
	v.Targets["selected"] = original
	oldBytes := append([]byte(nil), original.PrivateKey...)
	defer clear(oldBytes)
	if err := v.ReplaceKey("selected", []byte("invalid")); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	if !bytes.Equal(v.Targets["selected"].PrivateKey, oldBytes) {
		t.Fatal("invalid import changed the old key")
	}
	incoming := testTarget(t)
	if err := v.ReplaceKey("selected", incoming.PrivateKey); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), incoming.PrivateKey...)
	defer clear(want)
	clear(incoming.PrivateKey)
	got := v.Targets["selected"]
	if got.Address != original.Address || got.User != original.User || len(got.HostKeys) != len(original.HostKeys) || got.HostKeys[0] != original.HostKeys[0] {
		t.Fatal("key import changed connection metadata or server pins")
	}
	if !bytes.Equal(got.PrivateKey, want) || !bytes.Equal(original.PrivateKey, make([]byte, len(original.PrivateKey))) {
		t.Fatal("replacement key ownership or old-key clearing failed")
	}
	if err := v.ReplaceKey("missing", want); err == nil {
		t.Fatal("key-only import created an incomplete credential record")
	}
}

func TestPinnedHostKeysAndClientConfig(t *testing.T) {
	target := testTarget(t)
	defer clear(target.PrivateKey)
	config, err := target.ClientConfig()
	if err != nil || config.User != target.User || len(config.Auth) != 1 {
		t.Fatalf("client config: %v", err)
	}
	key, err := ParseHostKey([]byte(target.HostKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.HostKeyCallback(target.Address, nil, key); err != nil {
		t.Fatal(err)
	}
	other := testTarget(t)
	defer clear(other.PrivateKey)
	wrong, err := ParseHostKey([]byte(other.HostKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.HostKeyCallback(target.Address, nil, wrong); err == nil {
		t.Fatal("untrusted host key was accepted")
	}
	if _, err := ParseHostKey([]byte(target.HostKeys[0] + other.HostKeys[0])); err == nil {
		t.Fatal("multiple keys in a single pin were accepted")
	}
	if _, err := ParseHostKey([]byte("example.test " + target.HostKeys[0])); err == nil {
		t.Fatal("known_hosts syntax was accepted as a bare pin")
	}
}

func TestEncryptedFileCommitAndRevisionConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	first := []byte("opaque encrypted document one")
	second := []byte("opaque encrypted document two")
	if err := commit(path, first, nil); err != nil {
		t.Fatal(err)
	}
	if err := commit(path, second, nil); err == nil {
		t.Fatal("creation overwrote an existing vault")
	}
	revision := sha256.Sum256(first)
	if err := commit(path, second, &revision); err != nil {
		t.Fatal(err)
	}
	if err := commit(path, first, &revision); err == nil {
		t.Fatal("stale writer overwrote a newer vault")
	}
	data, err := readEncoded(path)
	if err != nil || !bytes.Equal(data, second) {
		t.Fatal("revision conflict changed stored bytes")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("lock or staging file was left after commit")
	}
}

func TestVaultLockAndSizeLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := commit(path, []byte("opaque encrypted document"), nil); err == nil {
		t.Fatal("vault lock was ignored")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("locked vault was created")
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatal("another writer's lock was removed")
	}
	if _, err := unmarshal(make([]byte, 64*1024+1)); err == nil {
		t.Fatal("oversized plaintext vault was accepted")
	}
	if _, err := readEncoded(filepath.Dir(path)); err == nil {
		t.Fatal("directory was accepted as an encrypted vault")
	}
}
