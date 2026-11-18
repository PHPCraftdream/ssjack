package record

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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
