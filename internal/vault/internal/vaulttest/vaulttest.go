// Package vaulttest holds fixtures shared by the vault packages' tests.
package vaulttest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
)

func Target(t *testing.T) record.Target {
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
	return record.Target{Address: "example.test:22", User: "test", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(public))}}
}

func DirectoryFixture(t *testing.T) (*core.Vault, string) {
	t.Helper()
	v := core.New()
	target := Target(t)
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

func DirectoryRef(t *testing.T, version byte) string {
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

func OwnerID(value byte) string {
	id := [16]byte{value}
	return hex.EncodeToString(id[:])
}

func OwnerReference(t *testing.T, object, version, snapshot byte) appstoreref.Ref {
	t.Helper()
	reference, err := appstoreref.New([16]byte{1}, [16]byte{object}, [16]byte{version}, [16]byte{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func OwnerReferenceText(t *testing.T, reference appstoreref.Ref) string {
	t.Helper()
	text, err := appstoreplaceholder.Encode(reference)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func OwnerStoreFixture(t *testing.T) (*core.Vault, string) {
	t.Helper()
	v, server := DirectoryFixture(t)
	master := []byte("synthetic linked-store master")
	if err := v.LinkOwnerStore(core.OwnerStore{Directory: t.TempDir(), StoreID: OwnerID(1), Master: master}); err != nil {
		t.Fatal(err)
	}
	clear(master)
	if !bytes.Equal(v.OwnerStore.Master, []byte("synthetic linked-store master")) {
		t.Fatal("owner-store link borrowed the input master buffer")
	}
	return v, server
}

func RotationIdentity(t *testing.T) ([]byte, []byte) {
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

func Public(t *testing.T, private []byte) []byte {
	t.Helper()
	key, err := ssh.ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(key.PublicKey())
}

func ProxyFixture(t *testing.T) (*core.Vault, string, string) {
	t.Helper()
	v, server := DirectoryFixture(t)
	first := v.Servers[server].Accounts["main"]
	target := record.OwnTarget(v.Targets[first])
	target.PrivateKey, target.Password, target.User = nil, []byte("synthetic SSH password"), "second"
	defer clear(target.Password)
	if err := v.SetAccount(server, "second", target); err != nil {
		t.Fatal(err)
	}
	return v, server, first
}

func RemoteFixture(t *testing.T) (*core.Vault, string, string) {
	t.Helper()
	v, ssh := DirectoryFixture(t)
	v.RemoteMCP = mcpdirectory.New()
	server, err := v.RemoteMCP.AddServer("docs", "https://docs.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: "work", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-private-MCP-token")}})
	if err != nil {
		t.Fatal(err)
	}
	return v, ssh, account
}

func Context(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
