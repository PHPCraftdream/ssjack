//go:build linux && amd64

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestNamedTextCredentialReturnsResolvedGrantProfile(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "synthetic named text fixture")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	target := vault.Target{Address: "example.invalid:22", User: "deploy", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))}}
	defer clear(target.PrivateKey)
	v := vault.New()
	defer v.Close()
	v.Version, v.Servers, v.Secrets = 2, make(map[string]vault.Server), make(map[string]vault.SecretBinding)
	server, err := v.AddServer("production", "deploy", target)
	if err != nil {
		t.Fatal(err)
	}
	selected := v.Servers[server].Accounts["deploy"]
	runner, profile, digest, err := textCredentialFromVault(v, "@production/deploy")
	if err != nil || runner == nil || profile != selected || profile == "@production/deploy" {
		t.Fatal("text-adapter grant handoff retained a selector instead of the authenticated credential identity")
	}
	want, err := credentialIdentity(selected, v.Targets[selected])
	if err != nil || digest != want {
		t.Fatal("text adapter bound another account's credential identity")
	}
	if _, _, _, err := textCredentialFromVault(v, "@production/missing"); err == nil {
		t.Fatal("text credential selection silently fell back")
	}
}
