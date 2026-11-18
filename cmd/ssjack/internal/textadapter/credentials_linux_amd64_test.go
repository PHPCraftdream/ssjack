//go:build linux && amd64

package textadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestStreamingRegistrationUsesExplicitRootInteractiveBoundary(t *testing.T) {
	for _, command := range []string{"register-stream", "register-reverse-stream"} {
		code, err := Run(context.Background(), "unused", "main", []string{command, "forbidden-caller-metadata"})
		if code != 1 || err == nil || (!strings.Contains(err.Error(), "requires root") && !strings.Contains(err.Error(), "unavailable in broker sessions") && !strings.Contains(err.Error(), "entered interactively")) {
			t.Fatal("streaming registration bypassed the existing root/terminal boundary or did not dispatch")
		}
	}
	code, err := Run(context.Background(), "unused", "main", []string{"revoke-stream"})
	if code != 1 || err == nil || (!strings.Contains(err.Error(), "requires root") && !strings.Contains(err.Error(), "unavailable in broker sessions") && !strings.Contains(err.Error(), "revoke-stream GRANT_ID")) {
		t.Fatal("streaming revocation did not use its explicit namespace")
	}
}

func TestStreamingServeRequiresHarnessBeforeUnlock(t *testing.T) {
	code, err := Run(context.Background(), "unused", "main", []string{"serve-stream", "grant"})
	if code != 1 || err == nil || !strings.Contains(err.Error(), "serve-stream") {
		t.Fatal("streaming serve reached unlock without a harness")
	}
	code, err = runTextStreamHarness(context.Background(), nil, "hydrate-stream-v2", "grant", "profile", "binding", nil, nil)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "explicit harness") {
		t.Fatal("streaming harness construction accepted missing command")
	}
}

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

func TestStartupPasswordDoesNotBypassTextAdapterTerminal(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	source := startupsecret.New("synthetic-password", true)
	defer source.Close()
	ctx := startup.WithInput(context.Background(), source)
	if _, _, _, err := readVaultTextCredential(ctx, "unused", "main"); err == nil {
		t.Fatal("startup password removed the text-adapter terminal boundary")
	}
	password, err := startup.ReadVaultPassword(ctx, "must not prompt", func(string) ([]byte, error) {
		return nil, errors.New("unexpected terminal prompt")
	})
	defer clear(password)
	if err != nil || string(password) != "synthetic-password" {
		t.Fatal("refused text adapter consumed the startup password")
	}
}
