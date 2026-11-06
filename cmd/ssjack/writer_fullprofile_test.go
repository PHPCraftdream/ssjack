package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultLegacyWriterFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production legacy writer admission is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := startLoopbackSSH(t, public, connectPassword, "legacy-writer")
	block, err := ssh.MarshalPrivateKey(private, "synthetic legacy writer fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(block.Bytes)
	key := pem.EncodeToMemory(block)
	defer clear(key)
	v := vault.New()
	defer v.Close()
	v.Targets["main"] = vault.Target{Address: server.address(), User: "first", PrivateKey: key, HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.hostKey))}, Usage: "both"}
	password := []byte("synthetic legacy writer database password")
	defer clear(password)
	root := t.TempDir()
	path := filepath.Join(root, "legacy.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ownerlocal.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cases := map[string]func(context.Context) (int, error){
		"add":    func(ctx context.Context) (int, error) { return runVaultCommand(ctx, path, []string{"add", "new"}) },
		"edit":   func(ctx context.Context) (int, error) { return runVaultCommand(ctx, path, []string{"edit", "main"}) },
		"remove": func(ctx context.Context) (int, error) { return runVaultCommand(ctx, path, []string{"remove", "main"}) },
		"key-import": func(ctx context.Context) (int, error) {
			return runVaultCommand(ctx, path, []string{"import", "main", "missing-synthetic-key"})
		},
		"passwd": func(ctx context.Context) (int, error) { return runVaultCommand(ctx, path, []string{"passwd"}) },
		"hostkey": func(ctx context.Context) (int, error) {
			return runHostKey(ctx, path, []string{"replace", "main", "missing-synthetic-pin"})
		},
		"policy": func(ctx context.Context) (int, error) { return runPolicy(ctx, path, "main", []string{"edit"}) },
		"rotate": func(ctx context.Context) (int, error) { return runRotation(ctx, path, "main") },
		"migrate": func(ctx context.Context) (int, error) {
			return runLegacyMigration(ctx, path, "new", "missing-synthetic-source")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			source := startupsecret.New(string(password), true)
			defer source.Close()
			ownerContext := context.WithValue(ctx, startupPasswordKey{}, source)
			code, err := run(ownerContext)
			if code != 1 || !errors.Is(err, vault.ErrWriterRole) {
				t.Fatal("occupied legacy writer did not refuse before effects")
			}
			if server.acceptedConnections() != 0 {
				t.Fatal("occupied rotation contacted its SSH target")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, before) {
				t.Fatal("refused legacy writer changed encrypted bytes")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 || entries[0].Name() != "legacy.ktav" {
				t.Fatal("refused writer created recovery, key or lock files")
			}
		})
	}
}
