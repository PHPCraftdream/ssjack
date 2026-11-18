package vaultcmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"golang.org/x/crypto/ssh"
)

func TestAlreadyCancelledExportDoesNotPromptOrWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := exportVaultKey(ctx, path, []byte("unused"), []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled export reached prompting or file publication: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("cancelled export created a file")
	}
	called := false
	if err := publishKeyExport(ctx, path, nil, nil, func(_, _ []byte) ([]byte, error) {
		called = true
		return nil, nil
	}); !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled export started cryptographic work")
	}
}

func TestExportCancelledDuringEncryptionDoesNotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := publishKeyExport(ctx, path, []byte("in-memory private fixture"), []byte("export secret"), func(_, _ []byte) ([]byte, error) {
		cancel()
		return []byte("encrypted fixture"), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("export cancellation was lost: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("private export was published after cancellation")
	}
}

func TestExportEncryptionFailureDoesNotPublish(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	failure := errors.New("encryption failed")
	err := publishKeyExport(context.Background(), path, nil, nil, func(_, _ []byte) ([]byte, error) { return nil, failure })
	if !errors.Is(err, failure) {
		t.Fatal("encryption error was lost")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed export created a file")
	}
}

func TestExportSecretMustBeIndependent(t *testing.T) {
	for _, pair := range []struct{ export, vault string }{{"", "vault"}, {"export", ""}, {"same", "same"}} {
		if err := validateExportSecret([]byte(pair.export), []byte(pair.vault)); err == nil {
			t.Fatal("empty authorization or reused vault secret was accepted")
		}
	}
	if err := validateExportSecret([]byte("separate export secret"), []byte("vault secret")); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyRotateRefusesActiveJournalBeforeRemoteEffects(t *testing.T) {
	active := []string{
		vault.RotationPrepared, vault.RotationAttempting, vault.RotationUnknown,
		vault.RotationAdded, vault.RotationVerified, vault.RotationCommitted,
	}
	for _, phase := range active {
		v := &vault.Vault{Rotation: &vault.RotationJournal{Phase: phase}}
		if err := refuseActiveRotation(v); err == nil {
			t.Fatalf("active phase %q admitted legacy rotate", phase)
		}
	}
	for _, phase := range []string{vault.RotationCancelled, vault.RotationComplete, vault.RotationArchived} {
		v := &vault.Vault{Rotation: &vault.RotationJournal{Phase: phase}}
		if err := refuseActiveRotation(v); err != nil {
			t.Fatalf("inactive phase %q refused: %v", phase, err)
		}
	}
	if err := refuseActiveRotation(&vault.Vault{}); err != nil {
		t.Fatalf("no journal refused: %v", err)
	}
}

func TestShowIncludesEffectiveUsageWithoutPrivateBytes(t *testing.T) {
	for _, usage := range []string{"", "both", "human", "agent"} {
		private := []byte("private payload must never be printed")
		target := vault.Target{Address: "example.test:22", User: "user", Usage: usage, PrivateKey: private}
		var output bytes.Buffer
		if err := writeProfileSummary(&output, "main", target); err != nil {
			t.Fatal(err)
		}
		want := usage
		if want == "" {
			want = "both"
		}
		if !strings.Contains(output.String(), "Usage: "+want+"\n") || !strings.Contains(output.String(), "Profile: main\n") {
			t.Fatalf("effective usage not displayed: %q", output.String())
		}
		if bytes.Contains(output.Bytes(), private) {
			t.Fatal("show printed private key bytes")
		}
	}
}

func TestCancelledVaultUpgradeDoesNotPrompt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := RunVaultMaintenance(ctx, filepath.Join(t.TempDir(), "missing"), "main", []string{"upgrade"})
	if code == 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("upgrade did not stop before terminal authorization: %d %v", code, err)
	}
}

func TestLegacyVaultMutationClassification(t *testing.T) {
	for _, action := range []string{"passwd", "add", "edit", "remove", "import"} {
		if !writesVault(action) {
			t.Fatalf("legacy mutation %s lacks early writer admission", action)
		}
	}
	for _, action := range []string{"list", "show", "public", "export"} {
		if writesVault(action) {
			t.Fatalf("read-only capture %s unnecessarily claims the database", action)
		}
	}
}

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
	server := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "legacy-writer")
	block, err := ssh.MarshalPrivateKey(private, "synthetic legacy writer fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(block.Bytes)
	key := pem.EncodeToMemory(block)
	defer clear(key)
	v := vault.New()
	defer v.Close()
	v.Targets["main"] = vault.Target{Address: server.Address(), User: "first", PrivateKey: key, HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.HostKey))}, Usage: "both"}
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
		"add":    func(ctx context.Context) (int, error) { return RunVaultCommand(ctx, path, []string{"add", "new"}) },
		"edit":   func(ctx context.Context) (int, error) { return RunVaultCommand(ctx, path, []string{"edit", "main"}) },
		"remove": func(ctx context.Context) (int, error) { return RunVaultCommand(ctx, path, []string{"remove", "main"}) },
		"key-import": func(ctx context.Context) (int, error) {
			return RunVaultCommand(ctx, path, []string{"import", "main", "missing-synthetic-key"})
		},
		"passwd": func(ctx context.Context) (int, error) { return RunVaultCommand(ctx, path, []string{"passwd"}) },
		"hostkey": func(ctx context.Context) (int, error) {
			return runHostKey(ctx, path, []string{"replace", "main", "missing-synthetic-pin"})
		},
		"policy": func(ctx context.Context) (int, error) { return RunPolicy(ctx, path, "main", []string{"edit"}) },
		"rotate": func(ctx context.Context) (int, error) { return runRotation(ctx, path, "main") },
		"migrate": func(ctx context.Context) (int, error) {
			return runLegacyMigration(ctx, path, "new", "missing-synthetic-source")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			source := startupsecret.New(string(password), true)
			defer source.Close()
			ownerContext := startup.WithInput(ctx, source)
			code, err := run(ownerContext)
			if code != 1 || !errors.Is(err, vault.ErrWriterRole) {
				t.Fatal("occupied legacy writer did not refuse before effects")
			}
			if server.AcceptedConnections() != 0 {
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

func TestExportRefusesExistingPathBeforePrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	original := []byte("keep existing file")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	err := exportVaultKey(context.Background(), path, []byte("unused payload"), []byte("vault secret"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("output conflict was not checked before prompting: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("existing export output changed")
	}
}
