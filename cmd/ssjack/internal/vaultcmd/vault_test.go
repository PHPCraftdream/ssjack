package vaultcmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Test-only export of the private argument validator so the external
// vaultcmd_test package can assert the original combined TestVaultArguments
// table, including the CLI-level routing cases from cmd/ssjack/internal/cli.
var ValidateVaultArgs = validateVaultArgs

func TestPlaintextImportDoesNotModifySource(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	original := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "input-key")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	imported, err := readImportedPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(imported)
	signer, err := ssh.ParsePrivateKey(imported)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(key.Public())
	if err != nil || !bytes.Equal(public.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("plaintext source identity changed")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("source key file was modified")
	}
}
