package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/keyfile"
)

func TestKeyFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--generate-key", "new", "--protect-key", "old"},
		{"--generate-key", "new", "--key-output", "other"},
		{"--key-output", "new"},
		{"--generate-key", "new", "claude"},
		{"--protect-key", "old", "claude"},
	} {
		if code, err := run(context.Background(), args); code == 0 || err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
}

func TestKeyOutputsNeverOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	original := []byte("original")
	if err := writeNewFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(path, []byte("replacement"), 0600); err == nil {
		t.Fatal("existing output was overwritten")
	}
	if code, err := run(context.Background(), []string{"--generate-key", path}); code == 0 || err == nil {
		t.Fatal("generation accepted an existing output")
	}
	if code, err := run(context.Background(), []string{"--protect-key", "missing", "--key-output", path}); code == 0 || err == nil {
		t.Fatal("protection accepted an existing output")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("existing file changed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private output permissions are not 0600")
		}
	}
	newPath := filepath.Join(dir, "another-key")
	if err := os.WriteFile(newPath+".pub", original, 0644); err != nil {
		t.Fatal(err)
	}
	if code, err := run(context.Background(), []string{"--generate-key", newPath}); code == 0 || err == nil {
		t.Fatal("generation accepted an existing public output")
	}
	if _, err := os.Lstat(newPath); !os.IsNotExist(err) {
		t.Fatal("private output was created despite public-path conflict")
	}
}

func TestOutputPreflightRejectsMissingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "key")
	if err := requireNewPath(path); err == nil {
		t.Fatal("missing parent was accepted")
	}
}

func TestProtectKeepsInputWhenOutputConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	original := []byte("input remains untouched")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := run(context.Background(), []string{"--protect-key", path, "--key-output", path}); code == 0 || err == nil {
		t.Fatal("in-place protection was accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("input changed")
	}
}

func TestLegacyKeyConversionPreservesIdentity(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	password := []byte("legacy test password")
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "test", password)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(block)
	plain, err := keyfile.ImportSSH(encoded, password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	signer, err := ssh.ParsePrivateKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil || !bytes.Equal(public.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("key identity changed during conversion")
	}
	if _, err := keyfile.ImportSSH(encoded, []byte("wrong")); err == nil {
		t.Fatal("wrong legacy password was accepted")
	}
}

func TestExportRefusesExistingPathBeforePrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported-key")
	original := []byte("keep existing file")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	err := exportVaultKey(path, []byte("unused payload"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("output conflict was not checked before prompting: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("existing export output changed")
	}
}
