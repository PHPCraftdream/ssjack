package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func TestCredentialCipherDigestRefusesInvalidOrigins(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	if _, err := credentialCipherDigest(missing); err == nil {
		t.Fatal("missing origin was accepted")
	}
	if _, err := credentialCipherDigest(directory); err == nil {
		t.Fatal("nonregular origin was accepted")
	}

	oversized := filepath.Join(directory, "oversized")
	if err := os.WriteFile(oversized, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversized, int64(keyfile.MaxSize)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialCipherDigest(oversized); err == nil {
		t.Fatal("oversized origin was accepted")
	}
}

func TestCredentialCipherDigestMatchesOrigin(t *testing.T) {
	const contents = "bounded ciphertext fixture"
	path := filepath.Join(t.TempDir(), "origin")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := credentialCipherDigest(path)
	if err != nil || digest != sha256.Sum256([]byte(contents)) {
		t.Fatal("bounded origin digest did not match the fixture")
	}
}
