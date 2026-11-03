package vault

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func TestSessionAdoptionRequiresAuthenticatedState(t *testing.T) {
	v, _ := directoryFixture(t)
	private := v.Targets["production"].PrivateKey
	if _, err := StartSession(context.Background(), "missing", v); err == nil {
		t.Fatal("unauthenticated vault was accepted as saved session state")
	}
	for _, value := range private {
		if value != 0 {
			t.Fatal("failed ownership transfer did not clear credentials")
		}
	}
}

func TestSessionAdoptionRejectsEditsBeforeHandoff(t *testing.T) {
	v, server := directoryFixture(t)
	// Test only the private handoff guard; no KDF or usable unlock is created.
	v.unlocked = new(keyfile.Unlocked)
	payload, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v.payloadHash = sha256.Sum256(payload)
	clear(payload)
	if err := v.RenameServer(server, "edited-before-handoff"); err != nil {
		t.Fatal(err)
	}
	if _, err := StartSession(context.Background(), "missing", v); err == nil || !strings.Contains(err.Error(), "edited before") {
		t.Fatal("edited memory state was reported as an already saved session")
	}
}

func TestSessionAdoptionRejectsStaleCiphertext(t *testing.T) {
	v, _ := directoryFixture(t)
	v.unlocked = new(keyfile.Unlocked)
	payload, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v.payloadHash = sha256.Sum256(payload)
	clear(payload)
	v.revision = sha256.Sum256([]byte("previous authenticated ciphertext"))
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(path, []byte("newer ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := StartSession(context.Background(), path, v); err == nil || !strings.Contains(err.Error(), "changed before") {
		t.Fatal("stale loaded vault was accepted as current session state")
	}
	encoded, err := os.ReadFile(path)
	if err != nil || string(encoded) != "newer ciphertext" {
		t.Fatal("failed session adoption rewrote the encrypted database")
	}
}

func TestSavedCipherDigestRefusesUnavailableMetadata(t *testing.T) {
	v, _ := directoryFixture(t)
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	if _, err := s.SavedCipherDigest(); err == nil {
		t.Fatal("synthetic session fabricated a saved ciphertext digest")
	}
}
