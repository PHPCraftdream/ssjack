package vault

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
)

// The pre-adoption production entry must refuse a vault that is not in an
// authenticated unchanged state; the real ciphertext path is covered by the
// full-profile suite.
func TestVaultRemoteMCPCaptureRefusesUnauthenticatedState(t *testing.T) {
	v, server := directoryFixture(t)
	profile, err := v.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	v.RemoteMCP = mcpdirectory.New()
	remote, err := v.RemoteMCP.AddServer("remote", "https://capture.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "keyed", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-vault-capture")}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v.RemoteMCP.CurrentBinding(keyed)
	if err != nil {
		t.Fatal(err)
	}
	ctx := sessionTestContext(t)
	digest := [32]byte{6}
	if capture, err := v.RemoteMCPCapture(ctx, "unused", digest, profile, []mcpdirectory.Binding{binding}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("unauthenticated vault granted a capture")
	}
	var nilVault *Vault
	if capture, err := nilVault.RemoteMCPCapture(ctx, "unused", digest, profile, []mcpdirectory.Binding{binding}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("nil vault was accepted")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if capture, err := v.RemoteMCPCapture(cancelled, "unused", digest, profile, []mcpdirectory.Binding{binding}); capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("cancelled context was accepted")
	}
}

// A file replaced while the capture is being assembled must revoke the newly
// owned copies at the return boundary instead of reaching the caller. The
// mutate seam of the unexported admission core makes that window deterministic
// without sleeps, global hooks or a second KDF.
func TestVaultRemoteMCPCaptureRefusesMidConstructionOriginChange(t *testing.T) {
	v, server := directoryFixture(t)
	profile, err := v.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	// Forge an authenticated unchanged vault without any KDF, exactly like the
	// private handoff-guard tests.
	v.unlocked = new(keyfile.Unlocked)
	v.RemoteMCP = mcpdirectory.New()
	remote, err := v.RemoteMCP.AddServer("remote", "https://capture.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	keyed, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "keyed", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-mid-construction")}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v.RemoteMCP.CurrentBinding(keyed)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v.payloadHash = sha256.Sum256(payload)
	clear(payload)
	encoded := []byte("authenticated ciphertext under test")
	digest := sha256.Sum256(encoded)
	v.revision = digest
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := sessionTestContext(t)
	replaced := false
	capture, err := v.remoteMCPCapture(ctx, path, digest, profile, []mcpdirectory.Binding{binding}, func() {
		replaced = true
		if err := os.WriteFile(path, []byte("replaced during construction"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	if !replaced || capture != nil || err != mcpgrant.ErrGrant {
		t.Fatal("mid-construction origin change was not refused")
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	clean, err := v.remoteMCPCapture(ctx, path, digest, profile, []mcpdirectory.Binding{binding}, nil)
	if err != nil || clean == nil {
		t.Fatal("restored origin did not admit a capture")
	}
	if err := clean.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
