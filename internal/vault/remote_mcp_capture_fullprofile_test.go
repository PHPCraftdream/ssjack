package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

// TestVaultRemoteMCPCaptureFullProfile drives the pre-adoption capture entry against
// a real encrypted database: authentic current ciphertext origin, replaced-file
// refusal, and capture independence across adoption and session close. The
// production KDF profile runs only in its dedicated GitHub CI job.
func TestVaultRemoteMCPCaptureFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	path := filepath.Join(t.TempDir(), "mcp-capture.ssjack.ktav")
	password := []byte("production capture fixture secret")
	v, err := NewUnlocked(password)
	if err != nil {
		t.Fatal(err)
	}
	target := testTarget(t)
	if err := v.InitializeDirectory("production", target); err != nil {
		v.Close()
		t.Fatal(err)
	}
	v.RemoteMCP = mcpdirectory.New()
	remote, err := v.RemoteMCP.AddServer("remote", "https://capture.example.org/mcp")
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	keyed, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "keyed", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-capture-secret")}})
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	binding, err := v.RemoteMCP.CurrentBinding(keyed)
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := CreateUnlocked(ctx, path, v); err != nil {
		v.Close()
		t.Fatal(err)
	}
	encoded, err := readEncoded(path)
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if digest != v.revision {
		v.Close()
		t.Fatal("committed ciphertext origin did not match the retained vault revision")
	}
	capture, err := v.RemoteMCPCapture(ctx, path, digest, "production", []mcpdirectory.Binding{binding})
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	// A replaced database file refuses instead of adopting foreign credentials.
	if err := os.WriteFile(path, []byte("replaced ciphertext"), 0600); err != nil {
		v.Close()
		t.Fatal(err)
	}
	if again, err := v.RemoteMCPCapture(ctx, path, digest, "production", []mcpdirectory.Binding{binding}); again != nil || err == nil {
		v.Close()
		t.Fatal("replaced ciphertext admitted a capture")
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		v.Close()
		t.Fatal(err)
	}
	restored, err := v.RemoteMCPCapture(ctx, path, digest, "production", []mcpdirectory.Binding{binding})
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	// Adoption transfers vault ownership; the capture keeps its own retained
	// context and stays issuable for the fresh revision-zero session.
	session, err := StartSession(ctx, path, v)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := capture.Issue(ctx, "production", 0, []mcpdirectory.Binding{binding})
	if err != nil {
		session.Discard()
		t.Fatal(err)
	}
	guard, err := launch.Guard()
	if err != nil {
		session.Discard()
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(guard, &output)
	if err != nil {
		session.Discard()
		t.Fatal(err)
	}
	for _, value := range []byte("Bearer synthetic-capture-secret") {
		if _, err := writer.Write([]byte{value}); err != nil {
			session.Discard()
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || output.String() != outputguard.Marker {
		session.Discard()
		t.Fatal("captured guard lost the transmitted authentication literal")
	}
	if err := launch.Close(ctx); err != nil {
		session.Discard()
		t.Fatal(err)
	}
	if err := session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// An independent capture survives adoption and session close.
	late, err := restored.Issue(ctx, "production", 0, []mcpdirectory.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	if err := late.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restored.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := capture.Issue(ctx, "production", 0, []mcpdirectory.Binding{binding}); err == nil {
		t.Fatal("consumed capture reissued")
	}
}
