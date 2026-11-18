package core_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/recovery"
	sessionpkg "github.com/PHPCraftdream/ssjack/internal/vault/internal/session"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
)

func TestSessionAdoptionRequiresAuthenticatedState(t *testing.T) {
	v, _ := vaulttest.DirectoryFixture(t)
	private := v.Targets["production"].PrivateKey
	if _, err := sessionpkg.StartSession(context.Background(), "missing", v); err == nil {
		t.Fatal("unauthenticated vault was accepted as saved session state")
	}
	for _, value := range private {
		if value != 0 {
			t.Fatal("failed ownership transfer did not clear credentials")
		}
	}
}

func TestSessionAdoptionRejectsEditsBeforeHandoff(t *testing.T) {
	v, server := vaulttest.DirectoryFixture(t)
	// Test only the private handoff guard; no KDF or usable unlock is created.
	core.ForgeAuthenticated(t, v)
	if err := v.RenameServer(server, "edited-before-handoff"); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionpkg.StartSession(context.Background(), "missing", v); err == nil || !strings.Contains(err.Error(), "edited before") {
		t.Fatal("edited memory state was reported as an already saved session")
	}
}

func TestSessionAdoptionRejectsStaleCiphertext(t *testing.T) {
	v, _ := vaulttest.DirectoryFixture(t)
	core.ForgeAuthenticated(t, v)
	core.ForgeRevision(v, sha256.Sum256([]byte("previous authenticated ciphertext")))
	path := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(path, []byte("newer ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionpkg.StartSession(context.Background(), path, v); err == nil || !strings.Contains(err.Error(), "changed before") {
		t.Fatal("stale loaded vault was accepted as current session state")
	}
	encoded, err := os.ReadFile(path)
	if err != nil || string(encoded) != "newer ciphertext" {
		t.Fatal("failed session adoption rewrote the encrypted database")
	}
}

func TestVaultUpgradeFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
	path := filepath.Join(t.TempDir(), "legacy")
	password := []byte("production upgrade fixture secret")
	v := core.New()
	defer v.Close()
	v.Targets["main"] = vaulttest.Target(t)
	plaintext, err := core.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	legacy, err := keyfile.SealVersion(plaintext, password, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(path, legacy, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if err := core.SaveUnlocked(context.Background(), path, loaded); err != nil {
		t.Fatal(err)
	}
	legacy, err = store.ReadEncoded(path)
	if err != nil {
		t.Fatal(err)
	}
	if version, err := keyfile.Format(legacy); err != nil || version != 1 {
		t.Fatal("ordinary save silently upgraded v1")
	}
	oldBackup := filepath.Join(filepath.Dir(path), "v1-backup")
	if err := recovery.Backup(context.Background(), path, oldBackup, password); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(oldBackup); err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("backup rewrote v1 bytes")
	}
	if _, err := recovery.PrepareUpgrade(context.Background(), path, []byte("wrong")); err == nil {
		t.Fatal("wrong secret accepted")
	}
	plan, err := recovery.PrepareUpgrade(context.Background(), path, password)
	if err != nil || !plan.Needed() {
		t.Fatalf("prepare upgrade: %v", err)
	}
	backup, err := plan.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(backup); err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("original v1 not preserved exactly")
	}
	upgraded, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if core.FormatOf(upgraded) != 2 || !bytes.Equal(upgraded.Targets["main"].PrivateKey, loaded.Targets["main"].PrivateKey) {
		t.Fatal("upgrade changed format or SSH identity")
	}
	again, err := recovery.PrepareUpgrade(context.Background(), path, password)
	if err != nil || again.Needed() {
		t.Fatalf("idempotent prepare: %v", err)
	}
	if _, err := again.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Restore(context.Background(), path, oldBackup, password, password); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ReadEncoded(path); err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("rollback did not restore exact v1 bytes")
	}
}

func TestVaultDirectoryFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in its dedicated GitHub CI job")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "directory")
	password := []byte("synthetic directory fixture")
	defer clear(password)
	v, server := vaulttest.DirectoryFixture(t)
	v.RemoteMCP = mcpdirectory.New()
	remote, err := v.RemoteMCP.AddServer("docs", "https://docs.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account, err := v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: remote, Name: "work", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-full-profile-MCP-secret")}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v.RemoteMCP.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RememberRemoteMCP(server, "main", []mcpdirectory.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	other := record.OwnTarget(v.Targets["production"])
	defer clear(other.PrivateKey)
	other.User, other.Usage = "another-user", "human"
	if _, err := v.AddServer("same-endpoint", "main", other); err != nil {
		t.Fatal(err)
	}
	if err := core.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	if invalid, err := core.Load(path, []byte("wrong password")); err == nil {
		invalid.Close()
		t.Fatal("directory accepted a wrong database password")
	}
	loaded, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Version != 2 || core.FormatOf(loaded) != 2 || len(loaded.Servers) != 2 || !reflect.DeepEqual(v.Targets, loaded.Targets) || !reflect.DeepEqual(v.Servers, loaded.Servers) || !reflect.DeepEqual(v.RemoteMCP, loaded.RemoteMCP) {
		t.Fatal("directory lost credentials, metadata or container format")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("synthetic-full-profile-MCP-secret")) || bytes.Contains(encoded, []byte("https://docs.invalid/mcp")) {
		t.Fatal("remote MCP directory persisted plaintext data")
	}
	for _, target := range v.Targets {
		if bytes.Contains(encoded, target.PrivateKey) || bytes.Contains(encoded, []byte(target.Address)) {
			t.Fatal("directory persisted plaintext credentials")
		}
	}
	verifySessionFullProfile(t, path, password, server)
}

func verifySessionFullProfile(t *testing.T, path string, password []byte, server string) {
	t.Helper()
	ctx := context.Background()
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sessionpkg.OpenSession(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Discard()
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, original) {
		t.Fatal("opening the owner session rewrote the database")
	}
	digest, err := session.SavedCipherDigest()
	if err != nil || digest != sha256.Sum256(original) {
		t.Fatal("session handoff changed or misidentified the loaded ciphertext")
	}
	for _, name := range []string{"first-save", "second-save"} {
		if err := session.Apply(func(v *core.Vault) error { return v.RenameServer(server, name) }); err != nil {
			t.Fatal(err)
		}
		if err := session.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := session.SavedCipherDigest()
		if err != nil || digest != sha256.Sum256(encoded) {
			t.Fatal("saved session revision did not identify the actual ciphertext")
		}
	}
	verifyOwnerExportFullProfile(t, session, password, server, path)
	if err := session.Close(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Version != 2 || core.FormatOf(loaded) != 2 || loaded.Servers[server].Name != "second-save" || len(loaded.Targets) != 2 {
		t.Fatal("background encrypted saves lost the latest revision or credentials")
	}
	verifyPasswordBindingFullProfile(t, path, password, loaded, server)
}

func verifyPasswordBindingFullProfile(t *testing.T, path string, password []byte, v *core.Vault, server string) {
	t.Helper()
	target := v.Targets["production"]
	target.PrivateKey, target.Password, target.User = nil, []byte("synthetic SSH password"), "password-user"
	defer clear(target.Password)
	if err := v.SetAccount(server, "password", target); err != nil {
		t.Fatal(err)
	}
	profile, err := v.AccountProfile(server, "password")
	if err != nil {
		t.Fatal(err)
	}
	before, err := v.PasswordCredentialIdentity(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.SaveUnlocked(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
	reopened, err := core.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.PasswordCredentialIdentity(profile)
	if err != nil || before != after {
		t.Fatal("password grant binding changed after encrypted reopen")
	}
	target.Password = []byte("changed synthetic SSH password")
	defer clear(target.Password)
	if err := reopened.SetAccount(server, "password", target); err != nil {
		t.Fatal(err)
	}
	changed, err := reopened.PasswordCredentialIdentity(profile)
	if err != nil || changed == before {
		t.Fatal("password change retained the old grant binding")
	}
}

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
	v, err := core.NewUnlocked(password)
	if err != nil {
		t.Fatal(err)
	}
	target := vaulttest.Target(t)
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
	if err := core.CreateUnlocked(ctx, path, v); err != nil {
		v.Close()
		t.Fatal(err)
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		v.Close()
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if digest != core.RevisionOf(v) {
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
	session, err := sessionpkg.StartSession(ctx, path, v)
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

func verifyOwnerExportFullProfile(t *testing.T, session *sessionpkg.Session, password []byte, server, source string) {
	t.Helper()
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := session.PrepareOwnerExport(sessionpkg.ExportSelection{Servers: map[string][]string{server: {"main"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	path := filepath.Join(t.TempDir(), "encrypted-owner.zip")
	if err := plan.WriteEncrypted(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("export rewrote its authenticated source database")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 2 {
		t.Fatal("credential-only archive has an unexpected inventory")
	}
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == "manifest.json.ktav" {
			if _, err := keyfile.Open(encoded, []byte("wrong synthetic export password")); err == nil {
				t.Fatal("encrypted export accepted the wrong password")
			}
		}
		plain, err := keyfile.Open(encoded, password)
		if err != nil {
			t.Fatal(err)
		}
		switch entry.Name {
		case "database.ssjack.ktav":
			selected, err := core.Unmarshal(plain)
			clear(plain)
			if err != nil {
				t.Fatal(err)
			}
			if len(selected.Targets) != 1 || len(selected.Servers) != 1 || len(selected.Secrets) != 0 || selected.OwnerStore != nil || selected.Servers[server].Name != "second-save" || len(selected.Targets["production"].PrivateKey) == 0 {
				selected.Close()
				t.Fatal("encrypted export lost its exact selected directory")
			}
			selected.Close()
		case "manifest.json.ktav":
			var index struct {
				Format   string `json:"format"`
				Database struct {
					Name string `json:"name"`
				} `json:"database"`
			}
			err := json.Unmarshal(plain, &index)
			clear(plain)
			if err != nil || index.Format != "ssjack-owner-export-v1" || index.Database.Name != "database.ssjack.ktav" {
				t.Fatal("encrypted manifest does not identify the selected database")
			}
		default:
			clear(plain)
			t.Fatal("unexpected encrypted export entry")
		}
	}
}
