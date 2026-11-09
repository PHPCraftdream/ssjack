package ownercommands

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type backend struct {
	*ownerdb.Manager
	mu              sync.Mutex
	state           *vault.Vault
	metadata        vault.DirectoryMetadata
	status          ownerdb.Status
	imports         ownerdb.ImportStatus
	changes         []vault.OwnerChange
	exports         []ownerdb.ExportRequest
	calls           []string
	flushErr        error
	flushes         int
	partial         bool
	linkedDirectory string
	linkedMaster    []byte
	archivePath     string
	archivePassword []byte
}

func fixture(t *testing.T) *backend {
	t.Helper()
	public, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	server, alias := strings.Repeat("01", 16), strings.Repeat("02", 16)
	reference, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(reference)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.NewDirectory()
	v.Targets["production"] = vault.Target{Address: "example.invalid:22", User: "operator", Password: []byte("synthetic-existing-password"), HostKeys: []string{pin}, Usage: "both"}
	v.Servers[server] = vault.Server{Name: "production", Accounts: map[string]string{"main": "production"}}
	v.Secrets[alias] = vault.SecretBinding{Name: "token", Ref: string(encoded)}
	v.RemoteMCP = mcpdirectory.New()
	mcpServer, mcpAccount := strings.Repeat("03", 16), strings.Repeat("04", 16)
	v.RemoteMCP.Servers[mcpServer] = mcpdirectory.Server{Name: "docs", URL: "https://docs.invalid/mcp", Enabled: true, Revision: 1}
	v.RemoteMCP.Accounts[mcpAccount] = mcpdirectory.Account{ServerID: mcpServer, Name: "work", Enabled: true, Revision: 1, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-existing-mcp-token")}}
	t.Cleanup(v.Close)
	return &backend{state: v, metadata: vault.DirectoryMetadata{
		Servers:   []vault.ServerMetadata{{ID: server, Name: "production", Address: "example.invalid:22", Accounts: []vault.AccountMetadata{{Name: "main", User: "operator", Authentication: "password", Usage: "both"}}}},
		Secrets:   map[string]vault.SecretBinding{alias: v.Secrets[alias]},
		RemoteMCP: v.RemoteMCP.Metadata(),
	}}
}

func (b *backend) Metadata() (vault.DirectoryMetadata, error) { return b.metadata, nil }
func (b *backend) Status() ownerdb.Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}
func (b *backend) ImportStatus() ownerdb.ImportStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.imports
}
func (b *backend) Edit(edit func(*vault.Vault) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return edit(b.state)
}
func (b *backend) Submit(change vault.OwnerChange) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	change.Value = append([]byte(nil), change.Value...)
	b.changes = append(b.changes, change)
	return nil
}
func (b *backend) Export(request ownerdb.ExportRequest) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exports = append(b.exports, request)
	return nil
}
func (b *backend) Flush(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushes++
	return b.flushErr
}
func (b *backend) Close(context.Context) error { return nil }
func (b *backend) record(action string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, action)
	return nil
}
func (b *backend) Link(directory string, master []byte) error {
	b.mu.Lock()
	b.linkedDirectory, b.linkedMaster = directory, append([]byte(nil), master...)
	b.mu.Unlock()
	return b.record("link")
}
func (b *backend) RetryDatabase() error { return b.record("retry-db") }
func (b *backend) Reconcile() error     { return b.record("reconcile") }
func (b *backend) ResumeDraft() error   { return b.record("resume-draft") }
func (b *backend) CancelDraft() error   { return b.record("cancel-draft") }
func (b *backend) ResumeImport() error  { return b.record("resume-import") }
func (b *backend) AbortImport() error   { return b.record("abort-import") }
func (b *backend) InspectImport(path string, password []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.archivePath, b.archivePassword = path, append([]byte(nil), password...)
	b.calls = append(b.calls, "inspect")
	b.imports = ownerdb.ImportStatus{Phase: ownerdb.ImportStaged}
	return nil
}
func (b *backend) ConfirmImport() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, "confirm")
	b.imports = ownerdb.ImportStatus{Phase: ownerdb.ImportComplete}
	if b.partial {
		b.imports.Phase = ownerdb.ImportPartial
	}
	return nil
}

var syntheticFailure = errors.New("synthetic-private-error")
