package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultOwnerArchiveFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production native archive process acceptance is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	store, id := nativeArchiveInstallation(t, ctx)
	control, database, server := nativeArchiveDatabase(t, ctx, store, id, true)
	mcpServerID, mcpAccounts := nativeArchiveMCPSelection(t, control)
	before := importBytes(t, database)
	secretArgs := []string{"add-secret", "--scope", "server", "--server", "archive-source", "--name", "selected-value"}
	nativeArchiveCommand(t, ctx, database, true, secretArgs, nativeArchiveInput{"Value:", []byte("\x1b")})
	if !bytes.Equal(before, importBytes(t, database)) {
		t.Fatal("cancelled native value form changed ciphertext")
	}
	nativeArchiveCommand(t, ctx, database, false, secretArgs, nativeArchiveInput{"Value:", nativeArchiveApply(nativeArchiveValue)})
	nativeArchiveCommand(t, ctx, database, false, []string{"add-secret", "--scope", "global", "--name", "excluded-value"}, nativeArchiveInput{"Value:", nativeArchiveApply(nativeArchiveExcluded)})
	status := control.Backend().Status()
	if status.Database.Err != nil || status.Database.Revision != status.Database.SavedRevision {
		t.Fatal("native value helper did not update the parent saved state")
	}
	loaded, err := vault.Load(database, []byte(nativeArchivePassword))
	nativeArchiveMust(t, err)
	alias, reference := "", ""
	for key, binding := range loaded.Secrets {
		if binding.ServerID == server {
			alias, reference = key, binding.Ref
		}
	}
	loaded.Close()
	if alias == "" {
		t.Fatal("native value helper did not persist its server scope")
	}
	beforeExport := importBytes(t, database)
	archives := make(map[string]string)
	for _, format := range []string{"encrypted", "plaintext"} {
		archive := filepath.Join(t.TempDir(), "selected.zip")
		arguments := []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--mcp-accounts", strings.Join([]string{mcpAccounts["public"], mcpAccounts["basic"], mcpAccounts["bearer"]}, ","), "--destination", archive, "--format", format}
		confirmation := ""
		if format == "plaintext" {
			confirmation = "EXPORT PLAINTEXT"
			nativeArchiveCommand(t, ctx, database, true, arguments, nativeArchiveInput{"Confirmation:", []byte("\x1b")})
			if _, err := os.Lstat(archive); !os.IsNotExist(err) {
				t.Fatal("cancelled native plaintext disclosure created an artifact")
			}
		}
		nativeArchiveCommand(t, ctx, database, false, arguments, nativeArchiveInput{"Confirmation:", nativeArchiveApply(confirmation)})
		verifyNativeArchive(t, ctx, archive, format == "encrypted", server, alias, mcpServerID, mcpAccounts)
		archives[format] = archive
	}
	if !bytes.Equal(beforeExport, importBytes(t, database)) {
		t.Fatal("native selected export changed its source ciphertext")
	}
	archiveDigest := importDigest(t, archives["encrypted"])
	if _, err := control.Backend().Metadata(); err != nil {
		t.Fatal("native export helper detach closed its coordinator")
	}
	nativeArchiveMust(t, control.Close(ctx))
	destination, target, _ := nativeArchiveDatabase(t, ctx, store, id, false)
	nativeArchiveCommand(t, ctx, target, false, []string{"import", "--file", archives["encrypted"]},
		nativeArchiveInput{"Archive password:", nativeArchiveApply(nativeArchivePassword)},
		nativeArchiveInput{"MCP server \"archive-mcp\"", nil},
		nativeArchiveInput{"MCP account \"basic\"", nil},
		nativeArchiveInput{"[Confirm import", []byte("\r")},
		nativeArchiveInput{"Type IMPORT", nativeArchiveApply("IMPORT")})
	imported, err := vault.Load(target, []byte(nativeArchivePassword))
	nativeArchiveMust(t, err)
	defer imported.Close()
	if len(imported.Targets) != 1 || len(imported.Secrets) != 1 || imported.Secrets[alias].ServerID != server || imported.Secrets[alias].Ref == reference || imported.OwnerStore == nil || imported.OwnerStore.StoreID != id {
		t.Fatal("native import lost selection, link scope or fresh publication")
	}
	verifyNativeMCP(t, imported, mcpServerID, mcpAccounts, true, true)
	profile, err := imported.AccountProfile(server, "selected")
	nativeArchiveMust(t, err)
	if !bytes.Equal(imported.Targets[profile].Password, []byte(nativeArchiveCredential)) {
		t.Fatal("native import lost the selected private credential")
	}
	readback := filepath.Join(t.TempDir(), "readback.zip")
	freshMCPServerID, freshMCPAccounts := nativeArchiveMCPSelection(t, destination)
	nativeArchiveCommand(t, ctx, target, false, []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--destination", readback, "--format", "plaintext"}, nativeArchiveInput{"Confirmation:", []byte("EXPORT PLAINTEXT\t\t\r")})
	verifyNativeArchive(t, ctx, readback, false, server, alias, "", nil)
	beforeMCPOnly := importBytes(t, target)
	mcpOnly := filepath.Join(t.TempDir(), "mcp-only.zip")
	nativeArchiveCommand(t, ctx, target, false, []string{"export", "--scope", "mcp", "--mcp-accounts", strings.Join([]string{freshMCPAccounts["public"], freshMCPAccounts["basic"], freshMCPAccounts["bearer"]}, ","), "--destination", mcpOnly, "--format", "plaintext"}, nativeArchiveInput{"Confirmation:", nativeArchiveApply("EXPORT PLAINTEXT")})
	verifyNativeMCPOnlyArchive(t, ctx, mcpOnly, freshMCPServerID, freshMCPAccounts)
	if !bytes.Equal(beforeMCPOnly, importBytes(t, target)) {
		t.Fatal("native MCP-only export changed its source ciphertext")
	}
	if archiveDigest != importDigest(t, archives["encrypted"]) {
		t.Fatal("native import changed its source archive")
	}
	nativeArchiveMust(t, destination.Close(ctx))
	role, err := ownerlocal.Listen(target)
	nativeArchiveMust(t, err)
	nativeArchiveMust(t, role.Close())
}

func verifyNativeArchive(t *testing.T, ctx context.Context, path string, encrypted bool, server, alias, mcpServerID string, mcpAccounts map[string]string) {
	t.Helper()
	var password []byte
	if encrypted {
		password = []byte(nativeArchivePassword)
		defer clear(password)
	}
	archive, err := ownerarchive.ReadFile(ctx, path, password)
	nativeArchiveMust(t, err)
	defer archive.Close()
	if archive.Encrypted() != encrypted || len(archive.SecretIDs()) != 1 || archive.SecretIDs()[0] != alias {
		t.Fatal("native archive included unselected values or changed encryption mode")
	}
	value, ok := archive.Value(alias)
	if !ok || !bytes.Equal(value, []byte(nativeArchiveValue)) {
		t.Fatal("native archive lost the exact private value")
	}
	defer clear(value)
	data := archive.Database()
	defer clear(data)
	var selected vault.Vault
	nativeArchiveMust(t, pure.LoadsInto(string(data), &selected))
	defer selected.Close()
	if selected.OwnerStore != nil || len(selected.Servers) != 1 || len(selected.Targets) != 1 || len(selected.Secrets) != 1 || len(selected.Servers[server].Accounts) != 1 || selected.Secrets[alias].ServerID != server {
		t.Fatal("native archive included unselected credentials, scopes or master link")
	}
	profile, err := selected.AccountProfile(server, "selected")
	nativeArchiveMust(t, err)
	if !bytes.Equal(selected.Targets[profile].Password, []byte(nativeArchiveCredential)) {
		t.Fatal("native archive changed its selected private credential")
	}
	if mcpServerID == "" {
		if selected.RemoteMCP != nil {
			t.Fatal("native archive included unselected MCP records")
		}
	} else {
		verifyNativeMCP(t, &selected, mcpServerID, mcpAccounts, false, true)
	}
}

func nativeArchiveMCPSelection(t *testing.T, control *ownercontrol.Control) (string, map[string]string) {
	t.Helper()
	metadata, err := control.Backend().Metadata()
	nativeArchiveMust(t, err)
	servers := make(map[string]string, len(metadata.RemoteMCP.Servers))
	for _, server := range metadata.RemoteMCP.Servers {
		servers[server.Name] = server.ID
	}
	accounts := make(map[string]string, len(metadata.RemoteMCP.Accounts))
	for _, account := range metadata.RemoteMCP.Accounts {
		if account.ServerID == servers["archive-mcp"] {
			accounts[account.Name] = account.ID
		}
	}
	if servers["archive-mcp"] == "" || len(accounts) < 3 {
		t.Fatal("native MCP archive fixture metadata is incomplete")
	}
	return servers["archive-mcp"], accounts
}

func verifyNativeMCPOnlyArchive(t *testing.T, ctx context.Context, path, sourceServerID string, sourceIDs map[string]string) {
	t.Helper()
	archive, err := ownerarchive.ReadFile(ctx, path, nil)
	nativeArchiveMust(t, err)
	defer archive.Close()
	if archive.Encrypted() || len(archive.SecretIDs()) != 0 {
		t.Fatal("native MCP-only archive added SSH/application values or changed format")
	}
	data := archive.Database()
	defer clear(data)
	var selected vault.Vault
	nativeArchiveMust(t, pure.LoadsInto(string(data), &selected))
	defer selected.Close()
	if selected.OwnerStore != nil || len(selected.Servers) != 0 || len(selected.Targets) != 0 || len(selected.Secrets) != 0 {
		t.Fatal("native MCP-only archive attached SSH identities or values")
	}
	verifyNativeMCP(t, &selected, sourceServerID, sourceIDs, false, false)
}

func verifyNativeMCP(t *testing.T, selected *vault.Vault, sourceServerID string, sourceIDs map[string]string, freshIDs, expectLast bool) {
	t.Helper()
	if selected.RemoteMCP == nil || len(selected.RemoteMCP.Servers) != 1 || len(selected.RemoteMCP.Accounts) != 3 {
		t.Fatal("native archive did not preserve exactly the selected MCP accounts")
	}
	var serverID string
	for id, server := range selected.RemoteMCP.Servers {
		serverID = id
		if server.Name != "archive-mcp" || server.URL != "https://archive.invalid/mcp" || server.Revision != 1 || (id == sourceServerID) != !freshIDs {
			t.Fatal("native MCP server identity or metadata changed")
		}
	}
	if serverID == "" {
		t.Fatal("native MCP server is missing")
	}
	seen := make(map[string]bool)
	for id, account := range selected.RemoteMCP.Accounts {
		if account.ServerID != serverID || account.Revision != 1 || (id == sourceIDs[account.Name]) != !freshIDs {
			t.Fatal("native MCP account identity or revision changed")
		}
		seen[account.Name] = true
		switch account.Name {
		case "public":
			if account.Auth.Kind != "none" || len(account.Auth.Secret) != 0 || len(account.Headers) != 0 {
				t.Fatal("native public MCP account changed")
			}
		case "basic":
			if account.Auth.Kind != "basic" || account.Auth.Username != "synthetic-mcp-user" || !bytes.Equal(account.Auth.Secret, []byte(nativeArchiveMCPBasic)) || len(account.Headers) != 1 || account.Headers[0].Name != "X-Archive-Key" || !bytes.Equal(account.Headers[0].Value, []byte(nativeArchiveMCPHeader)) {
				t.Fatal("native basic MCP credentials or header changed")
			}
		case "not-selected":
			t.Fatal("native archive included an unselected MCP account")
		case "bearer":
			if account.Auth.Kind != "bearer" || !bytes.Equal(account.Auth.Secret, []byte(nativeArchiveMCPBearer)) || len(account.Headers) != 1 || account.Headers[0].Name != "X-Bearer-Key" || !bytes.Equal(account.Headers[0].Value, []byte(nativeArchiveMCPBearerHeader)) {
				t.Fatal("native bearer MCP credentials or header changed")
			}
		default:
			t.Fatal("native archive included an unselected MCP account")
		}
	}
	if !seen["public"] || !seen["basic"] || !seen["bearer"] {
		t.Fatal("native MCP authentication kind was omitted")
	}
	if expectLast {
		if len(selected.RemoteMCP.Last) != 1 {
			t.Fatal("native archive lost the selected MCP Last context")
		}
		for _, bindings := range selected.RemoteMCP.Last {
			if len(bindings) != 3 {
				t.Fatal("native MCP Last did not close over all selected enabled identities")
			}
			for _, binding := range bindings {
				account, ok := selected.RemoteMCP.Accounts[binding.AccountID]
				if !ok || account.ServerID != binding.ServerID || selected.RemoteMCP.Servers[binding.ServerID].Revision != binding.ServerRevision || account.Revision != binding.AccountRevision {
					t.Fatal("native MCP Last contains an unbound identity")
				}
			}
		}
	} else if len(selected.RemoteMCP.Last) != 0 {
		t.Fatal("native MCP-only selection invented an SSH Last context")
	}
}
