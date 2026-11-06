package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
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
		arguments := []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--destination", archive, "--format", format}
		confirmation := ""
		if format == "plaintext" {
			confirmation = "EXPORT PLAINTEXT"
			nativeArchiveCommand(t, ctx, database, true, arguments, nativeArchiveInput{"Confirmation:", []byte("\x1b")})
			if _, err := os.Lstat(archive); !os.IsNotExist(err) {
				t.Fatal("cancelled native plaintext disclosure created an artifact")
			}
		}
		nativeArchiveCommand(t, ctx, database, false, arguments, nativeArchiveInput{"Confirmation:", nativeArchiveApply(confirmation)})
		verifyNativeArchive(t, ctx, archive, format == "encrypted", server, alias)
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
		nativeArchiveInput{"[Confirm import", []byte("\r")},
		nativeArchiveInput{"Type IMPORT", nativeArchiveApply("IMPORT")})
	imported, err := vault.Load(target, []byte(nativeArchivePassword))
	nativeArchiveMust(t, err)
	defer imported.Close()
	if len(imported.Targets) != 1 || len(imported.Secrets) != 1 || imported.Secrets[alias].ServerID != server || imported.Secrets[alias].Ref == reference || imported.OwnerStore == nil || imported.OwnerStore.StoreID != id {
		t.Fatal("native import lost selection, link scope or fresh publication")
	}
	profile, err := imported.AccountProfile(server, "selected")
	nativeArchiveMust(t, err)
	if !bytes.Equal(imported.Targets[profile].Password, []byte(nativeArchiveCredential)) {
		t.Fatal("native import lost the selected private credential")
	}
	readback := filepath.Join(t.TempDir(), "readback.zip")
	nativeArchiveCommand(t, ctx, target, false, []string{"export", "--scope", "account", "--server", "archive-source", "--account", "selected", "--destination", readback, "--format", "plaintext"}, nativeArchiveInput{"Confirmation:", nativeArchiveApply("EXPORT PLAINTEXT")})
	verifyNativeArchive(t, ctx, readback, false, server, alias)
	if archiveDigest != importDigest(t, archives["encrypted"]) {
		t.Fatal("native import changed its source archive")
	}
	nativeArchiveMust(t, destination.Close(ctx))
	role, err := ownerlocal.Listen(target)
	nativeArchiveMust(t, err)
	nativeArchiveMust(t, role.Close())
}

func verifyNativeArchive(t *testing.T, ctx context.Context, path string, encrypted bool, server, alias string) {
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
}
