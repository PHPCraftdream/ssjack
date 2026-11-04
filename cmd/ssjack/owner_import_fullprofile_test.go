package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const (
	importGlobalValue   = "updated owner fixture value"
	importLocalValue    = "synthetic server-local import value"
	importWrongPassword = "synthetic wrong archive credential"
)

// importFixture describes the two source archives; all data is synthetic.
type importFixture struct {
	server                           string
	encrypted, plaintext             string
	encryptedDigest, plaintextDigest [32]byte
	secrets                          map[string]vault.SecretBinding
	values                           map[string][]byte
	leaks                            []string
}

// ownerImportArchives exports a global and a server-local value as both an
// encrypted and a plaintext archive, then removes the local value again so the
// source keeps the state the later acceptance steps expect.
func ownerImportArchives(t *testing.T, ctx context.Context, manager *ownerdb.Manager, server, alias string) importFixture {
	t.Helper()
	if err := manager.Submit(vault.OwnerChange{Action: "add", Name: "local2", ServerID: server, MediaType: "text/plain", Value: []byte(importLocalValue)}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata := mustMetadata(t, manager)
	fixture := importFixture{server: server, secrets: metadata.Secrets, values: map[string][]byte{alias: []byte(importGlobalValue)}}
	for id, binding := range metadata.Secrets {
		if binding.Name == "local2" && binding.ServerID == server {
			fixture.values[id] = []byte(importLocalValue)
		}
	}
	if len(metadata.Secrets) != 2 || len(fixture.values) != 2 {
		t.Fatal("owner import fixture lost a scoped or global secret")
	}
	selection := vault.ExportSelection{Servers: map[string][]string{server: {"main", "second"}}, GlobalSecrets: true}
	for _, encrypted := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "owner-import-source.zip")
		request := ownerdb.ExportRequest{Selection: selection, Destination: path}
		if !encrypted {
			request.PlaintextConfirmation = "EXPORT PLAINTEXT"
		}
		if err := manager.Export(request); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		if encrypted {
			fixture.encrypted, fixture.encryptedDigest = path, importDigest(t, path)
		} else {
			fixture.plaintext, fixture.plaintextDigest = path, importDigest(t, path)
		}
	}
	for id, binding := range metadata.Secrets {
		if id == alias {
			continue
		}
		if err := manager.Submit(vault.OwnerChange{Action: "remove", AliasID: id, Name: binding.Name, ServerID: binding.ServerID, PreviousReference: binding.Ref}); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

// ownerImportAcceptance runs after the source manager closed, because a linked
// installation admits one owner session at a time. exportPassword is the
// source database password that sealed the encrypted archive. Destination A is
// seeded and uses the message-level model driver (no terminal) for the
// conflict, tamper and wrong-password flows; destination B is truly empty and
// imports through the manager API. The real-terminal proof runs last.
func ownerImportAcceptance(t *testing.T, ctx context.Context, storeDirectory, master string, exportPassword []byte, fixture importFixture, original *vault.Vault) {
	t.Helper()
	fixture.leaks = []string{importGlobalValue, importLocalValue, importWrongPassword, string(exportPassword), "synthetic SSH account password", "PRIVATE KEY"}
	passwordA := []byte("synthetic destination A database password")
	defer clear(passwordA)
	managerA, pathA := openImportDestination(t, ctx, storeDirectory, master, passwordA, "dest-seed-a")
	defer managerA.Discard()
	importEncryptedArchive(t, ctx, managerA, pathA, exportPassword, fixture)
	verifyImportedValues(t, ctx, managerA, fixture)
	requireImportConflicts(t, ctx, managerA, pathA, fixture)
	requireRejectedArchives(t, ctx, managerA, pathA, fixture, exportPassword)
	if err := managerA.Close(ctx); err != nil {
		t.Fatal(err)
	}
	verifyImportedDatabase(t, pathA, passwordA, fixture, original, "dest-seed-a")

	passwordB := []byte("synthetic destination B database password")
	defer clear(passwordB)
	managerB, pathB := openImportDestination(t, ctx, storeDirectory, master, passwordB, "")
	defer managerB.Discard()
	if err := managerB.InspectImport(fixture.plaintext, nil); err != nil {
		t.Fatal(err)
	}
	if err := managerB.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if status := managerB.ImportStatus(); status.Phase != ownerdb.ImportStaged || status.Preview.Encrypted || len(status.Conflicts) != 0 {
		t.Fatal("plaintext archive was not cleanly staged on an empty destination")
	}
	if err := managerB.ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	waitImportComplete(t, ctx, managerB, 2)
	verifyImportedValues(t, ctx, managerB, fixture)
	if err := managerB.Close(ctx); err != nil {
		t.Fatal(err)
	}
	verifyImportedDatabase(t, pathB, passwordB, fixture, original, "")
	if importDigest(t, fixture.plaintext) != fixture.plaintextDigest || importDigest(t, fixture.encrypted) != fixture.encryptedDigest {
		t.Fatal("owner import changed a source archive")
	}
	// Every manager above is closed, so the terminal child may take the store lock.
	ownerImportTerminalAcceptance(t, ctx, storeDirectory, master, exportPassword, fixture, original)
	ownerImportRecovery(t, ctx, storeDirectory, master, fixture, original)
}

// importEncryptedArchive drives the owner model with message-level key and
// paste events (no tea.Program, no terminal): wrong password, cancelled
// preview, then the confirmed import.
func importEncryptedArchive(t *testing.T, ctx context.Context, manager *ownerdb.Manager, database string, password []byte, fixture importFixture) {
	t.Helper()
	driver := newImportDriver(t, ctx, manager)
	before := importBytes(t, database)
	driver.openImport()
	driver.submit(fixture.encrypted, importWrongPassword)
	driver.require("wrong archive password")
	driver.forbid(fixture.leaks)
	requireUntouched(t, manager, database, before, fixture)

	driver.openImport()
	driver.submit(fixture.encrypted, string(password))
	driver.requirePreview("Archive: encrypted", fixture.leaks)
	driver.key(importKeyEsc)
	driver.absent("Import preview")
	requireUntouched(t, manager, database, before, fixture)

	driver.openImport()
	driver.submit(fixture.encrypted, string(password))
	driver.requirePreview("Archive: encrypted", fixture.leaks)
	driver.key(importKeyEnter)
	driver.require("Confirmation")
	driver.submit("IMPORT")
	waitImportComplete(t, ctx, manager, 2)
	driver.refresh()
	driver.require("Import complete")
	driver.forbid(fixture.leaks)
}
