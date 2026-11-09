package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func importBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func importDigest(t *testing.T, path string) [32]byte { return sha256.Sum256(importBytes(t, path)) }

// openImportDestination creates a fresh version 2 database and links it to the
// shared installation. A non-empty seed names one own server that an import must
// preserve; seed "" yields a truly empty destination (no server, no account).
func openImportDestination(t *testing.T, ctx context.Context, storeDirectory, master string, password []byte, seed string) (*ownerdb.Manager, string) {
	t.Helper()
	v := vault.NewDirectory()
	defer v.Close()
	if seed != "" {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(private)
		block, err := ssh.MarshalPrivateKey(private, "synthetic destination seed")
		if err != nil {
			t.Fatal(err)
		}
		pin, err := ssh.NewPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		target := vault.Target{Address: "seed.invalid:22", User: "seed", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(pin))}}
		defer clear(target.PrivateKey)
		if err := v.InitializeDirectory(seed, target); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "destination.ssjack.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	manager, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	linkMaster := []byte(master)
	linkErr := manager.Link(storeDirectory, linkMaster)
	clear(linkMaster)
	if linkErr != nil {
		manager.Discard()
		t.Fatal(linkErr)
	}
	if err := manager.Flush(ctx); err != nil {
		manager.Discard()
		t.Fatal(err)
	}
	return manager, path
}

// requireUntouched proves a refused or cancelled import left no trace.
func requireUntouched(t *testing.T, manager *ownerdb.Manager, database string, before []byte, fixture importFixture) {
	t.Helper()
	if manager.ImportStatus().Phase != ownerdb.ImportIdle {
		t.Fatal("owner import left a staged or running plan")
	}
	if !bytes.Equal(before, importBytes(t, database)) {
		t.Fatal("refused owner import changed the destination database")
	}
	if importDigest(t, fixture.encrypted) != fixture.encryptedDigest || importDigest(t, fixture.plaintext) != fixture.plaintextDigest {
		t.Fatal("owner import changed a source archive")
	}
}

// waitImportComplete relies on Flush returning only when the worker is idle.
func waitImportComplete(t *testing.T, ctx context.Context, manager *ownerdb.Manager, total int) {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		flushErr := manager.Flush(ctx)
		status := manager.ImportStatus()
		// Only phase, counts and booleans are printed: never error text or values.
		diagnostic := fmt.Sprintf("attempt=%d phase=%q published=%d total=%d expected=%d directory=%v failed=%v flush-failed=%v", attempt, status.Phase, status.Published, status.Total, total, status.DirectoryApplied, status.Err != nil, flushErr != nil)
		if flushErr != nil {
			t.Fatalf("owner import stopped before every value was published: %s", diagnostic)
		}
		switch status.Phase {
		case ownerdb.ImportComplete:
			if status.Published != total || status.Total != total || status.Err != nil || !status.DirectoryApplied {
				t.Fatalf("owner import completed with unexpected counts: %s", diagnostic)
			}
			return
		case ownerdb.ImportPartial:
			t.Fatalf("owner import finished partially: %s", diagnostic)
		}
		if attempt == 4 {
			t.Fatalf("owner import did not complete: %s", diagnostic)
		}
	}
}

// verifyImportedValues reads the destination's values back through a private
// plaintext export, which proves they were published to readable refs.
func verifyImportedValues(t *testing.T, ctx context.Context, manager *ownerdb.Manager, fixture importFixture) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "destination-export.zip")
	selection := vault.ExportSelection{Servers: map[string][]string{fixture.server: {"main", "second"}}, GlobalSecrets: true}
	if err := manager.Export(ownerdb.ExportRequest{Selection: selection, Destination: path, PlaintextConfirmation: "EXPORT PLAINTEXT"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	opened, err := ownerarchive.ReadFile(ctx, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if opened.Encrypted() || len(opened.SecretIDs()) != len(fixture.values) {
		t.Fatal("destination export has an unexpected value inventory")
	}
	for id, want := range fixture.values {
		if got, exists := opened.Value(id); !exists || !bytes.Equal(got, want) {
			t.Fatal("imported value differs from the exported value")
		}
	}
}

// requireImportConflicts shows that an archive already imported is refused
// whole: no overwrite, no merge, no change.
func requireImportConflicts(t *testing.T, ctx context.Context, manager *ownerdb.Manager, database string, fixture importFixture) {
	t.Helper()
	before, metadata := importBytes(t, database), mustMetadata(t, manager)
	if err := manager.InspectImport(fixture.plaintext, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	status := manager.ImportStatus()
	if status.Phase != ownerdb.ImportStaged || status.Err != nil {
		t.Fatal("plaintext archive was not staged for conflict evaluation")
	}
	kinds := make(map[string]bool)
	for _, conflict := range status.Conflicts {
		kinds[conflict.Kind] = true
	}
	for _, kind := range []string{vault.ConflictServerID, vault.ConflictServerName, vault.ConflictAccountID, vault.ConflictSecretID, vault.ConflictSecretName} {
		if !kinds[kind] {
			t.Fatalf("owner import did not report a %s conflict", kind)
		}
	}
	if err := manager.ConfirmImport(); !errors.Is(err, vault.ErrImportConflict) {
		t.Fatal("owner import confirmed despite conflicts")
	}
	if err := manager.AbortImport(); err != nil {
		t.Fatal(err)
	}
	requireUntouched(t, manager, database, before, fixture)
	if !reflect.DeepEqual(metadata, mustMetadata(t, manager)) {
		t.Fatal("refused owner import changed destination metadata")
	}
}

func mustMetadata(t *testing.T, manager *ownerdb.Manager) vault.DirectoryMetadata {
	t.Helper()
	metadata, err := manager.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func sameTarget(a, b vault.Target) bool {
	return a.Address == b.Address && a.User == b.User && a.Usage == b.Usage && bytes.Equal(a.PrivateKey, b.PrivateKey) && bytes.Equal(a.Password, b.Password) && slices.Equal(a.HostKeys, b.HostKeys)
}

// verifyImportedDatabase reloads the closed destination with its own password.
// An empty seed means the destination started empty, so exactly the imported
// server and its credentials may exist.
func verifyImportedDatabase(t *testing.T, path string, password []byte, fixture importFixture, original *vault.Vault, seed string) {
	t.Helper()
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	source, imported := original.Servers[fixture.server], loaded.Servers[fixture.server]
	servers, targets := 2, 3
	if seed == "" {
		servers, targets = 1, 2
	}
	if imported.Name != source.Name || len(source.Accounts) != 2 || len(imported.Accounts) != 2 || len(loaded.Servers) != servers || len(loaded.Targets) != targets {
		t.Fatal("owner import changed the server directory")
	}
	if seed != "" {
		if _, err := loaded.ServerID(seed); err != nil {
			t.Fatal("owner import lost the destination's own server")
		}
	}
	for name, profile := range source.Accounts {
		if imported.Accounts[name] != profile || !sameTarget(original.Targets[profile], loaded.Targets[profile]) {
			t.Fatal("owner import changed an account identity or credential")
		}
	}
	link := loaded.OwnerStore
	if link == nil || link.Pending != nil || len(loaded.Secrets) != len(fixture.secrets) {
		t.Fatal("owner import left the owner link unusable or incomplete")
	}
	for id, want := range fixture.secrets {
		got, exists := loaded.Secrets[id]
		if !exists || got.Name != want.Name || got.ServerID != want.ServerID || got.Ref == want.Ref {
			t.Fatal("owner import lost an alias identity, scope or fresh reference")
		}
		fresh, freshErr := appstoreplaceholder.Parse([]byte(got.Ref))
		old, oldErr := appstoreplaceholder.Parse([]byte(want.Ref))
		if freshErr != nil || oldErr != nil {
			t.Fatal("owner import stored an invalid reference")
		}
		store, object, oldObject := fresh.StoreID(), fresh.ObjectID(), old.ObjectID()
		if hex.EncodeToString(store[:]) != link.StoreID || object == oldObject {
			t.Fatal("owner import reused an archived reference or the wrong store")
		}
	}
}
