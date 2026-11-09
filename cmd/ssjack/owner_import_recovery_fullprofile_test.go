package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// ownerImportRecovery drives real partial imports on seeded destinations. A
// read-only database directory makes every durable save fail (the lock file
// and the temp file both need to be created there), while reads keep working.
func ownerImportRecovery(t *testing.T, ctx context.Context, storeDirectory, master string, fixture importFixture, original *vault.Vault) {
	t.Helper()
	recoveryAbort(t, ctx, storeDirectory, master, fixture)
	recoveryResume(t, ctx, storeDirectory, master, fixture, original)
	if importDigest(t, fixture.plaintext) != fixture.plaintextDigest || importDigest(t, fixture.encrypted) != fixture.encryptedDigest {
		t.Fatal("owner import recovery changed a source archive")
	}
}

// faultOn must prove the fault is real: root ignores directory permissions.
func faultOn(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if probe, err := os.CreateTemp(dir, "probe"); err == nil {
		name := probe.Name()
		probe.Close()
		os.Remove(name)
		t.Fatal("fault injection unavailable")
	}
}

func faultOff(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func recoveryStage(t *testing.T, ctx context.Context, manager *ownerdb.Manager, fixture importFixture) {
	t.Helper()
	if err := manager.InspectImport(fixture.plaintext, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if status := manager.ImportStatus(); status.Phase != ownerdb.ImportStaged || status.Err != nil || len(status.Conflicts) != 0 {
		t.Fatal("plaintext archive was not cleanly staged on a seeded destination")
	}
}

// recoveryPartial asserts a failed import is reported as partial, never as
// complete. published < 0 leaves the exact receipt count unchecked.
func recoveryPartial(t *testing.T, manager *ownerdb.Manager, published int) {
	t.Helper()
	status := manager.ImportStatus()
	if status.Phase != ownerdb.ImportPartial || !status.DirectoryApplied || status.Total != 2 || status.Err == nil {
		t.Fatalf("failed owner import was not reported as partial: phase=%q published=%d total=%d directory=%v failed=%v", status.Phase, status.Published, status.Total, status.DirectoryApplied, status.Err != nil)
	}
	if published >= 0 && status.Published != published {
		t.Fatalf("partial owner import reported an unexpected published count: published=%d expected=%d total=%d", status.Published, published, status.Total)
	}
}

func recoveryFlushFails(t *testing.T, ctx context.Context, manager *ownerdb.Manager) {
	t.Helper()
	if err := manager.Flush(ctx); err == nil {
		t.Fatal("owner save unexpectedly succeeded under the injected fault")
	}
}

// recoveryRefusals shows a partial import freezes everything it owns: no edit
// closure runs, no value is added, no second import starts, nothing changes.
func recoveryRefusals(t *testing.T, manager *ownerdb.Manager, fixture importFixture, mutate func(*vault.Vault)) {
	t.Helper()
	before := mustMetadata(t, manager)
	called := false
	err := manager.Edit(func(v *vault.Vault) error {
		called = true
		mutate(v)
		return nil
	})
	if !errors.Is(err, ownerdb.ErrPending) || called {
		t.Fatal("partial owner import accepted a conflicting form edit")
	}
	intruder := vault.OwnerChange{Action: "add", Name: "intruder", MediaType: "text/plain", Value: []byte("synthetic intruder value")}
	if err := manager.Submit(intruder); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("partial owner import accepted a secret change")
	}
	if err := manager.InspectImport(fixture.plaintext, nil); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("partial owner import accepted a second inspection")
	}
	if err := manager.ConfirmImport(); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("partial owner import accepted a second confirmation")
	}
	if !reflect.DeepEqual(before, mustMetadata(t, manager)) {
		t.Fatal("refused change altered destination metadata")
	}
}

// recoverySeedAndServer checks the directory kept both servers and that no
// imported alias exists.
func recoverySeedAndServer(t *testing.T, manager *ownerdb.Manager, fixture importFixture, seed string) vault.DirectoryMetadata {
	t.Helper()
	metadata := mustMetadata(t, manager)
	foundImported, foundSeed := false, false
	for _, server := range metadata.Servers {
		foundImported = foundImported || server.ID == fixture.server
		foundSeed = foundSeed || server.Name == seed
	}
	if len(metadata.Servers) != 2 || !foundImported || !foundSeed {
		t.Fatal("aborted owner import lost the imported or the seed server")
	}
	for id := range fixture.values {
		if _, exists := metadata.Secrets[id]; exists {
			t.Fatal("aborted owner import published a value")
		}
	}
	return metadata
}

func recoveryRenameServer(fixture importFixture) func(*vault.Vault) {
	return func(v *vault.Vault) {
		server := v.Servers[fixture.server]
		server.Name += "-renamed"
		v.Servers[fixture.server] = server
	}
}

func recoveryChangeAccount(fixture importFixture) func(*vault.Vault) {
	return func(v *vault.Vault) {
		profile := v.Servers[fixture.server].Accounts["main"]
		target := v.Targets[profile]
		target.User = "intruder"
		target.Password = []byte("synthetic replacement credential")
		v.Targets[profile] = target
	}
}

// recoveryAbort: a partial import is aborted, the directory stays, no value
// leaks into the database, and the manager is usable again.
func recoveryAbort(t *testing.T, ctx context.Context, storeDirectory, master string, fixture importFixture) {
	t.Helper()
	password := []byte("synthetic recovery D1 database password")
	defer clear(password)
	manager, path := openImportDestination(t, ctx, storeDirectory, master, password, "recovery-seed-d1")
	defer manager.Discard()
	recoveryStage(t, ctx, manager, fixture)
	before := importBytes(t, path)
	dir := filepath.Dir(path)

	faultOn(t, dir)
	if err := manager.ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	recoveryFlushFails(t, ctx, manager)
	recoveryPartial(t, manager, 0)
	if !bytes.Equal(before, importBytes(t, path)) {
		t.Fatal("failed owner import changed the durable database")
	}

	faultOff(t, dir)
	recoveryRefusals(t, manager, fixture, recoveryRenameServer(fixture))
	if err := manager.AbortImport(); err != nil {
		t.Fatal(err)
	}
	if manager.ImportStatus().Phase != ownerdb.ImportIdle {
		t.Fatal("aborted owner import is not idle")
	}
	// The import-owned error may or may not outlive the abort; either path
	// must end in a clean durable state.
	if err := manager.Flush(ctx); err != nil {
		if retryErr := manager.RetryDatabase(); retryErr != nil {
			t.Fatal(retryErr)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	recoverySeedAndServer(t, manager, fixture, "recovery-seed-d1")
	add := vault.OwnerChange{Action: "add", Name: "post-abort", MediaType: "text/plain", Value: []byte("synthetic post-abort value")}
	if err := manager.Submit(add); err != nil {
		t.Fatal("manager refused a secret after the import was aborted")
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	metadata := mustMetadata(t, manager)
	if err := manager.InspectImport(fixture.plaintext, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	kinds := make(map[string]bool)
	for _, conflict := range manager.ImportStatus().Conflicts {
		kinds[conflict.Kind] = true
	}
	if err := manager.ConfirmImport(); !errors.Is(err, vault.ErrImportConflict) || !kinds[vault.ConflictServerID] {
		t.Fatal("re-importing the same archive was not refused by conflicts")
	}
	if err := manager.AbortImport(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(metadata, mustMetadata(t, manager)) {
		t.Fatal("refused re-import changed destination metadata")
	}
}

// recoveryResume: a failed directory save, then a failed value save leaving a
// pending owner intent; explicit draft recovery plus ResumeImport completes.
func recoveryResume(t *testing.T, ctx context.Context, storeDirectory, master string, fixture importFixture, original *vault.Vault) {
	t.Helper()
	password := []byte("synthetic recovery D2 database password")
	defer clear(password)
	manager, path := openImportDestination(t, ctx, storeDirectory, master, password, "recovery-seed-d2")
	defer manager.Discard()
	recoveryStage(t, ctx, manager, fixture)
	before := importBytes(t, path)
	dir := filepath.Dir(path)

	faultOn(t, dir)
	if err := manager.ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	recoveryFlushFails(t, ctx, manager)
	recoveryPartial(t, manager, 0)

	faultOff(t, dir)
	if err := manager.RetryDatabase(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, importBytes(t, path)) {
		t.Fatal("retried save did not make the imported directory durable")
	}
	if manager.ImportStatus().Phase != ownerdb.ImportPartial {
		t.Fatal("owner import claimed completion before any value was published")
	}

	faultOn(t, dir)
	if err := manager.ResumeImport(); err != nil {
		t.Fatal(err)
	}
	recoveryFlushFails(t, ctx, manager)
	recoveryPartial(t, manager, 0)
	if !manager.Status().Pending {
		t.Fatal("failed value save left no pending owner intent")
	}

	faultOff(t, dir)
	if err := manager.ResumeImport(); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("import resumed over an unresolved owner intent")
	}
	recoveryRefusals(t, manager, fixture, recoveryChangeAccount(fixture))

	if err := manager.ResumeDraft(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if manager.Status().Pending {
		t.Fatal("explicit draft recovery left the owner intent pending")
	}
	if manager.ImportStatus().Phase != ownerdb.ImportPartial {
		t.Fatal("owner import claimed completion with one value unpublished")
	}

	if err := manager.ResumeImport(); err != nil {
		t.Fatal(err)
	}
	waitImportComplete(t, ctx, manager, 2)
	verifyImportedValues(t, ctx, manager, fixture)
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	verifyImportedDatabase(t, path, password, fixture, original, "recovery-seed-d2")
}
