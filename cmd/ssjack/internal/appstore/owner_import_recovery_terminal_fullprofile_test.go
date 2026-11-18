package appstore_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
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

// ownerImportTerminalAcceptance drives the real interactive owner editor in a
// terminal (tmux) against a truly empty destination: wrong archive password,
// cancelled preview, then a confirmed import. The reopened database proves
// the result through the real backend.
func ownerImportTerminalAcceptance(t *testing.T, ctx context.Context, storeDirectory, master string, exportPassword []byte, fixture importFixture, original *vault.Vault) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("owner import terminal acceptance requires the Linux CI fixture")
	}
	password := []byte("synthetic destination C database password")
	defer clear(password)
	manager, path := openImportDestination(t, ctx, storeDirectory, master, password, "")
	defer manager.Discard()
	// Close releases the store lock and persists the link; the child unlocks alone.
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runImportTerminal(t, ctx, path, password, exportPassword, fixture)
	reopened, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Discard()
	verifyTerminalImport(t, ctx, reopened, fixture, original)
	if err := reopened.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if importDigest(t, fixture.plaintext) != fixture.plaintextDigest || importDigest(t, fixture.encrypted) != fixture.encryptedDigest {
		t.Fatal("terminal owner import changed a source archive")
	}
}

// runImportTerminal passes every secret on stdin, never on the command line.
func runImportTerminal(t *testing.T, ctx context.Context, database string, password, exportPassword []byte, fixture importFixture) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_import.py"))
	if err != nil {
		t.Fatal(err)
	}
	var input []byte
	defer func() { clear(input) }()
	for _, line := range append([][]byte{password, []byte(importWrongPassword), exportPassword}, leakLines(fixture.leaks)...) {
		input = append(append(input, line...), '\n')
	}
	command := exec.CommandContext(ctx, "python3", "-I", driver, executable, database, fixture.encrypted)
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	ownerChildExecFail(t, "owner import terminal driver", command, output, err)
	if err != nil {
		t.Fatalf("synthetic owner import terminal interaction: %v: %s", err, output)
	}
	zombie := bytes.Contains(output, []byte("Owned terminal zombie required a SIGCHLD wakeup."))
	barrier := bytes.Contains(output, []byte("Owned terminal exit wakeup followed a stalled completion barrier."))
	if zombie {
		t.Log("synthetic owner import verified an owned zombie wakeup and a real zero exit status")
	}
	if barrier {
		t.Log("synthetic owner import recovered a missed reaping notification after the completion barrier stalled")
	}
	if !zombie || !barrier {
		t.Logf("owner child evidence: zombie-sigchld-marker=%t exit-barrier-marker=%t", zombie, barrier)
	}
}
func leakLines(leaks []string) [][]byte {
	lines := make([][]byte, 0, len(leaks))
	for _, leak := range leaks {
		if leak != "" {
			lines = append(lines, []byte(leak))
		}
	}
	return lines
}

// verifyTerminalImport exports the reopened destination in plaintext, which
// reads every imported value back from its published reference.
func verifyTerminalImport(t *testing.T, ctx context.Context, manager *ownerdb.Manager, fixture importFixture, original *vault.Vault) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "terminal-destination-export.zip")
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
	var selected vault.Vault
	if err := pure.LoadsInto(string(opened.Database()), &selected); err != nil {
		t.Fatal(err)
	}
	defer selected.Close()
	source, imported := original.Servers[fixture.server], selected.Servers[fixture.server]
	if len(selected.Servers) != 1 || len(selected.Targets) != 2 || imported.Name != source.Name || len(imported.Accounts) != 2 {
		t.Fatal("terminal import did not create exactly the imported server")
	}
	for name, profile := range source.Accounts {
		got, exists := imported.Accounts[name]
		if !exists || !sameTarget(original.Targets[profile], selected.Targets[got]) {
			t.Fatal("terminal import changed an account identity or credential")
		}
	}
	if len(selected.Secrets) != len(fixture.secrets) || opened.Encrypted() || len(opened.SecretIDs()) != len(fixture.values) {
		t.Fatal("terminal import has an unexpected secret inventory")
	}
	for id, want := range fixture.secrets {
		got, exists := selected.Secrets[id]
		if !exists || got.Name != want.Name || got.ServerID != want.ServerID || got.Ref == want.Ref {
			t.Fatal("terminal import lost an alias identity, scope or fresh reference")
		}
	}
	for id, want := range fixture.values {
		if value, exists := opened.Value(id); !exists || !bytes.Equal(value, want) {
			t.Fatal("terminal imported value differs from the exported value")
		}
	}
}

func ownerDatabaseAcceptance(t *testing.T, ctx context.Context, storeDirectory, master string, initial appstoreref.Ref) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "synthetic owner fixture")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Close()
	target := vault.Target{Address: "example.invalid:22", User: "first", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(public))}}
	defer clear(target.PrivateKey)
	if err := v.InitializeDirectory("legacy", target); err != nil {
		t.Fatal(err)
	}
	server, err := v.ServerID("legacy")
	if err != nil {
		t.Fatal(err)
	}
	second := v.Targets["legacy"]
	second.PrivateKey, second.Password, second.User = nil, []byte("synthetic SSH account password"), "second"
	defer clear(second.Password)
	if err := v.SetAccount(server, "second", second); err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(initial)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := v.BindSecret("", vault.SecretBinding{Name: "initial", Ref: string(encoded)})
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic owner credential database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "owner.ssjack.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	manager, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Discard()
	ownerAdmissionAcceptance(t, manager, storeDirectory)
	linkMaster := []byte(master)
	linkErr := manager.Link(storeDirectory, linkMaster)
	clear(linkMaster)
	if linkErr != nil {
		t.Fatal(linkErr)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Submit(vault.OwnerChange{Action: "update", AliasID: alias, Name: "initial", PreviousReference: string(encoded), MediaType: "text/plain", Value: []byte("updated owner fixture value")}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata, err := manager.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := appstoreplaceholder.Parse([]byte(metadata.Secrets[alias].Ref))
	if err != nil || updated == initial || updated.ObjectID() != initial.ObjectID() || metadata.OwnerStore.PendingID != "" {
		t.Fatal("owner value update did not finalize an exact new version")
	}
	if err := manager.Submit(vault.OwnerChange{Action: "add", Name: "local", ServerID: server, MediaType: "text/plain", Value: []byte("server-local owner fixture value")}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	metadata, err = manager.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	var localID string
	for id, binding := range metadata.Secrets {
		if binding.Name == "local" && binding.ServerID == server {
			localID = id
		}
	}
	if localID == "" || len(metadata.Secrets) != 2 {
		t.Fatal("owner add lost a scoped or unrelated secret")
	}
	if err := manager.Submit(vault.OwnerChange{Action: "remove", AliasID: localID, Name: "local", ServerID: server, PreviousReference: metadata.Secrets[localID].Ref}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// Archives are made while the source session is open; the import runs after
	// Close because a linked installation admits one owner session at a time.
	archives := ownerImportArchives(t, ctx, manager, server, alias)
	ownerExportAcceptance(t, ctx, manager, path, password, server, alias, v.Targets["legacy"])
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	ownerImportAcceptance(t, ctx, storeDirectory, master, password, archives, v)
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.OwnerStore.Pending != nil || len(loaded.Secrets) != 1 || loaded.Secrets[alias].Name != "initial" || !bytes.Equal(loaded.Targets["legacy"].PrivateKey, v.Targets["legacy"].PrivateKey) || len(loaded.Servers[server].Accounts) != 2 {
		t.Fatal("owner coordination lost credentials, aliases, or durable completion")
	}
	profile, err := loaded.AccountProfile(server, "second")
	if err != nil || !bytes.Equal(loaded.Targets[profile].Password, second.Password) {
		t.Fatal("owner coordination changed the second SSH account's password")
	}
	if _, err := loaded.StageOwnerChange(vault.OwnerChange{Action: "add", Name: "unsubmitted", MediaType: "text/plain", Value: []byte("retained restart draft")}); err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveUnlocked(ctx, path, loaded); err != nil {
		t.Fatal(err)
	}
	restarted, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Discard()
	if status := restarted.Status(); !status.Pending || status.Busy {
		t.Fatal("startup resumed a pending owner draft without an explicit action")
	}
	if err := restarted.CancelDraft(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(ctx); err != nil {
		t.Fatal(err)
	}
	ownerTerminalAcceptance(t, ctx, path, password, v, server)
	ownerConnectionAcceptance(t, ctx, path, password, server)
	ownerCommandAcceptance(t, ctx, path, password, server)
}
func ownerAdmissionAcceptance(t *testing.T, manager *ownerdb.Manager, directory string) {
	t.Helper()
	before, err := manager.Snapshot()
	if err != nil || before.CipherDigest == ([32]byte{}) || before.Status.Database.Pending || before.Status.Database.Revision != before.Status.Database.SavedRevision {
		t.Fatal("initial coordinator snapshot has no consistent saved receipt")
	}
	destination := filepath.Join(t.TempDir(), "not-written.zip")
	archive := filepath.Join(t.TempDir(), "not-read.zip")
	cases := map[string]func(uint64) error{
		"edit": func(revision uint64) error {
			return manager.EditAt(revision, func(*vault.Vault) error { t.Fatal("stale edit callback executed"); return nil })
		},
		"link": func(revision uint64) error {
			return manager.LinkAt(revision, directory, []byte("synthetic-unused-master"))
		},
		"export": func(revision uint64) error {
			return manager.ExportAt(revision, ownerdb.ExportRequest{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: destination})
		},
		"inspect": func(revision uint64) error {
			return manager.InspectImportAt(revision, archive, []byte("synthetic-unused-password"))
		},
		"retry": manager.RetryDatabaseAt,
		"abort": manager.AbortImportAt,
	}
	for action, apply := range cases {
		t.Run("stale-"+action, func(t *testing.T) {
			if err := apply(before.Status.Database.Revision + 1); !errors.Is(err, vault.ErrOwnerRevision) {
				t.Fatal("stale owner command did not refuse before publication")
			}
			after, err := manager.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("stale admission changed metadata, import state, busy state or persistence receipt")
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("stale export touched its destination")
			}
		})
	}
}

func ownerExportAcceptance(t *testing.T, ctx context.Context, manager *ownerdb.Manager, database string, password []byte, server, alias string, original vault.Target) {
	t.Helper()
	before, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	selection := vault.ExportSelection{Servers: map[string][]string{server: {"main", "second"}}, GlobalSecrets: true}
	for _, encrypted := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "owner-export.zip")
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
		verifyOwnerArchive(t, path, password, encrypted, server, alias, original)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Export(request); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err == nil {
			t.Fatal("owner export overwrote an existing artifact")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(encoded, after) {
			t.Fatal("refused export changed an existing artifact")
		}
		if err := manager.RetryDatabase(); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(database)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("owner export changed the source database")
	}
}
func verifyOwnerArchive(t *testing.T, path string, password []byte, encrypted bool, server, alias string, original vault.Target) {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 3 {
		t.Fatal("owner export did not include its exact value inventory")
	}
	foundDatabase, foundValue, foundManifest := false, false, false
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(input, 1024*1024))
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		if encrypted {
			body, err = keyfile.Open(body, password)
			if err != nil {
				t.Fatal(err)
			}
		}
		switch entry.Name {
		case "database.ktav", "database.ssjack.ktav":
			var selected vault.Vault
			err := pure.LoadsInto(string(body), &selected)
			clear(body)
			if err != nil {
				t.Fatal(err)
			}
			main := selected.Servers[server].Accounts["main"]
			second := selected.Servers[server].Accounts["second"]
			if len(selected.Targets) != 2 || selected.OwnerStore != nil || selected.Secrets[alias].Name != "initial" || !bytes.Equal(selected.Targets[main].PrivateKey, original.PrivateKey) || !bytes.Equal(selected.Targets[second].Password, []byte("synthetic SSH account password")) {
				selected.Close()
				t.Fatal("owner export lost credentials, scopes or settings")
			}
			selected.Close()
			foundDatabase = true
		case "secrets/" + alias + ".bin", "secrets/" + alias + ".bin.ktav":
			value := body
			if encrypted {
				if len(value) == 0 || value[0] != 1 {
					clear(body)
					t.Fatal("encrypted value omitted its format frame")
				}
				value = value[1:]
			}
			if !bytes.Equal(value, []byte("updated owner fixture value")) {
				clear(body)
				t.Fatal("export did not collect the actual exact private value")
			}
			clear(body)
			foundValue = true
		case "manifest.json", "manifest.json.ktav":
			var manifest struct {
				Format  string         `json:"format"`
				Secrets map[string]any `json:"secrets"`
			}
			err := json.Unmarshal(body, &manifest)
			clear(body)
			if err != nil || manifest.Format != "ssjack-owner-export-v1" || len(manifest.Secrets) != 1 || manifest.Secrets[alias] == nil {
				t.Fatal("export manifest lost the selected alias inventory")
			}
			foundManifest = true
		default:
			clear(body)
			t.Fatal("owner export included unselected material")
		}
	}
	if !foundDatabase || !foundValue || !foundManifest {
		t.Fatal("owner export was incomplete")
	}
}
