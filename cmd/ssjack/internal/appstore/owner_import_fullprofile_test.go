package appstore_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/terminalmodel"
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

const (
	importKeyTab   = 9
	importKeyEnter = 13
	importKeyEsc   = 27
)

var errManagerApproval = errors.New("approval operations are not part of the import flow")

// managerBackend adds the approval operations, which the import flow never calls, to the manager.
type managerBackend struct{ *ownerdb.Manager }

func (managerBackend) ApproveApplication(ownerpacket.ApprovalChange) error { return errManagerApproval }
func (managerBackend) RevokeApplication(ownerpacket.ApprovalChange) error  { return errManagerApproval }

// importDriver feeds Bubble Tea messages straight into the owner model's
// Update, except secret entry which runs the same model in a short-lived Program.
// Tick commands are never executed, so the model only changes through this driver.
type importDriver struct {
	t     *testing.T
	model *ownertui.Model
}

func newImportDriver(t *testing.T, ctx context.Context, manager *ownerdb.Manager) *importDriver {
	t.Helper()
	d := &importDriver{t: t, model: ownertui.New(ctx, managerBackend{manager})}
	// A tall window keeps every preview row visible.
	d.send(tea.WindowSizeMsg{Width: 200, Height: 100})
	d.refresh()
	return d
}

// refresh delivers one metadata and import-status snapshot.
func (d *importDriver) refresh() { d.send(d.model.Init()()) }
func (d *importDriver) send(msg tea.Msg) tea.Cmd {
	_, cmd := d.model.Update(msg)
	return cmd
}
func (d *importDriver) key(code rune) tea.Cmd { return d.send(tea.KeyPressMsg{Code: code}) }
func (d *importDriver) view() string          { return d.model.View().Content }

func (d *importDriver) secret(value []byte) {
	d.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output := &terminalmodel.Output{}
	release := make(chan struct{})
	d.model.SetSecretReader(func(int) ([]byte, error) {
		<-release
		return append([]byte(nil), value...), nil
	})
	p := tea.NewProgram(terminalmodel.Capture(d.model, output), tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(output), tea.WithWindowSize(200, 100), tea.WithEnvironment([]string{"TERM=dumb"}), tea.WithoutSignalHandler())
	done := make(chan error, 1)
	go func() { _, err := p.Run(); done <- err }()
	stop := func() {
		p.Quit()
		if flakediag.WaitFor(d.t, "temporary import secret-entry Program to stop", 3*time.Second, func() (string, bool) {
			select {
			case err := <-done:
				if err != nil {
					d.t.Errorf("temporary import secret-entry Program returned an error")
				}
				return "stopped", true
			default:
				select {
				case <-ctx.Done():
					return "timeout", true
				default:
					return "running", false
				}
			}
		}) != "stopped" {
			d.t.Fatal("temporary import secret-entry Program did not stop")
		}
	}
	p.Send(tea.KeyPressMsg{Code: importKeyEnter})
	if flakediag.WaitFor(d.t, "import password prompt marker", 3*time.Second, func() (string, bool) {
		matched := strings.Contains(output.Raw(), "Secret (hidden; Enter submits, Esc/Ctrl+C cancels): ")
		return "matched=" + strconv.FormatBool(matched), matched
	}) != "matched=true" {
		close(release)
		p.Quit()
		if flakediag.WaitFor(d.t, "temporary import secret-entry Program to stop", 3*time.Second, func() (string, bool) {
			select {
			case err := <-done:
				if err != nil {
					d.t.Errorf("temporary import secret-entry Program returned an error")
				}
				return "stopped", true
			default:
				if ctx.Err() != nil {
					return "timeout", true
				}
				return "running", false
			}
		}) != "stopped" {
			d.t.Fatal("temporary import secret-entry Program did not stop")
		}
		d.t.Fatal("temporary import secret-entry Program did not render the prompt marker")
	}
	close(release)
	if flakediag.WaitFor(d.t, "import password to render masked completion", 3*time.Second, func() (string, bool) {
		matched := strings.Contains(output.String(), "<hidden; entered>")
		return "masked=" + strconv.FormatBool(matched), matched
	}) != "masked=true" {
		stop()
		d.t.Fatal("temporary import secret-entry Program did not complete")
	}
	stop()
}

// require names only fixed, non-secret fragments, so it may print them.
func (d *importDriver) require(texts ...string) {
	d.t.Helper()
	view := d.view()
	for _, text := range texts {
		if !strings.Contains(view, text) {
			d.t.Fatalf("owner TUI view lacks %q", text)
		}
	}
}
func (d *importDriver) absent(text string) {
	d.t.Helper()
	if strings.Contains(d.view(), text) {
		d.t.Fatalf("owner TUI still shows %q", text)
	}
}

// forbid never prints the offending text: it may be a password or a value.
func (d *importDriver) forbid(secrets []string) {
	d.t.Helper()
	view := d.view()
	for _, secret := range secrets {
		if strings.Contains(view, secret) {
			d.t.Fatal("owner TUI view exposed secret material")
		}
	}
}

// openImport moves to the Import root item and opens its form.
func (d *importDriver) openImport() {
	d.t.Helper()
	const label = "> Import credentials and values"
	for i := 0; i < 40 && !strings.Contains(d.view(), label); i++ {
		d.key(tea.KeyDown)
	}
	d.require(label)
	d.key(importKeyEnter)
	d.require("Archive file", "Archive password")
}

// submit pastes one text per field, then runs [Apply] and delivers its result.
func (d *importDriver) submit(texts ...string) {
	d.t.Helper()
	for _, text := range texts {
		if strings.Contains(d.view(), "> Archive password:") {
			value := []byte(text)
			d.secret(value)
			clear(value)
		} else {
			d.send(tea.PasteMsg{Content: text})
		}
		d.key(importKeyTab)
	}
	cmd := d.key(importKeyEnter)
	if cmd == nil {
		d.t.Fatal("owner TUI form did not start its operation")
	}
	d.send(cmd())
}

// requirePreview checks the staged preview: metadata and scopes, no secrets.
func (d *importDriver) requirePreview(archive string, secrets []string) {
	d.t.Helper()
	d.require("Import preview", archive, `Server "legacy"`,
		`Account "main" / login "first" / "key"`,
		`Account "second" / login "second" / "password"`,
		`Secret "initial" / scope: global`,
		`Secret "local2" / scope: server "legacy"`)
	d.forbid(secrets)
}

// tamperedArchive rewrites the archive with one flipped bit inside a value
// entry. The ZIP checksum stays valid, so only the manifest digest can object.
func tamperedArchive(t *testing.T, source string) string {
	t.Helper()
	reader, err := zip.OpenReader(source)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	flipped := false
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
		if !flipped && strings.HasPrefix(entry.Name, "secrets/") && len(body) > 0 {
			body[len(body)/2] ^= 1
			flipped = true
		}
		target, err := writer.CreateHeader(&zip.FileHeader{Name: entry.Name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || !flipped {
		t.Fatal("could not build a tampered archive")
	}
	path := filepath.Join(t.TempDir(), "tampered.zip")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireRejectedArchives runs damaged inputs through the idle manager.
func requireRejectedArchives(t *testing.T, ctx context.Context, manager *ownerdb.Manager, database string, fixture importFixture, password []byte) {
	t.Helper()
	encoded := importBytes(t, fixture.encrypted)
	dir := t.TempDir()
	truncated, garbage := filepath.Join(dir, "truncated.zip"), filepath.Join(dir, "garbage.zip")
	if err := os.WriteFile(truncated, encoded[:len(encoded)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(garbage, bytes.Repeat([]byte("not a zip archive "), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path     string
		password []byte
		want     error
	}{
		{truncated, nil, ownerarchive.ErrArchive},
		{garbage, nil, ownerarchive.ErrArchive},
		{tamperedArchive(t, fixture.encrypted), password, ownerarchive.ErrAuthentication},
	}
	for _, c := range cases {
		before := importBytes(t, database)
		if err := manager.InspectImport(c.path, c.password); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal("rejected archive poisoned the owner manager")
		}
		if status := manager.ImportStatus(); !errors.Is(status.Err, c.want) {
			t.Fatal("damaged archive failed with an unexpected error class")
		}
		requireUntouched(t, manager, database, before, fixture)
	}
}
