package ownerdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestManagerSnapshotVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	password := []byte("test-password")
	v := vault.NewDirectory()
	if err := vault.CreateWithRecords(context.Background(), path, v, password); err != nil {
		t.Fatal(err)
	}
	m, err := Open(context.Background(), path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Discard()
	backup, err := m.SnapshotVault()
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(copied, current) {
		t.Fatal("manager snapshot differs from persisted ciphertext")
	}
}

func TestCopiedOwnerMaterialIsIndependentlyOwned(t *testing.T) {
	original := &vault.OwnerStore{Directory: "fixture", StoreID: "fixture", Master: []byte("synthetic master"), Pending: &vault.OwnerIntent{ID: "fixture", Versions: map[string]string{"object": "version"}, Change: vault.OwnerChange{Value: []byte("synthetic pending value")}}}
	owned := copyLink(original)
	owned.Pending.Versions["object"] = "changed"
	clearLink(owned)
	if !bytes.Equal(original.Master, []byte("synthetic master")) || !bytes.Equal(original.Pending.Change.Value, []byte("synthetic pending value")) || original.Pending.Versions["object"] != "version" || !bytes.Equal(owned.Master, make([]byte, len(owned.Master))) || !bytes.Equal(owned.Pending.Change.Value, make([]byte, len(owned.Pending.Change.Value))) {
		t.Fatal("coordinator copies borrowed private buffers or version metadata, or did not clear owned private material")
	}
	clearLink(original)
}

func TestExportRequestOwnsItsSelectionAndRejectsConcurrentRequests(t *testing.T) {
	m := &Manager{db: &vault.Session{}, jobs: make(chan string, 1), changed: make(chan struct{})}
	request := ExportRequest{Selection: vault.ExportSelection{Servers: map[string][]string{"server": {"deploy"}}}, Destination: "synthetic-export.zip"}
	if err := m.Export(request); err != nil {
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
			return
		}
		t.Fatal(err)
	}
	request.Selection.Servers["server"][0] = "changed"
	delete(request.Selection.Servers, "server")
	if !m.busy || m.exportRequest == nil || m.exportRequest.Selection.Servers["server"][0] != "deploy" || <-m.jobs != ":export" {
		t.Fatal("queued export borrowed caller scope metadata")
	}
	if err := m.Export(ExportRequest{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "another.zip"}); err == nil || !errors.Is(m.Edit(func(*vault.Vault) error { return nil }), ErrPending) {
		t.Fatal("concurrent export or directory edit bypassed the single owner worker")
	}
	m = &Manager{jobs: make(chan string, 1), changed: make(chan struct{})}
	for _, request := range []ExportRequest{{}, {Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "synthetic.zip", PlaintextConfirmation: "yes"}, {Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "synthetic.zip"}} {
		if err := m.Export(request); err == nil || m.busy || len(m.jobs) != 0 {
			t.Fatal("invalid or unauthenticated export queued work")
		}
	}
}

func TestCipherDigestChecksOnlyBoundedRegularCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database")
	encoded := []byte("synthetic ciphertext fixture")
	writeErr := os.WriteFile(path, encoded, 0600)
	digest, err := cipherDigest(path)
	if writeErr != nil || err != nil || digest != sha256.Sum256(encoded) {
		t.Fatal("ciphertext revision check changed or misidentified bytes")
	}
	_, dirErr := cipherDigest(filepath.Dir(path))
	_, missingErr := cipherDigest(path + "-missing")
	if dirErr == nil || missingErr == nil {
		t.Fatal("ciphertext checker accepted a directory or a missing database")
	}
}
func importManager() *Manager {
	return &Manager{db: &vault.Session{}, jobs: make(chan string, 1), changed: make(chan struct{})}
}
func importRef(store, object, version, snapshot byte) appstoreref.Ref {
	ref, err := appstoreref.New([16]byte{store}, [16]byte{object}, [16]byte{version}, [16]byte{snapshot})
	if err != nil {
		panic("invalid import ref fixture")
	}
	return ref
}
func refText(ref appstoreref.Ref) string {
	raw, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		panic("invalid import ref fixture")
	}
	return string(raw)
}

func TestInspectImportValidatesAndGatesBeforeQueueing(t *testing.T) {
	for _, path := range []string{"", strings.Repeat("a", 4097), "bad\x00path", "bad\npath", "bad\rpath"} {
		m := importManager()
		if err := m.InspectImport(path, nil); err == nil || m.busy || len(m.jobs) != 0 || m.imp.phase != ImportIdle {
			t.Fatal("invalid import path queued work")
		}
	}
	if m := importManager(); m.InspectImport("archive.zip", make([]byte, 16385)) == nil || len(m.jobs) != 0 {
		t.Fatal("oversized import password queued work")
	}
	phase := func(p ImportPhase) func(*Manager) { return func(m *Manager) { m.imp.phase = p } }
	gates := map[string]func(*Manager){"closed": func(m *Manager) { m.closed = true }, "closing": func(m *Manager) { m.closing = true }, "busy": func(m *Manager) { m.busy = true }, "pending": func(m *Manager) { m.pending = &vault.OwnerIntent{} }, "error": func(m *Manager) { m.err = errors.New("fixture") }, "inspect": phase(ImportInspecting), "staged": phase(ImportStaged), "applying": phase(ImportApplying), "partial": phase(ImportPartial), "no-worker": func(m *Manager) { m.jobs = nil }}
	for name, gate := range gates {
		m := importManager()
		gate(m)
		if err := m.InspectImport("archive.zip", []byte("pw")); !errors.Is(err, ErrPending) || m.imp.password != nil || (m.jobs != nil && len(m.jobs) != 0) || (activeImportPhase(m.imp.phase) && (!errors.Is(m.rotationAdmission(false), ErrPending) || !errors.Is(m.rotationAdmission(true), ErrPending))) {
			t.Fatalf("inspection was not refused while %s", name)
		}
	}
}

func TestInspectImportOwnsPasswordAndReplacesCompleteImport(t *testing.T) {
	m := importManager()
	m.imp.phase, m.imp.staged, m.imp.effects = ImportComplete, new(vault.OwnerImport), true
	password := []byte("synthetic password")
	err := m.InspectImport("archive.zip", password)
	clear(password)
	if err != nil || !bytes.Equal(m.imp.password, []byte("synthetic password")) || !m.busy || m.imp.phase != ImportInspecting || m.imp.staged != nil || m.imp.effects || <-m.jobs != ":import-inspect" || !errors.Is(m.InspectImport("other.zip", nil), ErrPending) {
		t.Fatal("inspection did not take a private copy, reset the previous import or hold the busy worker")
	}
	m = importManager()
	m.imp.phase, m.imp.aborted, m.imp.password = ImportInspecting, true, []byte("synthetic password")
	held := m.imp.password
	err = m.inspectImport(context.Background())
	if err != nil || m.imp.phase != ImportIdle || !errors.Is(m.imp.err, ErrImportAborted) || m.imp.password != nil || !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("failed inspection left state, password material or a manager error behind")
	}
}

func TestImportPhaseGatingForConfirmResumeAbort(t *testing.T) {
	refuse := func(name string, run func(*Manager) error, phases ...ImportPhase) {
		for _, phase := range phases {
			m := importManager()
			m.imp.phase, m.imp.staged = phase, new(vault.OwnerImport)
			if err := run(m); !errors.Is(err, ErrPending) || m.busy || len(m.jobs) != 0 {
				t.Fatalf("%s ran in phase %q", name, phase)
			}
		}
	}
	refuse("confirm", (*Manager).ConfirmImport, ImportIdle, ImportInspecting, ImportApplying, ImportPartial, ImportComplete)
	refuse("resume", (*Manager).ResumeImport, ImportIdle, ImportInspecting, ImportStaged, ImportApplying, ImportComplete)
	m := importManager()
	m.imp.phase, m.imp.staged, m.pending = ImportPartial, new(vault.OwnerImport), &vault.OwnerIntent{}
	if err := m.ResumeImport(); !errors.Is(err, ErrPending) || len(m.jobs) != 0 {
		t.Fatal("resume ignored an unresolved owner intent")
	}
	m = importManager()
	m.imp.phase, m.imp.staged = ImportStaged, new(vault.OwnerImport)
	if err := m.ConfirmImport(); err == nil || m.busy || len(m.jobs) != 0 || m.imp.phase != ImportStaged {
		t.Fatal("confirm queued without an evaluated conflict-free destination")
	}
	m.db = nil
	if status := m.ImportStatus(); len(status.Conflicts) == 0 || status.Phase != ImportStaged {
		t.Fatal("unevaluable destination was reported as conflict-free")
	}
	m = importManager()
	m.imp.phase, m.imp.staged, m.err = ImportPartial, new(vault.OwnerImport), errors.New("fixture")
	if err := m.ResumeImport(); err != nil || !m.busy || m.imp.phase != ImportApplying || <-m.jobs != ":import-resume" {
		t.Fatal("resume was not queued from a partial import with a manager error")
	}
}

func TestAbortImportSemanticsPerPhase(t *testing.T) {
	idle := importManager().AbortImport()
	for _, phase := range []ImportPhase{ImportStaged, ImportComplete, ImportPartial} {
		m := importManager()
		m.imp.phase, m.imp.staged, m.imp.password, m.imp.effects = phase, new(vault.OwnerImport), []byte("pw"), true
		if err := m.AbortImportAt(1); !errors.Is(err, vault.ErrOwnerRevision) || m.imp.phase != phase || m.imp.staged == nil || m.AbortImportAt(0) != nil || m.imp.phase != ImportIdle || m.imp.staged != nil || m.imp.password != nil || m.imp.effects {
			t.Fatalf("revision-scoped abort did not preserve stale or discard current phase %q", phase)
		}
		m.imp.phase, m.busy = phase, true
		if err := m.AbortImport(); !errors.Is(err, ErrPending) {
			t.Fatal("abort raced a job that is still settling")
		}
	}
	m := importManager()
	m.imp.phase, m.imp.staged, m.imp.errOwned, m.err = ImportPartial, new(vault.OwnerImport), true, errors.New("fixture")
	m.AbortImport()
	cleared := m.err == nil
	m.imp.phase, m.imp.errOwned, m.err, m.pending = ImportPartial, true, errors.New("fixture"), &vault.OwnerIntent{}
	m.AbortImport()
	if idle != nil || !cleared || m.err == nil {
		t.Fatal("abort failed when idle, kept its own manager error or hid an unresolved owner intent")
	}
	for _, phase := range []ImportPhase{ImportInspecting, ImportApplying} {
		cancelled := false
		m = importManager()
		m.busy, m.imp.phase, m.imp.staged, m.imp.cancel = true, phase, new(vault.OwnerImport), func() { cancelled = true }
		if err := m.AbortImportAt(1); !errors.Is(err, vault.ErrOwnerRevision) || cancelled || m.imp.aborted || m.AbortImportAt(0) != nil || !cancelled || !m.imp.aborted || m.imp.phase != phase || m.imp.staged == nil {
			t.Fatalf("abort did not only cancel the running %q job", phase)
		}
	}
}

func TestStopDiscardsStagedImportAndHelpersAreSafe(t *testing.T) {
	for _, closed := range []*Manager{{closed: true}, {closing: true}} {
		if config, address, err := closed.HumanSSH("server", "account"); !errors.Is(err, ErrPending) || config != nil || address != "" {
			t.Fatal("closed manager handed out an SSH configuration")
		}
	}
	done := make(chan struct{})
	close(done)
	m := &Manager{cancel: func() {}, done: done, changed: make(chan struct{})}
	m.imp.phase, m.imp.staged, m.imp.password = ImportPartial, new(vault.OwnerImport), []byte("pw")
	m.stop()
	if m.imp.phase != ImportIdle || m.imp.staged != nil || m.imp.password != nil {
		t.Fatal("closing kept staged import material")
	}
	for err, want := range map[error]error{ownerarchive.ErrAuthentication: ownerarchive.ErrAuthentication, vault.ErrImportInvalid: ownerarchive.ErrArchive, context.DeadlineExceeded: errImportInterrupted, errors.New("secret-bearing"): errImportFailed, vault.ErrImportChanged: vault.ErrImportChanged, errImportEntries: errImportEntries} {
		if got := safeImportError(err); got != want {
			t.Fatal("import error was not mapped to fixed text")
		}
	}
	preview := vault.ImportPreview{Servers: []vault.ImportServer{{Name: "a", Fingerprints: []string{"x"}}}}
	copied := clonePreview(preview)
	copied.Servers[0].Fingerprints[0] = "changed"
	if preview.Servers[0].Fingerprints[0] != "x" {
		t.Fatal("status preview shares storage with the staged plan")
	}
}

func TestImportAliasOwnership(t *testing.T) {
	secret := vault.ImportSecret{AliasID: "a", Name: "token", ServerID: "s"}
	owned := func(name, scope, ref string, receipts map[string]string) bool {
		return importAliasOwned(secret, vault.SecretBinding{Name: name, ServerID: scope, Ref: ref}, receipts)
	}
	r1 := map[string]string{"a": "r1"}
	if owned("token", "s", "r1", nil) || !owned("token", "s", "r1", r1) || owned("token", "s", "r2", r1) || owned("other", "s", "r1", r1) || owned("token", "", "r1", r1) {
		t.Fatal("alias ownership needs the exact receipt under the plan's name and scope")
	}
}

func TestImportOwnsDestinationGatesEditSubmitAndStatus(t *testing.T) {
	for _, phase := range []ImportPhase{ImportApplying, ImportPartial} {
		m := importManager()
		m.link, m.imp.phase = &vault.OwnerStore{}, phase
		if err := m.Edit(func(*vault.Vault) error { t.Fatal("edit callback ran"); return nil }); !errors.Is(err, ErrPending) {
			t.Fatalf("edit ran while import was %q", phase)
		}
		if err := m.Submit(vault.OwnerChange{}); err == nil || (appstoreentry.Supported() && !errors.Is(err, ErrPending)) || m.busy || len(m.jobs) != 0 {
			t.Fatalf("submit ran while import was %q", phase)
		}
	}
	m := importManager()
	m.db, m.imp.phase, m.imp.staged = nil, ImportStaged, new(vault.OwnerImport)
	m.imp.preview = vault.ImportPreview{Secrets: []vault.ImportSecret{{AliasID: "a", Name: "token"}}}
	staged := m.ImportStatus()
	m.imp.published, m.imp.inflight = map[string]string{"a": "r1"}, "b"
	if status := m.ImportStatus(); staged.Published != 0 || staged.Total != 1 || status.Published != 0 {
		t.Fatal("staged plan reported published aliases or status counted without a readable destination")
	}
	m.imp.reset()
	if m.imp.published != nil || m.imp.inflight != "" {
		t.Fatal("reset kept import receipts")
	}
}

func TestImportReceiptsFollowOnlyAuthenticatedCommits(t *testing.T) {
	plan := []vault.ImportSecret{{AliasID: "a", Name: "n1"}, {AliasID: "b", Name: "n2", ServerID: "s"}}
	a1, a2, b2 := importRef(1, 1, 1, 1), importRef(1, 1, 9, 2), importRef(1, 2, 8, 2)
	bind := func(name, scope string, ref appstoreref.Ref) vault.SecretBinding {
		return vault.SecretBinding{Name: name, ServerID: scope, Ref: refText(ref)}
	}
	chA, chB := vault.OwnerChange{AliasID: "a", Name: "n1", ObjectID: "01" + strings.Repeat("0", 30)}, vault.OwnerChange{AliasID: "b", Name: "n2", ServerID: "s", ObjectID: "02" + strings.Repeat("0", 30)}
	refs2, good, old := []appstoreref.Ref{a2, b2}, map[string]vault.SecretBinding{"a": bind("n1", "", a2), "b": bind("n2", "s", b2)}, refText(a1)
	with := func(a vault.SecretBinding) map[string]vault.SecretBinding {
		return map[string]vault.SecretBinding{"a": a, "b": good["b"]}
	}
	run := func(phase ImportPhase, receipts map[string]string, inflight string, change vault.OwnerChange, refs []appstoreref.Ref, meta map[string]vault.SecretBinding) *Manager {
		m := importManager()
		m.imp.phase, m.imp.preview.Secrets, m.imp.published, m.imp.inflight = phase, plan, receipts, inflight
		m.importCommittedWith(change, refs, meta)
		return m
	}
	for _, phase := range []ImportPhase{ImportApplying, ImportPartial} {
		m := run(ImportApplying, nil, "a", chA, []appstoreref.Ref{a1}, map[string]vault.SecretBinding{"a": bind("n1", "", a1)})
		first := m.imp.published["a"] == old && m.imp.inflight == ""
		m.imp.phase, m.imp.inflight = phase, "b"
		before := importPublished(plan, m.imp.published, good) == 0 && !importAliasOwned(plan[0], good["a"], m.imp.published)
		m.importCommittedWith(chB, refs2, good)
		p := m.imp.published
		if !first || !before || p["a"] != refText(a2) || p["b"] != refText(b2) || m.imp.inflight != "" || importPublished(plan, p, good) != 2 || !importAliasOwned(plan[0], good["a"], p) || !importAliasOwned(plan[1], good["b"], p) {
			t.Fatalf("commit hook did not follow the authenticated refs in phase %q", phase)
		}
	}
	check := func(name string, phase ImportPhase, change vault.OwnerChange, refs []appstoreref.Ref, meta map[string]vault.SecretBinding, wantA string, wantB bool) {
		m := run(phase, map[string]string{"a": old}, "b", change, refs, meta)
		_, gotB := m.imp.published["b"]
		if m.imp.published["a"] != wantA || gotB != wantB || (m.imp.inflight == "") != wantB {
			t.Fatalf("%s: receipts moved without an authenticating commit", name)
		}
	}
	check("version not in commit", ImportApplying, chB, refs2, with(bind("n1", "", importRef(1, 1, 7, 2))), old, true)
	check("foreign store", ImportApplying, chB, []appstoreref.Ref{importRef(5, 1, 9, 2), b2}, good, old, true)
	check("renamed", ImportApplying, chB, refs2, with(bind("x", "", a2)), old, true)
	check("rescoped", ImportApplying, chB, refs2, with(bind("n1", "s", a2)), old, true)
	check("missing", ImportApplying, chB, refs2, map[string]vault.SecretBinding{"b": good["b"]}, old, true)
	check("own binding differs", ImportApplying, chB, refs2, map[string]vault.SecretBinding{"a": good["a"], "b": bind("n2", "s", importRef(1, 2, 7, 2))}, refText(a2), false)
	check("not the import's intent", ImportApplying, chA, refs2, good, old, false)
	check("staged", ImportStaged, chB, refs2, good, old, false)
	check("complete", ImportComplete, chB, refs2, good, old, false)
}

func rotatingManager() *Manager {
	done := make(chan struct{})
	close(done)
	lifetime, cancel := context.WithCancel(context.Background())
	return &Manager{busy: true, rotating: true, jobs: make(chan string, 1), changed: make(chan struct{}), done: done, ctx: lifetime, cancel: cancel}
}

func TestRotationInFlightExcludesWritersWithoutHoldingTheLock(t *testing.T) {
	m := rotatingManager()
	// m.mu is free: a reader or a refused writer returns at once.
	if !m.mu.TryLock() {
		t.Fatal("an in-flight rotation held the manager lock")
	}
	m.mu.Unlock()
	if err := m.Edit(func(*vault.Vault) error { return nil }); !errors.Is(err, ErrPending) {
		t.Fatalf("edit during rotation = %v", err)
	}
	if err := m.RetryDatabaseAt(1); !errors.Is(err, ErrPending) {
		t.Fatalf("retry during rotation = %v", err)
	}
	if err := m.beginRotation(true); !errors.Is(err, ErrPending) {
		t.Fatalf("second rotation operation = %v", err)
	}
	if !m.busy || !m.rotating {
		t.Fatal("a refused operation cleared the in-flight rotation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close during rotation = %v", err)
	}
	if m.closing || m.closed {
		t.Fatal("a timed-out close left the manager closing")
	}
}

func TestDiscardWaitsForRotationToEnd(t *testing.T) {
	m := rotatingManager()
	stopped := make(chan struct{})
	go func() {
		m.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("stop did not wait for the in-flight rotation")
	case <-time.After(100 * time.Millisecond):
	}
	if m.ctx.Err() != nil {
		t.Fatal("stop cancelled the manager before the rotation ended")
	}
	m.endRotation()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not resume after the rotation ended")
	}
	if !m.closed || m.busy || m.rotating || m.ctx.Err() == nil {
		t.Fatal("stop after rotation left the manager open")
	}
}

var (
	fixtureOnce              sync.Once
	pristineDir              string
	pristinePath             string
	pristineErr              error
	sharedOnce               sync.Once
	sharedDir                string
	sharedPath               string
	shared                   *Manager
	sharedErr                error
	fakeHashes               = map[string]string{}
	restartBeforeSaveManager *Manager
	keptDirs                 []string
	reopenedManager          *Manager
)

func TestMain(m *testing.M) {
	code := m.Run()
	for _, m := range []*Manager{shared, restartBeforeSaveManager, reopenedManager} {
		if m != nil {
			m.Discard()
		}
	}
	for _, dir := range keptDirs {
		_ = os.RemoveAll(dir)
	}
	if pristineDir != "" {
		_ = os.RemoveAll(pristineDir)
	}
	if sharedDir != "" {
		_ = os.RemoveAll(sharedDir)
	}
	os.Exit(code)
}

// Real vaults: each create/open runs four 1 GiB Argon2id passes (10-30 s on CI), so these tests run only with
// SSJACK_TEST_FULL_KDF=1 (dedicated CI step). Budget 6: create, shared open, SnapshotFailure, EditApplied, two reopens.
func requireFullKDF(t *testing.T) {
	t.Helper()
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in GitHub CI")
	}
}

func pristineFixture() (string, error) {
	fixtureOnce.Do(func() {
		pristineDir, pristineErr = os.MkdirTemp("", "ownerdb-pristine-")
		if pristineErr != nil {
			return
		}
		pristinePath = filepath.Join(pristineDir, "vault")
		pristineErr = vault.CreateWithRecords(context.Background(), pristinePath, vault.NewDirectory(), []byte("test-password"))
	})
	return pristinePath, pristineErr
}

func copyPristine(t *testing.T, dir string) string {
	t.Helper()
	src, err := pristineFixture()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func openCopiedManager(t *testing.T) (*Manager, string, []byte) {
	return openCopiedManagerWithCleanup(t, true)
}

func openCopiedManagerWithCleanup(t *testing.T, cleanup bool) (*Manager, string, []byte) {
	t.Helper()
	requireFullKDF(t)
	flakediag.OnFailure(t, func() string { return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024) })
	dir := t.TempDir()
	if !cleanup {
		var err error
		if dir, err = os.MkdirTemp("", "ownerdb-kept-"); err != nil {
			t.Fatal(err)
		}
		keptDirs = append(keptDirs, dir)
	}
	path := copyPristine(t, dir)
	password := []byte("test-password")
	m, err := Open(context.Background(), path, password)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup {
		t.Cleanup(m.Discard)
	}
	return m, path, password
}

// Tests sharing this manager run sequentially in source order (no t.Parallel); that ordering is the determinism contract.
func sharedManager(t *testing.T) (*Manager, string, []byte) {
	t.Helper()
	requireFullKDF(t)
	sharedOnce.Do(func() {
		flakediag.OnFailure(t, func() string { return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024) })
		sharedDir, sharedErr = os.MkdirTemp("", "ownerdb-shared-")
		if sharedErr != nil {
			return
		}
		sharedPath = copyPristine(t, sharedDir)
		shared, sharedErr = Open(context.Background(), sharedPath, []byte("test-password"))
	})
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	return shared, sharedPath, []byte("test-password")
}
