package ownerdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
	if shared != nil {
		shared.Discard()
	}
	if restartBeforeSaveManager != nil {
		restartBeforeSaveManager.Discard()
	}
	if reopenedManager != nil {
		reopenedManager.Discard()
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

func setVerifier(t *testing.T, m *Manager, hash string, verifyErr error) {
	t.Helper()
	if err := m.SetDescriptorVerifier(func(string) (string, error) { return hash, verifyErr }); err != nil {
		t.Fatal(err)
	}
}

func approveMutation(name, path, hash string) ApprovalMutation {
	return ApprovalMutation{Kind: "approve", Name: name, Path: path, Hash: hash}
}

func revokeMutation(name, path, hash string) ApprovalMutation {
	return ApprovalMutation{Kind: "revoke", Name: name, Hash: hash, Replaces: hash} // the wire carries no path on revoke
}

func snapshotFiles(t *testing.T, vaultPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(vaultPath))
	if err != nil {
		t.Fatal(err)
	}
	prefix, suffix := filepath.Base(vaultPath)+"."+approvalSnapshotLabel+"-", ".ssjack.ktav"
	var files []string
	for _, entry := range entries {
		if name := entry.Name(); strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

// clearSnapshots deletes evidence snapshots only; it never touches the vault file or session.
func clearSnapshots(t *testing.T, vaultPath string) {
	t.Helper()
	for _, name := range snapshotFiles(t, vaultPath) {
		if err := os.Remove(filepath.Join(filepath.Dir(vaultPath), name)); err != nil {
			t.Fatal(err)
		}
	}
}

// makeStandins writes n stand-in snapshot files; file i gets the modification time stamp(i).
func makeStandins(t *testing.T, vaultPath string, n int, stamp func(i int) time.Time) []string {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s.%s-%02d-standin.ssjack.ktav", filepath.Base(vaultPath), approvalSnapshotLabel, i)
		file := filepath.Join(filepath.Dir(vaultPath), names[i])
		if err := os.WriteFile(file, []byte("stand-in"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, stamp(i), stamp(i)); err != nil {
			t.Fatal(err)
		}
	}
	return names
}

func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func holdSaveLock(t *testing.T, vaultPath string) {
	t.Helper()
	if err := os.WriteFile(vaultPath+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(vaultPath + ".lock") })
}

// KDF budget: pristine creation 1; sharedManager Open (VerifyRefusals through ReplyLost) 1;
// SnapshotFailure copy+Open 1; EditAppliedThenSaveFailed copy+Open 1; RestartBeforeSave reopen
// (its manager is reused by TimeoutAfterEnqueue) 1; RestartAfterDurableSave reopen of the shared vault 1.
// Total: 6. Each operation is four 1 GiB Argon2id runs, 10-15 s under the race detector on CI.
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

func fakeDescriptor(path string) (string, error) {
	if hash, ok := fakeHashes[path]; ok {
		return hash, nil
	}
	return "", errors.New("descriptor missing")
}

// waitDurable polls (bounded): a manager retry is asynchronous, and Session.Flush would return the stale save error before the worker clears it.
func waitDurable(t *testing.T, m *Manager) {
	t.Helper()
	flakediag.WaitFor(t, "database becomes durable", 30*time.Second, func() (string, bool) {
		status := m.Status().Database
		return fmt.Sprintf("revision=%d saved=%d pending=%v err=%v", status.Revision, status.SavedRevision, status.Pending, status.Err), !status.Pending && status.Err == nil && status.Revision == status.SavedRevision
	})
}

func approvalHash(seed byte) string { return fmt.Sprintf("%064x", seed) }

func approvalNames(t *testing.T, m *Manager) []string {
	t.Helper()
	metadata, err := m.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(metadata.Approvals))
	for _, approval := range metadata.Approvals {
		names = append(names, approval.Name)
	}
	return names
}

func hasName(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

// unchangedApproval asserts a refused composite left the vault, revision and approval list as they were.
func unchangedApproval(t *testing.T, m *Manager, path string, before [32]byte, revision uint64, count int, message string) {
	t.Helper()
	if len(snapshotFiles(t, path)) != 0 || fileDigest(t, path) != before || m.Status().Database.Revision != revision || len(approvalNames(t, m)) != count {
		t.Fatal(message)
	}
}

func TestApprovalVerifyRefusals(t *testing.T) {
	m, path, _ := sharedManager(t)
	dir := filepath.Dir(path)
	t.Run("unconfigured keeper refuses", func(t *testing.T) {
		before, revision, count := fileDigest(t, path), m.Status().Database.Revision, len(approvalNames(t, m))
		mutationPath := filepath.Join(dir, "app-v0")
		if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation("app-v0", mutationPath, approvalHash(1))); !errors.Is(err, ErrApprovalReview) {
			t.Fatalf("unconfigured verifier error = %v", err)
		}
		unchangedApproval(t, m, path, before, revision, count, "unconfigured keeper changed approval state")
		// This zero value is a throwaway guard check and is never used for approvals.
		if err := (&Manager{}).SetDescriptorVerifier(nil); err == nil {
			t.Fatal("nil verifier replacement succeeded")
		}
	})
	if err := m.SetDescriptorVerifier(fakeDescriptor); err != nil {
		t.Fatal(err)
	}
	t.Run("verifier error refuses with review", func(t *testing.T) {
		before, revision, count := fileDigest(t, path), m.Status().Database.Revision, len(approvalNames(t, m))
		mutationPath := filepath.Join(dir, "app-v1")
		if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation("app-v1", mutationPath, approvalHash(1))); !errors.Is(err, ErrApprovalReview) {
			t.Fatalf("verifier error = %v", err)
		}
		unchangedApproval(t, m, path, before, revision, count, "verifier error changed approval state")
	})
	t.Run("mismatch refuses with review", func(t *testing.T) {
		mutationPath := filepath.Join(dir, "app-v2")
		before, revision, count := fileDigest(t, path), m.Status().Database.Revision, len(approvalNames(t, m))
		fakeHashes[mutationPath] = approvalHash(9)
		mutation := approveMutation("app-v2", mutationPath, approvalHash(1))
		if err := m.ApproveWithSnapshot(context.Background(), revision, mutation); !errors.Is(err, ErrApprovalReview) {
			t.Fatalf("mismatch error = %v", err)
		}
		unchangedApproval(t, m, path, before, revision, count, "mismatch changed approval state")
		fakeHashes[mutationPath] = approvalHash(1)
		if err := m.ApproveWithSnapshot(context.Background(), revision, mutation); err != nil {
			t.Fatal(err)
		}
		if err := m.SetDescriptorVerifier(fakeDescriptor); err == nil {
			t.Fatal("verifier replacement after approval succeeded")
		}
		if len(snapshotFiles(t, path)) != 1 || fileDigest(t, path) == before {
			t.Fatal("first approval was not persisted with one snapshot")
		}
	})
}

func TestApprovalSnapshotThenApplyAtomic(t *testing.T) {
	m, path, _ := sharedManager(t)
	clearSnapshots(t, path)
	dir := filepath.Dir(path)
	pathA, pathB := filepath.Join(dir, "app-a1"), filepath.Join(dir, "app-a2")
	fakeHashes[pathA], fakeHashes[pathB] = approvalHash(1), approvalHash(2)
	waitDurable(t, m)
	status := m.Status().Database
	expected, before, baseline := status.Revision, fileDigest(t, path), len(approvalNames(t, m))
	if status.Revision != status.SavedRevision || status.Pending || status.Err != nil {
		t.Fatalf("database not saved before the race: %+v", status)
	}
	loser := make(chan error, 1)
	go func() {
		loser <- m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-a2", pathB, approvalHash(2)))
	}()
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-a1", pathA, approvalHash(1)))
	loserErr := <-loser
	if (err == nil) == (loserErr == nil) {
		t.Fatalf("composite outcomes = %v, %v", err, loserErr)
	}
	if err != nil && !errors.Is(err, vault.ErrOwnerRevision) || loserErr != nil && !errors.Is(loserErr, vault.ErrOwnerRevision) {
		t.Fatalf("losing composite error = %v, %v", err, loserErr)
	}
	files := snapshotFiles(t, path)
	if len(files) != 1 || fileDigest(t, filepath.Join(dir, files[0])) != before {
		t.Fatal("snapshot did not preserve pre-write ciphertext")
	}
	if fileDigest(t, path) == before {
		t.Fatal("database ciphertext did not change")
	}
	status = m.Status().Database
	names := approvalNames(t, m)
	winner, lost := "app-a1", "app-a2"
	if err != nil {
		winner, lost = lost, winner
	}
	if status.Pending || status.Err != nil || status.Revision != expected+1 || status.SavedRevision != expected+1 || len(names) != baseline+1 || !hasName(names, winner) || hasName(names, lost) {
		t.Fatalf("unexpected composite result: %+v, approvals %v", status, names)
	}
}

func TestApprovalSnapshotRetentionBound(t *testing.T) {
	m, path, _ := sharedManager(t)
	var passZeroSnapshot string
	dir := filepath.Dir(path)
	t.Run("retains newest snapshots", func(t *testing.T) {
		clearSnapshots(t, path)
		expected := m.Status().Database.Revision
		baseTime := time.Now()
		standins := makeStandins(t, path, 10, func(i int) time.Time { return baseTime.Add(-time.Duration(100-i) * time.Hour) })
		for i := 0; i < 2; i++ {
			name := fmt.Sprintf("app-r%d", i)
			p := filepath.Join(dir, name)
			hash := approvalHash(byte(i + 1))
			fakeHashes[p] = hash
			if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation(name, p, hash)); err != nil {
				t.Fatalf("pass %d: %v", i, err)
			}
			expected++
			files := snapshotFiles(t, path)
			if len(files) != 10 {
				t.Fatalf("pass %d snapshot count = %d", i, len(files))
			}
			if i == 0 {
				for _, file := range files {
					if !strings.Contains(file, "-standin.") {
						passZeroSnapshot = file
						break
					}
				}
				if passZeroSnapshot == "" {
					t.Fatal("pass 0 real snapshot missing")
				}
			} else if _, err := os.Stat(filepath.Join(dir, passZeroSnapshot)); err != nil {
				t.Fatalf("pass 0 real snapshot missing after pass 1: %v", err)
			}
			for j, name := range standins {
				_, statErr := os.Stat(filepath.Join(dir, name))
				removed := j <= i
				if removed && statErr == nil {
					t.Fatalf("oldest stand-in %d remains after pass %d", j, i)
				}
				if !removed && statErr != nil {
					t.Fatalf("newer stand-in %d missing after pass %d: %v", j, i, statErr)
				}
			}
		}
		waitDurable(t, m)
	})
	t.Run("approve revoke round trip", func(t *testing.T) {
		name, p := "app-rr", filepath.Join(dir, "app-rr")
		fakeHashes[p] = approvalHash(1)
		expected, baseline := m.Status().Database.Revision, len(approvalNames(t, m))
		if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation(name, p, approvalHash(1))); err != nil {
			t.Fatal(err)
		}
		expected++
		names := approvalNames(t, m)
		if len(names) != baseline+1 || !hasName(names, name) || m.Status().Database.Revision != expected || len(snapshotFiles(t, path)) != 10 {
			t.Fatal("approve round trip state mismatch")
		}
		if err := m.ApproveWithSnapshot(context.Background(), expected, revokeMutation(name, p, approvalHash(1))); err != nil {
			t.Fatal(err)
		}
		expected++
		waitDurable(t, m)
		names = approvalNames(t, m)
		if len(names) != baseline || hasName(names, name) || m.Status().Database.Revision != expected || len(snapshotFiles(t, path)) != 10 {
			t.Fatal("revoke round trip state mismatch")
		}
	})
	t.Run("prune failure refuses", func(t *testing.T) {
		// Start with only the nine stand-ins so the oldest blocker is the sole prune candidate.
		for _, name := range snapshotFiles(t, path) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		baseTime := time.Now()
		makeStandins(t, path, 9, func(i int) time.Time { return baseTime.Add(time.Duration(i) * time.Hour) })
		blocker := filepath.Join(dir, fmt.Sprintf("%s.%s-00-blocker.ssjack.ktav", filepath.Base(path), approvalSnapshotLabel))
		if err := os.Mkdir(blocker, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blocker, "retain"), []byte("stand-in"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(blocker) })
		oldest := baseTime.Add(-time.Hour)
		if err := os.Chtimes(blocker, oldest, oldest); err != nil {
			t.Fatal(err)
		}
		before, revision := fileDigest(t, path), m.Status().Database.Revision
		p := filepath.Join(dir, "app-prune")
		fakeHashes[p] = approvalHash(1)
		if err := m.ApproveWithSnapshot(context.Background(), revision, approveMutation("app-prune", p, approvalHash(1))); err == nil || errors.Is(err, vault.ErrOwnerRevision) || errors.Is(err, ErrApprovalReview) || errors.Is(err, ErrPending) {
			t.Fatalf("prune failure error = %v", err)
		}
		status := m.Status().Database
		if len(snapshotFiles(t, path)) != 10 || fileDigest(t, path) != before || status.Revision != revision {
			t.Fatal("prune failure changed vault state or created a snapshot")
		}
	})
}

func TestApprovalSnapshotSucceededEditRejected(t *testing.T) {
	m, path, _ := sharedManager(t)
	clearSnapshots(t, path)
	dir := filepath.Dir(path)
	appPath := filepath.Join(dir, "app-e-shared")
	fakeHashes[appPath] = approvalHash(1)
	expected, baseline := m.Status().Database.Revision, len(approvalNames(t, m))
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-e1", appPath, approvalHash(1))); err != nil {
		t.Fatal(err)
	}
	firstDigest := fileDigest(t, path)
	expected++
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-e2", appPath, approvalHash(1))); err == nil || err.Error() != "another approved application already uses this path" {
		t.Fatalf("unexpected path-conflict error: %v", err)
	}
	names := approvalNames(t, m)
	if len(snapshotFiles(t, path)) != 2 || len(names) != baseline+1 || !hasName(names, "app-e1") || hasName(names, "app-e2") || fileDigest(t, path) != firstDigest || m.Status().Database.Revision != expected {
		t.Fatal("rejected edit did not retain only the first approval")
	}
}

func TestApprovalSaveSucceededReplyLost(t *testing.T) {
	// Proves only that a durable success is readable afterwards and that one composite yields exactly one approval and snapshot; it does not model a lost reply (the no-replay rule is pinned in internal/ownerrpc/exchange_test.go).
	m, path, _ := sharedManager(t)
	dir := filepath.Dir(path)
	p := filepath.Join(dir, "app-reply")
	fakeHashes[p] = approvalHash(1)
	before, expected := fileDigest(t, path), m.Status().Database.Revision
	beforeFiles := len(snapshotFiles(t, path))
	beforeMetadata, err := m.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-reply", p, approvalHash(1))); err != nil {
		t.Fatal(err)
	}
	metadata, metadataErr := m.Metadata()
	status := m.Status().Database
	found := false
	for _, approval := range metadata.Approvals {
		if approval.Name == "app-reply" && approval.Path == p && approval.Hash == approvalHash(1) {
			found = true
		}
	}
	if metadataErr != nil || status.SavedRevision != expected+1 || status.Revision != expected+1 || len(metadata.Approvals) != len(beforeMetadata.Approvals)+1 || !found || fileDigest(t, path) == before || len(snapshotFiles(t, path)) != beforeFiles+1 {
		t.Fatal("durable approval state was not confirmed")
	}
}

func TestApprovalSnapshotFailureKeepsVaultUnchanged(t *testing.T) {
	m, path, _ := openCopiedManager(t)
	setVerifier(t, m, approvalHash(1), nil)
	if err := os.WriteFile(path, []byte("corrupted ciphertext fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	corrupted, expected := fileDigest(t, path), m.Status().Database.Revision
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app", filepath.Join(filepath.Dir(path), "app"), approvalHash(1)))
	status := m.Status().Database
	metadata, metadataErr := m.Metadata()
	if err == nil || len(snapshotFiles(t, path)) != 0 || fileDigest(t, path) != corrupted || status.Revision != expected || status.SavedRevision != expected || status.Err != nil || status.Pending || metadataErr != nil || len(metadata.Approvals) != 0 {
		t.Fatal("snapshot failure changed the live approval state")
	}
}

func TestApprovalEditAppliedThenSaveFailed(t *testing.T) {
	m, path, _ := openCopiedManagerWithCleanup(t, false)
	restartBeforeSaveManager = m
	setVerifier(t, m, approvalHash(1), nil)
	holdSaveLock(t, path)
	before, expected := fileDigest(t, path), m.Status().Database.Revision
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app", filepath.Join(filepath.Dir(path), "app"), approvalHash(1)))
	status := m.Status().Database
	metadata, metadataErr := m.Metadata()
	if err == nil || status.Revision != expected+1 || !status.Pending || status.Err == nil || metadataErr != nil || len(metadata.Approvals) != 1 || fileDigest(t, path) != before || len(snapshotFiles(t, path)) != 1 {
		t.Fatal("save failure rolled back or persisted the applied approval")
	}
}

func TestApprovalRestartBeforeSave(t *testing.T) {
	// Depends on TestApprovalEditAppliedThenSaveFailed running first in source order; its manager is applied in memory but not durable.
	m := restartBeforeSaveManager
	if m == nil {
		t.Skip("needs TestApprovalEditAppliedThenSaveFailed in the same run")
	}
	restartBeforeSaveManager = nil
	path := m.path
	m.Discard()
	reopened, err := Open(context.Background(), path, []byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	reopenedManager = reopened
	status := reopened.Status().Database
	metadata, metadataErr := reopened.Metadata()
	if status.Revision != status.SavedRevision || metadataErr != nil || len(metadata.Approvals) != 0 || len(snapshotFiles(t, path)) != 1 {
		t.Fatal("restart before save did not reopen the prior state")
	}
}

func TestApprovalTimeoutAfterEnqueue(t *testing.T) {
	// Proves operation-failure after enqueue using the .lock seam to make save fail. It cannot pause the worker mid-save, so the timeout branch is not exercised; a queued save may complete after explicit retry, never by replaying the operation.
	// Runs on the manager reopened by TestApprovalRestartBeforeSave (prior durable state, no approvals).
	m := reopenedManager
	if m == nil {
		t.Skip("needs TestApprovalRestartBeforeSave in the same run")
	}
	path := m.path
	setVerifier(t, m, approvalHash(1), nil)
	holdSaveLock(t, path)
	before, expected := fileDigest(t, path), m.Status().Database.Revision
	err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app", filepath.Join(filepath.Dir(path), "app"), approvalHash(1)))
	status := m.Status().Database
	metadata, metadataErr := m.Metadata()
	if err == nil || errors.Is(err, vault.ErrOwnerRevision) || errors.Is(err, ErrApprovalReview) || errors.Is(err, ErrPending) {
		t.Fatalf("save failure outcome class = %v", err)
	}
	if status.Revision != expected+1 || !status.Pending || metadataErr != nil || len(metadata.Approvals) != 1 || fileDigest(t, path) != before {
		t.Fatal("save failure after enqueue did not preserve the applied pending state")
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := m.RetryDatabaseAt(expected + 1); err != nil {
		t.Fatal(err)
	}
	waitDurable(t, m)
	metadata, metadataErr = m.Metadata()
	if metadataErr != nil || len(metadata.Approvals) != 1 || metadata.Approvals[0].Hash != approvalHash(1) || m.Status().Database.Revision != expected+1 || fileDigest(t, path) == before {
		t.Fatal("retry failed to durably persist exactly one approval")
	}
}

// TestApprovalRestartAfterDurableSave reopens the shared manager's vault, so it must stay the last test that uses it.
func TestApprovalRestartAfterDurableSave(t *testing.T) {
	m, path, password := sharedManager(t)
	_ = m.SetDescriptorVerifier(fakeDescriptor) // fails once an earlier scenario already approved; needed only when run alone
	dir := filepath.Dir(path)
	appPath := filepath.Join(dir, "app-rd")
	fakeHashes[appPath] = approvalHash(1)
	expected := m.Status().Database.Revision
	if err := m.ApproveWithSnapshot(context.Background(), expected, approveMutation("app-rd", appPath, approvalHash(1))); err != nil {
		t.Fatal(err)
	}
	status := m.Status().Database
	if status.Revision != expected+1 || status.SavedRevision != expected+1 {
		t.Fatal("approval was not durable before restart")
	}
	want := approvalNames(t, m)
	m.Discard()
	shared, sharedErr = nil, errors.New("shared manager was discarded by the restart scenario")
	reopened, err := Open(context.Background(), path, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Discard)
	metadata, metadataErr := reopened.Metadata()
	status = reopened.Status().Database
	got := approvalNames(t, reopened)
	exact := false
	for _, approval := range metadata.Approvals {
		if approval.Name == "app-rd" && approval.Path == appPath && approval.Hash == approvalHash(1) {
			exact = true
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	if metadataErr != nil || !exact || strings.Join(got, ",") != strings.Join(want, ",") || status.Revision != status.SavedRevision || len(snapshotFiles(t, path)) == 0 {
		t.Fatal("restart after durable save lost an approval or its evidence snapshot")
	}
}
