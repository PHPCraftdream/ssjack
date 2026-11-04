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
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestCopiedOwnerMaterialIsIndependentlyOwned(t *testing.T) {
	original := &vault.OwnerStore{Directory: "fixture", StoreID: "fixture", Master: []byte("synthetic master"), Pending: &vault.OwnerIntent{ID: "fixture", Versions: map[string]string{"object": "version"}, Change: vault.OwnerChange{Value: []byte("synthetic pending value")}}}
	owned := copyLink(original)
	owned.Pending.Versions["object"] = "changed"
	clearLink(owned)
	if !bytes.Equal(original.Master, []byte("synthetic master")) || !bytes.Equal(original.Pending.Change.Value, []byte("synthetic pending value")) || original.Pending.Versions["object"] != "version" {
		t.Fatal("coordinator copies borrowed private buffers or version metadata")
	}
	if !bytes.Equal(owned.Master, make([]byte, len(owned.Master))) || !bytes.Equal(owned.Pending.Change.Value, make([]byte, len(owned.Pending.Change.Value))) {
		t.Fatal("coordinator cleanup did not clear owned private material")
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
	if err := m.Export(ExportRequest{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "another.zip"}); err == nil {
		t.Fatal("concurrent export bypassed the single owner worker")
	}
	m = &Manager{jobs: make(chan string, 1), changed: make(chan struct{})}
	for _, request := range []ExportRequest{
		{},
		{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "synthetic.zip", PlaintextConfirmation: "yes"},
		{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "synthetic.zip"},
	} {
		if err := m.Export(request); err == nil || m.busy || len(m.jobs) != 0 {
			t.Fatal("invalid or unauthenticated export queued work")
		}
	}
}

func TestCipherDigestChecksOnlyBoundedRegularCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database")
	encoded := []byte("synthetic ciphertext fixture")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := cipherDigest(path)
	if err != nil || digest != sha256.Sum256(encoded) {
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
	gates := map[string]func(*Manager){
		"closed":    func(m *Manager) { m.closed = true },
		"closing":   func(m *Manager) { m.closing = true },
		"busy":      func(m *Manager) { m.busy = true },
		"pending":   func(m *Manager) { m.pending = &vault.OwnerIntent{} },
		"error":     func(m *Manager) { m.err = errors.New("fixture") },
		"inspect":   func(m *Manager) { m.imp.phase = ImportInspecting },
		"staged":    func(m *Manager) { m.imp.phase = ImportStaged },
		"applying":  func(m *Manager) { m.imp.phase = ImportApplying },
		"partial":   func(m *Manager) { m.imp.phase = ImportPartial },
		"no-worker": func(m *Manager) { m.jobs = nil },
	}
	for name, gate := range gates {
		m := importManager()
		gate(m)
		if err := m.InspectImport("archive.zip", []byte("pw")); !errors.Is(err, ErrPending) || m.imp.password != nil || (m.jobs != nil && len(m.jobs) != 0) {
			t.Fatalf("inspection was not refused while %s", name)
		}
	}
}

func TestInspectImportOwnsPasswordAndReplacesCompleteImport(t *testing.T) {
	m := importManager()
	m.imp.phase, m.imp.staged, m.imp.effects = ImportComplete, new(vault.OwnerImport), true
	password := []byte("synthetic password")
	if err := m.InspectImport("archive.zip", password); err != nil {
		t.Fatal(err)
	}
	clear(password)
	if !bytes.Equal(m.imp.password, []byte("synthetic password")) || !m.busy || m.imp.phase != ImportInspecting || m.imp.staged != nil || m.imp.effects || <-m.jobs != ":import-inspect" {
		t.Fatal("inspection did not take a private copy or reset the previous import")
	}
	if err := m.InspectImport("other.zip", nil); !errors.Is(err, ErrPending) {
		t.Fatal("second inspection bypassed the busy worker")
	}
	m = importManager()
	m.imp.phase, m.imp.aborted, m.imp.password = ImportInspecting, true, []byte("synthetic password")
	held := m.imp.password
	if err := m.inspectImport(context.Background()); err != nil {
		t.Fatal("inspect outcome must never become the manager error")
	}
	if m.imp.phase != ImportIdle || !errors.Is(m.imp.err, ErrImportAborted) || m.imp.password != nil || !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("failed inspection left state or password material behind")
	}
}

func TestImportPhaseGatingForConfirmResumeAbort(t *testing.T) {
	for _, phase := range []ImportPhase{ImportIdle, ImportInspecting, ImportApplying, ImportPartial, ImportComplete} {
		m := importManager()
		m.imp.phase, m.imp.staged = phase, new(vault.OwnerImport)
		if err := m.ConfirmImport(); !errors.Is(err, ErrPending) || m.busy || len(m.jobs) != 0 {
			t.Fatalf("confirm ran in phase %q", phase)
		}
	}
	for _, phase := range []ImportPhase{ImportIdle, ImportInspecting, ImportStaged, ImportApplying, ImportComplete} {
		m := importManager()
		m.imp.phase, m.imp.staged = phase, new(vault.OwnerImport)
		if err := m.ResumeImport(); !errors.Is(err, ErrPending) || m.busy || len(m.jobs) != 0 {
			t.Fatalf("resume ran in phase %q", phase)
		}
	}
	m := importManager()
	m.imp.phase, m.imp.staged, m.pending = ImportPartial, new(vault.OwnerImport), &vault.OwnerIntent{}
	if err := m.ResumeImport(); !errors.Is(err, ErrPending) || len(m.jobs) != 0 {
		t.Fatal("resume ignored an unresolved owner intent")
	}
	// An unevaluable destination must refuse confirmation, never queue.
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
	if err := importManager().AbortImport(); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []ImportPhase{ImportStaged, ImportComplete, ImportPartial} {
		m := importManager()
		m.imp.phase, m.imp.staged, m.imp.password, m.imp.effects = phase, new(vault.OwnerImport), []byte("pw"), true
		if err := m.AbortImport(); err != nil || m.imp.phase != ImportIdle || m.imp.staged != nil || m.imp.password != nil || m.imp.effects {
			t.Fatalf("abort did not discard phase %q", phase)
		}
		m.imp.phase, m.busy = phase, true
		if err := m.AbortImport(); !errors.Is(err, ErrPending) {
			t.Fatal("abort raced a job that is still settling")
		}
	}
	m := importManager()
	m.imp.phase, m.imp.staged, m.imp.errOwned, m.err = ImportPartial, new(vault.OwnerImport), true, errors.New("fixture")
	m.AbortImport()
	if m.err != nil {
		t.Fatal("aborting a partial import kept its own manager error")
	}
	m.imp.phase, m.imp.errOwned, m.err, m.pending = ImportPartial, true, errors.New("fixture"), &vault.OwnerIntent{}
	m.AbortImport()
	if m.err == nil {
		t.Fatal("abort hid an unresolved owner intent")
	}
	for _, phase := range []ImportPhase{ImportInspecting, ImportApplying} {
		cancelled := false
		m = importManager()
		m.busy, m.imp.phase, m.imp.staged, m.imp.cancel = true, phase, new(vault.OwnerImport), func() { cancelled = true }
		if err := m.AbortImport(); err != nil || !cancelled || !m.imp.aborted || m.imp.phase != phase || m.imp.staged == nil {
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
	for err, want := range map[error]error{
		ownerarchive.ErrAuthentication: ownerarchive.ErrAuthentication,
		vault.ErrImportInvalid:         ownerarchive.ErrArchive,
		context.DeadlineExceeded:       errImportInterrupted,
		errors.New("secret-bearing"):   errImportFailed,
		vault.ErrImportChanged:         vault.ErrImportChanged,
		errImportEntries:               errImportEntries,
	} {
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
	bind := func(name, scope, ref string) vault.SecretBinding {
		return vault.SecretBinding{Name: name, ServerID: scope, Ref: ref}
	}
	cases := []struct {
		name, receipt, inflight string
		binding                 vault.SecretBinding
		want                    bool
	}{
		{"no receipt", "", "", bind("token", "s", "r1"), false},
		{"receipt", "r1", "", bind("token", "s", "r1"), true},
		{"ref changed", "r1", "", bind("token", "s", "r2"), false},
		{"renamed", "r1", "", bind("other", "s", "r1"), false},
		{"rescoped", "r1", "", bind("token", "", "r1"), false},
		{"inflight renamed", "", "a", bind("other", "s", "r1"), false},
		{"inflight", "", "a", bind("token", "s", "r1"), true},
	}
	for _, tc := range cases {
		receipts := map[string]string{}
		if tc.receipt != "" {
			receipts["a"] = tc.receipt
		}
		if got := importAliasOwned(secret, tc.binding, receipts, tc.inflight); got != tc.want {
			t.Fatalf("%s: ownership %v", tc.name, got)
		}
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
	if status := m.ImportStatus(); status.Published != 0 || status.Total != 1 {
		t.Fatal("staged plan reported published aliases")
	}
	m.imp.published, m.imp.inflight = map[string]string{"a": "r1"}, "b"
	if status := m.ImportStatus(); status.Published != 0 {
		t.Fatal("status counted without a readable destination")
	}
	m.imp.reset()
	if m.imp.published != nil || m.imp.inflight != "" {
		t.Fatal("reset kept import receipts")
	}
}
