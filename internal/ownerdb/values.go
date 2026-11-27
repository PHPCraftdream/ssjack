package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerclone"
	"github.com/PHPCraftdream/ssjack/internal/ownerresource"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type resources = ownerresource.Resources

func openResources(ctx context.Context, link *vault.OwnerStore) (*resources, error) {
	return ownerresource.Open(ctx, link)
}

type ExportRequest struct {
	Selection             vault.ExportSelection
	Destination           string
	PlaintextConfirmation string
}

func (m *Manager) export(expected *uint64, request ExportRequest) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return errors.New("owner export requires a supported private-file runtime")
	}
	if request.Destination == "" || len(request.Destination) > 4096 || strings.ContainsAny(request.Destination, "\x00\r\n") || (request.PlaintextConfirmation != "" && request.PlaintextConfirmation != "EXPORT PLAINTEXT") {
		return errors.New("invalid owner export destination or plaintext confirmation")
	}
	if len(request.Selection.Servers) > 64 || (len(request.Selection.Servers) == 0 && !request.Selection.GlobalSecrets && len(request.Selection.RemoteMCP) == 0) || request.Selection.Validate() != nil {
		return errors.New("select an explicit bounded export scope")
	}
	owned := request
	owned.Selection.Servers = make(map[string][]string, len(request.Selection.Servers))
	for id, accounts := range request.Selection.Servers {
		if len(accounts) == 0 || len(accounts) > 64 {
			return errors.New("select explicit bounded export accounts")
		}
		owned.Selection.Servers[id] = append([]string(nil), accounts...)
	}
	owned.Selection.RemoteMCP = append([]mcpdirectory.Binding(nil), request.Selection.RemoteMCP...)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || m.jobs == nil || m.rotationBlocksMutation() {
		return ErrPending
	}
	if len(owned.Selection.RemoteMCP) != 0 {
		metadata, status, _, err := m.db.MetadataSnapshot()
		if err != nil || (expected != nil && status.Revision != *expected) || status.Pending || status.Err != nil || !metadata.RemoteMCP.MatchesBindings(owned.Selection.RemoteMCP) {
			return errors.New("selected remote MCP export records changed")
		}
	}
	return m.admit(expected, func() error {
		m.exportRequest, m.busy = &owned, true
		m.jobs <- ":export"
		m.signal()
		return nil
	})
}

func (m *Manager) exportArchive(ctx context.Context, request ExportRequest) error {
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	plan, err := m.db.PrepareOwnerExport(request.Selection)
	if err != nil {
		return err
	}
	defer plan.Close()
	if len(plan.Bindings()) != 0 {
		if m.link == nil {
			return errors.New("selected values require the linked owner store")
		}
		if m.resources == nil {
			m.resources, err = openResources(ctx, m.link)
			if err != nil {
				return err
			}
		}
		if m.resources.Editor() != nil {
			m.resources.ResetEditor()
		}
		if err := m.resources.OpenEditor(ctx); err != nil {
			return err
		}
		defer func() { m.resources.ResetEditor() }()
		if err := m.resources.Check(); err != nil {
			return err
		}
		if err := m.resources.Editor().AppendOwnerExport(ctx, plan); err != nil {
			return err
		}
		if err := m.resources.Check(); err != nil {
			return err
		}
	}
	if request.PlaintextConfirmation == "" {
		return plan.WriteEncrypted(ctx, request.Destination)
	}
	return plan.WritePlaintext(ctx, request.Destination, request.PlaintextConfirmation)
}

var errAliasOnly = errors.New("remove only the shared secret binding")

func (m *Manager) applyValue(change vault.OwnerChange) (string, error) {
	if change.Action == "add" {
		id, err := m.resources.Editor().Add(change.MediaType, change.Value)
		return hex.EncodeToString(id[:]), err
	}
	previous, err := appstoreplaceholder.Parse([]byte(change.PreviousReference))
	if err != nil {
		return "", err
	}
	object := previous.ObjectID()
	found := false
	for _, metadata := range m.resources.Editor().Objects() {
		if metadata.ObjectID == object {
			if metadata.Reference != previous || metadata.Pending {
				return "", appstorecrypto.ErrOwnerChanged
			}
			found = true
		}
	}
	if !found {
		return "", appstorecrypto.ErrOwnerChanged
	}
	metadata, err := m.db.Metadata()
	if err != nil {
		return "", err
	}
	shared := false
	for aliasID, alias := range metadata.Secrets {
		if aliasID == change.AliasID {
			continue
		}
		reference, err := appstoreplaceholder.Parse([]byte(alias.Ref))
		if err != nil {
			return "", err
		}
		if reference.StoreID() == previous.StoreID() && reference.ObjectID() == object {
			shared = true
		}
	}
	switch change.Action {
	case "update":
		if shared {
			id, err := m.resources.Editor().Add(change.MediaType, change.Value)
			return hex.EncodeToString(id[:]), err
		}
		err = m.resources.Editor().Update(object, change.Value)
	case "remove":
		if shared {
			return "", errAliasOnly
		}
		err = m.resources.Editor().Remove(object)
	default:
		return "", errors.New("unsupported owner value change")
	}
	return hex.EncodeToString(object[:]), err
}

type ImportPhase string

const (
	ImportIdle       ImportPhase = ""
	ImportInspecting ImportPhase = "inspecting"
	ImportStaged     ImportPhase = "staged"
	ImportApplying   ImportPhase = "applying"
	ImportPartial    ImportPhase = "partial"
	ImportComplete   ImportPhase = "complete"
)

// ImportStatus carries metadata only: never values, credentials or passwords.
type ImportStatus struct {
	PlanID           uint64
	Phase            ImportPhase
	Preview          vault.ImportPreview
	Conflicts        []vault.ImportConflict
	Published, Total int
	DirectoryApplied bool
	Err              error
}

var (
	ErrImportAborted     = errors.New("owner import was aborted")
	errImportFailed      = errors.New("owner import failed")
	errImportInterrupted = errors.New("owner import timed out or was interrupted")
	errImportEvaluate    = errors.New("owner import cannot be evaluated against the destination")
)

// importState is guarded by Manager.mu. The staged OwnerImport is closed only
// by the worker (completion) or by operator calls while no import job runs.
// published maps alias ID to the exact destination ref this import recorded as
// its receipt; inflight is the alias whose owner intent was staged by this
// import and not yet receipted. Only the commit hook (importCommitted) writes
// receipts; an alias is import-owned only by an exact receipt.
type importState struct {
	planID    uint64
	phase     ImportPhase
	staged    *vault.OwnerImport
	preview   vault.ImportPreview
	err       error
	path      string
	password  []byte
	cancel    context.CancelFunc
	aborted   bool
	effects   bool
	published map[string]string
	inflight  string
	errOwned  bool // m.err was set by an import job
}

// reset discards every secret-bearing buffer and the plan metadata.
func (s *importState) reset() {
	s.planID = 0
	s.staged.Close()
	clear(s.password)
	s.staged, s.password, s.preview, s.path, s.effects = nil, nil, vault.ImportPreview{}, "", false
	s.published, s.inflight = nil, ""
}

// owns reports that the import controls the destination: between the
// directory merge and completion no other edit may touch imported entries.
func (s *importState) owns() bool {
	return s.phase == ImportApplying || s.phase == ImportPartial
}

// InspectImport reads the archive on the owner worker; the destination is
// never touched. The outcome lives only in ImportStatus, never in m.err.
func (m *Manager) InspectImport(path string, password []byte) error {
	return m.inspectImportRequest(nil, path, password)
}
func (m *Manager) InspectImportAt(expected uint64, path string, password []byte) error {
	return m.inspectImportRequest(&expected, path, password)
}
func (m *Manager) inspectImportRequest(expected *uint64, path string, password []byte) error {
	if path == "" || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") || len(password) > 16384 {
		return errors.New("invalid owner import path or password")
	}
	owned := append([]byte(nil), password...)
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.imp.phase {
	case ImportInspecting, ImportStaged, ImportApplying, ImportPartial:
		clear(owned)
		return ErrPending
	}
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || m.jobs == nil || m.rotationBlocksMutation() || m.importSequence == ^uint64(0) {
		clear(owned)
		return ErrPending
	}
	err := m.admit(expected, func() error {
		m.imp.reset()
		m.importSequence++
		m.imp.planID = m.importSequence
		m.imp.phase, m.imp.err, m.imp.aborted = ImportInspecting, nil, false
		m.imp.path, m.imp.password = path, owned
		m.busy = true
		m.jobs <- ":import-inspect"
		m.signal()
		return nil
	})
	if err != nil {
		clear(owned)
	}
	return err
}

// inspectImport always returns nil so a bad archive or password cannot wedge
// the manager behind m.err.
func (m *Manager) inspectImport(ctx context.Context) error {
	m.mu.Lock()
	path, password := m.imp.path, m.imp.password
	m.imp.path, m.imp.password = "", nil
	m.mu.Unlock()
	defer clear(password)
	staged, err := m.readImport(ctx, path, password)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil && m.imp.aborted {
		staged.Close()
		staged, err = nil, ErrImportAborted
	}
	if err != nil {
		m.imp.phase, m.imp.err, m.imp.planID = ImportIdle, safeImportError(err), 0
		return nil
	}
	m.imp.staged, m.imp.preview, m.imp.phase, m.imp.err = staged, staged.Preview(), ImportStaged, nil
	return nil
}

func (m *Manager) HumanSSHAt(expected uint64, server, account string) (*ssh.ClientConfig, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing {
		return nil, "", ErrPending
	}
	return m.db.HumanSSHAt(expected, server, account)
}

func (m *Manager) linkStore(ctx context.Context) error {
	m.mu.Lock()
	link := copyLink(m.linking)
	m.mu.Unlock()
	if link == nil {
		return ErrPending
	}
	defer clearLink(link)
	resource, err := openResources(ctx, link)
	if err != nil {
		return err
	}
	retained := false
	defer func() {
		if !retained {
			resource.Close()
		}
	}()
	if err := m.db.Apply(func(v *vault.Vault) error { return v.LinkOwnerStore(*link) }); err != nil {
		return err
	}
	m.mu.Lock()
	m.link = copyLink(link)
	clearLink(m.linking)
	m.linking = nil
	m.mu.Unlock()
	m.resources, retained = resource, true
	return syncDatabase(ctx, m.path, m.db)
}

// importConflicts must be called with m.mu held; the staged plan is read-only
// while any other goroutine may be reading it.
func (m *Manager) importConflicts() ([]vault.ImportConflict, error) {
	conflicts, err := m.db.ImportConflicts(m.imp.staged)
	if err != nil {
		return nil, errImportEvaluate
	}
	if m.imp.staged.SecretCount() > 0 && !appstoreentry.Supported() {
		conflicts = append(conflicts, vault.ImportConflict{Kind: "runtime-unsupported", Subject: "linked values require the supported Linux owner runtime"})
	}
	return conflicts, nil
}

// ImportStatus is cheap and safe to poll; failures leave counts at zero.
func (m *Manager) ImportStatus() ImportStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.importStatus(nil)
}

func (m *Manager) importStatus(metadata *vault.DirectoryMetadata) ImportStatus {
	s := &m.imp
	status := ImportStatus{Phase: s.phase, PlanID: s.planID, Err: s.err, DirectoryApplied: s.effects}
	if s.phase == ImportIdle || s.phase == ImportInspecting {
		return status
	}
	status.Preview, status.Total = clonePreview(s.preview), len(s.preview.Secrets)
	// Only receipts count: a colliding foreign alias is never Published.
	if m.db != nil && len(s.published) > 0 {
		if metadata == nil {
			if current, err := m.db.Metadata(); err == nil {
				metadata = &current
			}
		}
		if metadata != nil {
			status.Published = importPublished(s.preview.Secrets, s.published, metadata.Secrets)
		}
	}
	if s.phase == ImportStaged && s.staged != nil {
		conflicts, err := m.importConflicts()
		if err != nil {
			conflicts = []vault.ImportConflict{{Kind: "destination-unavailable", Subject: "destination cannot be evaluated"}}
		}
		status.Conflicts = conflicts
	}
	return status
}

// ConfirmImport only queues the apply job; the TUI polls ImportStatus. The
// job re-checks conflicts authoritatively inside the directory merge.
func (m *Manager) ConfirmImport() error                  { return m.confirmImport(nil, nil) }
func (m *Manager) ConfirmImportAt(expected uint64) error { return m.confirmImport(&expected, nil) }
func (m *Manager) confirmImport(expected, plan *uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if plan != nil && (*plan == 0 || *plan != m.imp.planID) {
		return ErrPending
	}
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || m.jobs == nil || m.imp.phase != ImportStaged || m.imp.staged == nil || m.rotationBlocksMutation() {
		return ErrPending
	}
	conflicts, err := m.importConflicts()
	if err != nil {
		return err
	}
	if len(conflicts) != 0 {
		return vault.ErrImportConflict
	}
	return m.admit(expected, func() error {
		m.imp.phase, m.imp.err, m.imp.aborted = ImportApplying, nil, false
		m.busy = true
		m.jobs <- ":import-apply"
		m.signal()
		return nil
	})
}

// ResumeImport continues a partial import after any pending owner intent was
// resolved through ResumeDraft, Reconcile or CancelDraft. It is also the
// recovery path out of an import-originated m.err.
func (m *Manager) ResumeImport() error                  { return m.resumeImport(nil, nil) }
func (m *Manager) ResumeImportAt(expected uint64) error { return m.resumeImport(&expected, nil) }
func (m *Manager) resumeImport(expected, plan *uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if plan != nil && (*plan == 0 || *plan != m.imp.planID) {
		return ErrPending
	}
	if m.closed || m.closing || m.busy || m.pending != nil || m.db == nil || m.jobs == nil || m.imp.phase != ImportPartial || m.imp.staged == nil || m.rotationBlocksMutation() {
		return ErrPending
	}
	return m.admit(expected, func() error {
		m.imp.phase, m.imp.err, m.imp.aborted = ImportApplying, nil, false
		m.busy = true
		m.jobs <- ":import-resume"
		m.signal()
		return nil
	})
}

// AbortImport discards the plan. A partial import keeps whatever was already
// applied to the destination; only the retained RAM values are dropped. A
// running job is cancelled and settles the final state itself.
func (m *Manager) AbortImport() error                  { return m.abortImport(nil, nil) }
func (m *Manager) AbortImportAt(expected uint64) error { return m.abortImport(&expected, nil) }
func (m *Manager) abortImport(expected, plan *uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if plan != nil && (*plan == 0 || *plan != m.imp.planID) || m.rotationBlocksMutation() {
		return ErrPending
	}
	if expected != nil {
		if m.closed || m.closing || m.db == nil {
			return ErrPending
		}
		return m.db.AdmitAt(*expected, m.abortImportLocked)
	}
	return m.abortImportLocked()
}
func (m *Manager) abortImportLocked() error {
	switch m.imp.phase {
	case ImportInspecting, ImportApplying:
		m.imp.aborted = true
		if m.imp.cancel != nil {
			m.imp.cancel()
		}
	case ImportStaged, ImportComplete, ImportPartial:
		if m.busy {
			return ErrPending // a job is still settling its final state
		}
		if m.imp.phase == ImportPartial && m.imp.errOwned && m.pending == nil {
			m.err, m.imp.errOwned = nil, false
		}
		m.imp.reset()
		m.imp.phase, m.imp.err = ImportIdle, nil
		m.signal()
	}
	return nil
}

func copyIntent(pending *vault.OwnerIntent) *vault.OwnerIntent { return ownerclone.Intent(pending) }

// HumanSSH is the only credential path out of the manager: a host-pin verified
// client configuration for one human-permitted account, never raw bytes.
func (m *Manager) HumanSSH(serverID, account string) (*ssh.ClientConfig, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing {
		return nil, "", ErrPending
	}
	return m.db.HumanSSH(serverID, account)
}

// ServeText admits one fixed-grant consumer inside this keeper's installation.
func (m *Manager) ServeText(ctx context.Context, request ownerresource.TextRequest) (*ownerresource.Consumer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.link == nil || m.imp.owns() {
		return nil, ErrPending
	}
	if m.resources == nil {
		resource, err := openResources(ctx, m.link)
		if err != nil {
			return nil, err
		}
		m.resources = resource
	}
	return m.resources.ServeText(ctx, request)
}

// OutputGuard admits a private model-job capability, never an owner RPC value.
// History covers admitted snapshots; startup must seed before frozen consumers.
func (m *Manager) OutputGuard(ctx context.Context) (*outputguard.Snapshot, error) {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return nil, outputguard.ErrGuard
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || m.imp.owns() {
		return nil, outputguard.ErrGuard
	}
	metadata, status, digest, err := m.db.MetadataSnapshot()
	if err != nil || status.Err != nil || status.Pending || status.Revision != status.SavedRevision || digest == ([32]byte{}) {
		return nil, outputguard.ErrGuard
	}
	actual, err := cipherDigest(m.path)
	if err != nil || actual != digest {
		return nil, outputguard.ErrGuard
	}
	candidate, err := m.db.OutputGuardAt(status.Revision, digest)
	if err != nil {
		return nil, outputguard.ErrGuard
	}
	if m.link == nil && len(metadata.Secrets) != 0 {
		return nil, outputguard.ErrGuard
	}
	if m.link != nil {
		if m.resources == nil {
			resource, err := openResources(ctx, m.link)
			if err != nil {
				return nil, outputguard.ErrGuard
			}
			m.resources = resource
		}
		if m.resources.OpenEditor(ctx) != nil {
			return nil, outputguard.ErrGuard
		}
		linked, err := m.resources.Editor().OutputGuard(ctx, metadata.Secrets)
		if err != nil {
			return nil, outputguard.ErrGuard
		}
		candidate, err = outputguard.Union(candidate, linked)
		if err != nil || m.resources.Check() != nil {
			return nil, outputguard.ErrGuard
		}
	}
	if m.guardHistory != nil {
		candidate, err = outputguard.Union(m.guardHistory, candidate)
		if err != nil {
			return nil, outputguard.ErrGuard
		}
	}
	_, final, finalDigest, err := m.db.MetadataSnapshot()
	if err != nil || final.Err != nil || final.Pending || final.Revision != status.Revision || final.SavedRevision != status.Revision || finalDigest != digest || ctx.Err() != nil {
		return nil, outputguard.ErrGuard
	}
	actual, err = cipherDigest(m.path)
	if err != nil || actual != digest || ctx.Err() != nil {
		return nil, outputguard.ErrGuard
	}
	m.guardHistory = candidate
	return candidate, nil
}

// RememberRemoteMCPAt admits a preference only; it cannot authorize a bridge.
func (m *Manager) RememberRemoteMCPAt(ctx context.Context, expected uint64, digest [32]byte, profile string, selected []mcpdirectory.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || m.imp.owns() || m.rotationBlocksMutation() {
		return ErrPending
	}
	actual, err := cipherDigest(m.path)
	if err != nil || actual != digest {
		return mcpdirectory.ErrChanged
	}
	return m.db.RememberRemoteMCPAt(ctx, expected, digest, profile, selected)
}
