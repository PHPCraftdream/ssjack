package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

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
