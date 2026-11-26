// Package ownerdb coordinates trusted-local owner operations, never MCP tools.
package ownerdb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerclone"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var ErrPending = errors.New("owner change requires explicit inspection or database-save recovery")

type Status struct {
	Database vault.SessionStatus
	Busy     bool
	Pending  bool
	Err      error
}

type Manager struct {
	mu             sync.Mutex
	closeMu        sync.Mutex
	path           string
	db             *vault.Session
	link           *vault.OwnerStore
	linking        *vault.OwnerStore
	pending        *vault.OwnerIntent
	confirmed      *appstorecrypto.SnapshotCommit
	resources      *resources
	guardHistory   *outputguard.Snapshot
	exportRequest  *ExportRequest
	busy, rotating bool
	closed         bool
	closing        bool
	err            error
	imp            importState
	importSequence uint64
	verify         DescriptorVerifier
	approvalUsed   bool
	jobs           chan string
	changed        chan struct{}
	done           chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
}

func Open(ctx context.Context, path string, password []byte) (*Manager, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("owner session requires an active context")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	loaded, err := vault.Load(absolute, password)
	if err != nil {
		return nil, err
	}
	return Adopt(ctx, absolute, loaded)
}

// Adopt consumes one authenticated unchanged vault without another KDF.
func Adopt(ctx context.Context, path string, loaded *vault.Vault) (*Manager, error) {
	if loaded == nil {
		return nil, errors.New("owner adoption requires an authenticated vault")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		loaded.Close()
		return nil, err
	}
	link := copyLink(loaded.OwnerStore)
	db, err := vault.StartSession(ctx, absolute, loaded)
	if err != nil {
		clearLink(link)
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	m := &Manager{path: absolute, db: db, link: link, jobs: make(chan string, 1), changed: make(chan struct{}), done: make(chan struct{}), ctx: lifetime, cancel: cancel}
	if link != nil && link.Pending != nil {
		m.pending = copyIntent(link.Pending)
		m.err = ErrPending
	}
	go m.run()
	return m, nil
}

func copyLink(link *vault.OwnerStore) *vault.OwnerStore { return ownerclone.Link(link) }
func clearLink(link *vault.OwnerStore)                  { ownerclone.ClearLink(link) }

func (m *Manager) AcceptOwner(ctx context.Context) (ownerlocal.Connection, error) {
	return m.db.AcceptOwner(ctx)
}

func (m *Manager) ConfirmImportPlanAt(expected, plan uint64) error {
	return m.confirmImport(&expected, &plan)
}
func (m *Manager) ResumeImportPlanAt(expected, plan uint64) error {
	return m.resumeImport(&expected, &plan)
}
func (m *Manager) AbortImportPlanAt(expected, plan uint64) error {
	return m.abortImport(&expected, &plan)
}

func (m *Manager) signal() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *Manager) Export(request ExportRequest) error { return m.export(nil, request) }
func (m *Manager) ExportAt(expected uint64, request ExportRequest) error {
	return m.export(&expected, request)
}

func (m *Manager) Metadata() (vault.DirectoryMetadata, error) { return m.db.Metadata() }

// SnapshotVault preserves the last persisted ciphertext of this session.
func (m *Manager) SnapshotVault() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.db == nil {
		return "", errors.New("database session is not open")
	}
	return m.db.SnapshotSaved(m.path)
}

// approvalSnapshotRetention bounds approval-snapshot files per vault.
const (
	approvalSnapshotLabel     = "approval-snapshot"
	approvalSnapshotRetention = 10
)

type ApprovalMutation struct {
	Kind           string
	Name, Path     string
	Hash, Replaces string
}

var ErrApprovalReview = errors.New("owner approval review state changed")

// DescriptorVerifier re-derives the descriptor fingerprint from the file at
// application_path on the keeper machine (section 4.2.1); slice 3 wires the
// real verifier from internal/application/discovery.
type DescriptorVerifier func(path string) (hash string, err error)

// SetDescriptorVerifier installs the keeper-side descriptor fingerprint
// verifier; call it before the first approval write. Slice 3 wires it at keeper
// manager construction. It cannot be replaced afterwards; approvals fail closed
// when no verifier is configured.
func (m *Manager) SetDescriptorVerifier(verifier DescriptorVerifier) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.approvalUsed || verifier == nil {
		return errors.New("descriptor verifier must be installed once, before the first approval write")
	}
	m.verify = verifier
	return nil
}

// ApproveWithSnapshot pins the review and snapshot to the same manager state.
func (m *Manager) ApproveWithSnapshot(ctx context.Context, expected uint64, mut ApprovalMutation) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.imp.owns() || m.db == nil || m.rotationBlocksMutation() {
		return ErrPending
	}
	if mut.Kind == "approve" {
		if m.verify == nil {
			return ErrApprovalReview
		}
		hash, err := m.verify(mut.Path)
		if err != nil || !lowerHex(hash) || !lowerHex(mut.Hash) || hash != mut.Hash {
			return ErrApprovalReview
		}
	}
	if err := verifyApprovalReview(m.db, expected, mut); err != nil {
		return err
	}
	if err := vault.PruneSnapshots(m.path, approvalSnapshotLabel, approvalSnapshotRetention-1); err != nil {
		return err
	}
	if _, err := m.db.SnapshotSaved(m.path); err != nil {
		return err
	}
	if err := m.db.ApplyAt(expected, func(v *vault.Vault) error { return applyApprovalMutation(v, mut) }); err != nil {
		return approvalApplyError(err)
	}
	m.approvalUsed = true
	return m.db.Flush(ctx)
}

func lowerHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func verifyApprovalReview(db *vault.Session, expected uint64, mut ApprovalMutation) error {
	status := db.Status()
	if expected != status.Revision {
		return vault.ErrOwnerRevision
	}
	metadata, err := db.Metadata()
	if err != nil {
		return err
	}
	switch mut.Kind {
	case "approve":
		if mut.Replaces == "" {
			return nil
		}
		for _, record := range metadata.Approvals {
			if record.Name == mut.Name && record.Hash == mut.Replaces {
				return nil
			}
		}
	case "revoke":
		for _, record := range metadata.Approvals {
			if record.Name == mut.Name && filepath.Clean(record.Path) == filepath.Clean(mut.Path) && record.Hash == mut.Replaces {
				return nil
			}
		}
	default:
		return errors.New("approval mutation kind is invalid")
	}
	return fmt.Errorf("%w: reviewed approval state no longer matches the live record", ErrApprovalReview)
}

func applyApprovalMutation(v *vault.Vault, mut ApprovalMutation) error {
	switch mut.Kind {
	case "approve":
		if vault.ValidateApprovalName(mut.Name) != nil {
			return errors.New("name_invalid")
		}
		if err := validApprovalPath(mut.Path); err != nil {
			if len(mut.Path) > 512 {
				return errors.New("path_limit_exceeded")
			}
			return errors.New("path_invalid")
		}
		return v.ApproveApplication(vault.Approval{Name: mut.Name, Path: mut.Path, Hash: mut.Hash}, mut.Replaces)
	case "revoke":
		records, err := vault.ListApplicationApprovals(v)
		if err != nil {
			return errors.New("revoke_stale")
		}
		found := false
		for _, record := range records {
			if record.Name != mut.Name {
				continue
			}
			if filepath.Clean(record.Path) != filepath.Clean(mut.Path) || record.Hash != mut.Replaces {
				return errors.New("revoke_stale")
			}
			found = true
			break
		}
		if !found {
			return errors.New("revoke_stale")
		}
		if err := v.RevokeApplication(mut.Name); err != nil {
			return errors.New("revoke_failed")
		}
		return nil
	default:
		return errors.New("mutation_invalid")
	}
}

func validApprovalPath(p string) error {
	if p == "" || len(p) > 512 {
		return errors.New("path_invalid")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return errors.New("path_invalid")
		}
	}
	if !filepath.IsAbs(p) || p != filepath.Clean(p) {
		return errors.New("path_invalid")
	}
	return nil
}

func approvalApplyError(err error) error {
	if errors.Is(err, vault.ErrOwnerRevision) {
		return err
	}
	switch err.Error() {
	case "revoke_stale",
		"application approval already exists; pass the reviewed descriptor hash to replace it",
		"replaced approval does not match the reviewed descriptor hash",
		"application approval does not exist":
		return fmt.Errorf("%w: %s", ErrApprovalReview, err.Error())
	}
	return err
}

// Edit is a trusted owner form callback, not a public model-facing getter.
// While an import is applying or partial it is refused: an edit to an imported
// account or alias between a failure and resume would otherwise go unnoticed.
func (m *Manager) Edit(edit func(*vault.Vault) error) error { return m.edit(nil, edit) }
func (m *Manager) EditAt(expected uint64, edit func(*vault.Vault) error) error {
	return m.edit(&expected, edit)
}
func (m *Manager) edit(expected *uint64, edit func(*vault.Vault) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || edit == nil || m.imp.owns() || m.rotationBlocksMutation() {
		return ErrPending
	}
	apply := m.db.Apply
	if expected != nil {
		apply = func(edit func(*vault.Vault) error) error { return m.db.ApplyAt(*expected, edit) }
	}
	return apply(func(v *vault.Vault) error {
		owner := copyLink(v.OwnerStore)
		defer clearLink(owner)
		aliases := make(map[string]vault.SecretBinding, len(v.Secrets))
		for id, alias := range v.Secrets {
			aliases[id] = alias
		}
		if err := edit(v); err != nil {
			return err
		}
		if !reflect.DeepEqual(owner, v.OwnerStore) || !reflect.DeepEqual(aliases, v.Secrets) {
			return errors.New("server forms cannot change linked owner material or secret bindings")
		}
		return nil
	})
}

func (m *Manager) Submit(change vault.OwnerChange) error { return m.submit(nil, change) }
func (m *Manager) SubmitAt(expected uint64, change vault.OwnerChange) error {
	return m.submit(&expected, change)
}
func (m *Manager) submit(expected *uint64, change vault.OwnerChange) error {
	if !appstoreentry.Supported() {
		return errors.New("linked secret editing requires a supported native owner runtime")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.link == nil || m.imp.owns() || m.rotationBlocksMutation() {
		return ErrPending
	}
	var pending *vault.OwnerIntent
	apply := m.db.Apply
	if expected != nil {
		apply = func(edit func(*vault.Vault) error) error { return m.db.ApplyAt(*expected, edit) }
	}
	err := apply(func(v *vault.Vault) error {
		if _, err := v.StageOwnerChange(change); err != nil {
			return err
		}
		pending = copyIntent(v.OwnerStore.Pending)
		return nil
	})
	if err != nil {
		if pending != nil {
			clear(pending.Change.Value)
		}
		return err
	}
	m.pending, m.busy = pending, true
	m.jobs <- pending.ID
	m.signal()
	return nil
}

func (m *Manager) admit(expected *uint64, publish func() error) error {
	if expected == nil {
		return publish()
	}
	if m.db == nil {
		return ErrPending
	}
	return m.db.AdmitAt(*expected, publish)
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{Database: m.db.Status(), Busy: m.busy, Pending: m.pending != nil, Err: m.err}
}

func (m *Manager) Flush(ctx context.Context) error {
	for {
		m.mu.Lock()
		if !m.busy {
			err, pending := m.err, m.pending != nil
			m.mu.Unlock()
			if err != nil {
				return err
			}
			if pending {
				return ErrPending
			}
			return m.db.Flush(ctx)
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (m *Manager) Close(ctx context.Context) error {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closing = true
	m.mu.Unlock()
	if err := m.Flush(ctx); err != nil {
		m.mu.Lock()
		m.closing = false
		m.mu.Unlock()
		return err
	}
	if err := m.resources.CloseConsumers(ctx); err != nil {
		m.mu.Lock()
		m.closing = false
		m.mu.Unlock()
		return err
	}
	if err := m.db.Close(ctx); err != nil {
		m.mu.Lock()
		m.closing = false
		m.mu.Unlock()
		return err
	}
	m.stop()
	return nil
}

// Discard must follow explicit owner confirmation of any unsaved/pending state.
func (m *Manager) Discard() {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.stop()
	m.db.Discard()
}

func (m *Manager) stop() {
	m.lockAfterRotation()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	if m.imp.cancel != nil {
		m.imp.cancel()
	}
	m.signal()
	m.mu.Unlock()
	<-m.done
	m.resources.Close()
	clearLink(m.link)
	clearLink(m.linking)
	if m.pending != nil {
		clear(m.pending.Change.Value)
	}
	// Staged import material is RAM-only and is discarded on exit.
	m.mu.Lock()
	m.imp.reset()
	m.guardHistory = nil
	m.imp.phase = ImportIdle
	m.mu.Unlock()
}
