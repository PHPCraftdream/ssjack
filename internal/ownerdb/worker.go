package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (m *Manager) run() {
	defer close(m.done)
	for {
		select {
		case <-m.ctx.Done():
			return
		case id := <-m.jobs:
			ctx, cancel := m.jobContext(id)
			var err error
			switch id {
			case ":import-inspect":
				err = m.inspectImport(ctx)
			case ":import-apply":
				err = m.importArchive(ctx, false)
			case ":import-resume":
				err = m.importArchive(ctx, true)
			case ":export":
				m.mu.Lock()
				request := m.exportRequest
				m.mu.Unlock()
				if request == nil {
					err = ErrPending
				} else {
					err = m.exportArchive(ctx, *request)
				}
			case ":link":
				err = m.linkStore(ctx)
			case ":save":
				err = m.db.Retry()
				if err == nil {
					err = syncDatabase(ctx, m.path, m.db)
				}
			case ":reconcile":
				err = m.reconcile(ctx)
			case ":cancel":
				err = m.cancelDraft(ctx)
			case ":resume":
				if m.resources != nil && m.resources.editor != nil {
					m.resources.editor.Close()
					m.resources.editor = nil
				}
				m.mu.Lock()
				pendingID := m.pending.ID
				m.mu.Unlock()
				err = m.db.Retry()
				if err == nil {
					err = m.process(ctx, pendingID)
				}
			default:
				err = m.process(ctx, id)
			}
			cancel()
			m.mu.Lock()
			m.busy, m.err = false, err
			m.imp.cancel = nil
			m.imp.errOwned = err != nil && strings.HasPrefix(id, ":import-")
			if id == ":export" {
				m.exportRequest = nil
			}
			m.signal()
			m.mu.Unlock()
		}
	}
}

// jobContext bounds a job; import jobs also publish their cancel func so
// AbortImport can stop them before the next secret.
func (m *Manager) jobContext(id string) (context.Context, context.CancelFunc) {
	timeout := time.Minute
	m.mu.Lock()
	defer m.mu.Unlock()
	switch id {
	case ":import-inspect":
		timeout = 5 * time.Minute
	case ":import-apply", ":import-resume":
		timeout = min(time.Duration(1+m.imp.staged.SecretCount())*time.Minute, 130*time.Minute)
	}
	ctx, cancel := context.WithTimeout(m.ctx, timeout)
	if strings.HasPrefix(id, ":import-") {
		m.imp.cancel = cancel
	}
	return ctx, cancel
}

// importStopped reports an operator abort before a context timeout.
func (m *Manager) importStopped(ctx context.Context) error {
	m.mu.Lock()
	aborted := m.imp.aborted
	m.mu.Unlock()
	if aborted {
		return ErrImportAborted
	}
	return ctx.Err()
}

// safeImportError maps everything to fixed text that cannot hold archive content.
func safeImportError(err error) error {
	switch {
	case errors.Is(err, ownerarchive.ErrAuthentication):
		return ownerarchive.ErrAuthentication
	case errors.Is(err, ownerarchive.ErrArchive), errors.Is(err, vault.ErrImportInvalid):
		return ownerarchive.ErrArchive
	case errors.Is(err, vault.ErrImportConflict):
		return vault.ErrImportConflict
	case errors.Is(err, vault.ErrImportChanged):
		return vault.ErrImportChanged
	case errors.Is(err, errImportEntries):
		return errImportEntries
	case errors.Is(err, ErrImportAborted):
		return ErrImportAborted
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return errImportInterrupted
	case errors.Is(err, ErrPending):
		return ErrPending
	}
	return errImportFailed
}

func clonePreview(p vault.ImportPreview) vault.ImportPreview {
	out := vault.ImportPreview{Encrypted: p.Encrypted, Servers: make([]vault.ImportServer, 0, len(p.Servers)), Secrets: append([]vault.ImportSecret{}, p.Secrets...), Conflicts: append([]vault.ImportConflict{}, p.Conflicts...)}
	for _, server := range p.Servers {
		server.Fingerprints = append([]string{}, server.Fingerprints...)
		server.Accounts = append([]vault.ImportAccount(nil), server.Accounts...)
		out.Servers = append(out.Servers, server)
	}
	return out
}

func (m *Manager) process(ctx context.Context, id string) error {
	m.mu.Lock()
	pending := copyIntent(m.pending)
	m.mu.Unlock()
	if pending == nil || pending.ID != id || pending.Phase != "draft" {
		return ErrPending
	}
	defer clear(pending.Change.Value)
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	if m.resources == nil {
		resource, err := openResources(ctx, m.link)
		if err != nil {
			return err
		}
		m.resources = resource
	}
	if err := m.resources.openEditor(ctx); err != nil {
		return err
	}
	object, err := m.applyValue(pending.Change)
	if errors.Is(err, errAliasOnly) {
		if err := m.db.Apply(func(v *vault.Vault) error {
			if err := v.CancelOwnerDraft(id); err != nil {
				return err
			}
			return v.RemoveSecretBinding(pending.Change.AliasID)
		}); err != nil {
			return err
		}
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return err
		}
		m.mu.Lock()
		clear(m.pending.Change.Value)
		m.pending = nil
		m.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	commit, err := m.resources.editor.CommitPrepared(ctx, func(ctx context.Context, proposal appstorecrypto.OwnerWriteProposal) error {
		if err := m.resources.check(); err != nil {
			return err
		}
		versions := make(map[string]string, len(proposal.References))
		for _, reference := range proposal.References {
			storeID, selected, version, snapshot := reference.StoreID(), reference.ObjectID(), reference.VersionID(), reference.SnapshotID()
			if hex.EncodeToString(storeID[:]) != m.link.StoreID || snapshot != proposal.SnapshotID {
				return errors.New("owner proposal identity mismatch")
			}
			versions[hex.EncodeToString(selected[:])] = hex.EncodeToString(version[:])
		}
		previous := proposal.Previous.Hash()
		transaction, snapshot := hex.EncodeToString(proposal.TransactionID[:]), hex.EncodeToString(proposal.SnapshotID[:])
		var prepared *vault.OwnerIntent
		if err := m.db.Apply(func(v *vault.Vault) error {
			if err := v.PrepareOwnerChange(id, transaction, snapshot, hex.EncodeToString(previous[:]), object, versions); err != nil {
				return err
			}
			prepared = copyIntent(v.OwnerStore.Pending)
			return nil
		}); err != nil {
			if prepared != nil {
				clear(prepared.Change.Value)
			}
			return err
		}
		m.mu.Lock()
		clear(m.pending.Change.Value)
		m.pending = prepared
		m.mu.Unlock()
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return err
		}
		return m.resources.check()
	})
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.confirmed = &commit
	prepared := copyIntent(m.pending)
	m.mu.Unlock()
	if prepared == nil || prepared.Phase != "prepared" {
		return ErrPending
	}
	defer clear(prepared.Change.Value)
	transaction, snapshot := commit.State.CommittedTransactionID(), commit.State.CommittedSnapshotID()
	if err := m.db.Apply(func(v *vault.Vault) error {
		return v.FinishOwnerChange(id, hex.EncodeToString(transaction[:]), hex.EncodeToString(snapshot[:]), commit.Refs)
	}); err != nil {
		return err
	}
	m.importCommitted(prepared.Change, commit.Refs)
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	m.mu.Lock()
	clear(m.pending.Change.Value)
	m.pending, m.confirmed = nil, nil
	m.mu.Unlock()
	return nil
}
