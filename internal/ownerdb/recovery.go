package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (m *Manager) queueRecovery(command, phase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending == nil || m.pending.Phase != phase {
		return ErrPending
	}
	m.busy = true
	m.jobs <- command
	m.signal()
	return nil
}

// Reconcile requires a new explicit owner action; startup never calls it.
func (m *Manager) Reconcile() error { return m.queueRecovery(":reconcile", "prepared") }

func (m *Manager) ResumeDraft() error { return m.queueRecovery(":resume", "draft") }

func (m *Manager) CancelDraft() error { return m.queueRecovery(":cancel", "draft") }

func decodeOwnerID(text string) ([16]byte, error) {
	var id [16]byte
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(id) {
		return id, ErrPending
	}
	copy(id[:], decoded)
	return id, nil
}

func recoveryExpected(pending *vault.OwnerIntent) (appstorecrypto.OwnerRecoveryExpectation, error) {
	var expected appstorecrypto.OwnerRecoveryExpectation
	var err error
	expected.TransactionID, err = decodeOwnerID(pending.TransactionID)
	if err != nil {
		return expected, err
	}
	expected.SnapshotID, err = decodeOwnerID(pending.SnapshotID)
	if err != nil {
		return expected, err
	}
	previous, err := hex.DecodeString(pending.PreviousStateHash)
	if err != nil || len(previous) != len(expected.PreviousHash) {
		return expected, ErrPending
	}
	copy(expected.PreviousHash[:], previous)
	expected.Versions = make(map[[16]byte][16]byte, len(pending.Versions))
	for object, version := range pending.Versions {
		objectID, err := decodeOwnerID(object)
		if err != nil {
			return expected, err
		}
		versionID, err := decodeOwnerID(version)
		if err != nil {
			return expected, err
		}
		expected.Versions[objectID] = versionID
	}
	return expected, nil
}

func (m *Manager) reconcile(ctx context.Context) error {
	m.mu.Lock()
	pending := copyIntent(m.pending)
	confirmed := m.confirmed
	m.mu.Unlock()
	if pending == nil || pending.Phase != "prepared" {
		return ErrPending
	}
	defer clear(pending.Change.Value)
	if err := m.db.Retry(); err != nil {
		return err
	}
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	metadata, err := m.db.Metadata()
	if err != nil {
		return err
	}
	if confirmed != nil && metadata.OwnerStore != nil && metadata.OwnerStore.PendingID == "" {
		m.clearPending()
		return nil
	}
	if m.resources == nil {
		m.resources, err = openResources(ctx, m.link)
		if err != nil {
			return err
		}
	}
	if err := m.resources.check(); err != nil {
		return err
	}
	if m.resources.editor != nil {
		m.resources.editor.Close()
		m.resources.editor = nil
	}
	expected, err := recoveryExpected(pending)
	if err != nil {
		return err
	}
	writer, transport, err := m.resources.installation.Writer(m.resources.directory)
	if err != nil {
		return err
	}
	defer transport.Close()
	commit, err := writer.RecoverOwner(ctx, expected)
	undispatched := errors.Is(err, appstorecrypto.ErrOwnerUndispatched)
	burned := errors.Is(err, appstorecrypto.ErrWriterBurned) && commit.State.Valid() && commit.State.CommittedTransactionID() != expected.TransactionID && commit.State.CommittedSnapshotID() != expected.SnapshotID
	if undispatched || burned {
		var draft *vault.OwnerIntent
		if err := m.db.Apply(func(v *vault.Vault) error {
			if err := v.ReopenOwnerDraft(pending.ID, pending.TransactionID, pending.SnapshotID); err != nil {
				return err
			}
			draft = copyIntent(v.OwnerStore.Pending)
			return nil
		}); err != nil {
			if draft != nil {
				clear(draft.Change.Value)
			}
			return err
		}
		m.mu.Lock()
		clear(m.pending.Change.Value)
		m.pending, m.confirmed = draft, nil
		m.mu.Unlock()
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return err
		}
		return ErrPending
	}
	if err != nil {
		return err
	}
	transaction, snapshot := commit.State.CommittedTransactionID(), commit.State.CommittedSnapshotID()
	if err := m.db.Apply(func(v *vault.Vault) error {
		return v.FinishOwnerChange(pending.ID, hex.EncodeToString(transaction[:]), hex.EncodeToString(snapshot[:]), commit.Refs)
	}); err != nil {
		return err
	}
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	if m.resources != nil && m.resources.editor != nil {
		m.resources.editor.Close()
		m.resources.editor = nil
	}
	m.clearPending()
	return nil
}

func (m *Manager) clearPending() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil {
		clear(m.pending.Change.Value)
	}
	m.pending, m.confirmed = nil, nil
}

func (m *Manager) cancelDraft(ctx context.Context) error {
	m.mu.Lock()
	id := m.pending.ID
	m.mu.Unlock()
	if err := m.db.Apply(func(v *vault.Vault) error {
		if v.OwnerStore != nil && v.OwnerStore.Pending == nil {
			return nil
		}
		return v.CancelOwnerDraft(id)
	}); err != nil {
		return err
	}
	if err := m.db.Retry(); err != nil {
		return err
	}
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	if m.resources != nil && m.resources.editor != nil {
		m.resources.editor.Close()
		m.resources.editor = nil
	}
	m.clearPending()
	return nil
}
