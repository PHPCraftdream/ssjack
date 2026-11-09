package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (m *Manager) queueRecovery(expected *uint64, command, phase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending == nil || m.pending.Phase != phase {
		return ErrPending
	}
	return m.admit(expected, func() error {
		m.busy = true
		m.jobs <- command
		m.signal()
		return nil
	})
}

// Reconcile requires a new explicit owner action; startup never calls it.
func (m *Manager) Reconcile() error { return m.queueRecovery(nil, ":reconcile", "prepared") }
func (m *Manager) ReconcileAt(expected uint64) error {
	return m.queueRecovery(&expected, ":reconcile", "prepared")
}

func (m *Manager) ResumeDraft() error { return m.queueRecovery(nil, ":resume", "draft") }
func (m *Manager) ResumeDraftAt(expected uint64) error {
	return m.queueRecovery(&expected, ":resume", "draft")
}

func (m *Manager) CancelDraft() error { return m.queueRecovery(nil, ":cancel", "draft") }
func (m *Manager) CancelDraftAt(expected uint64) error {
	return m.queueRecovery(&expected, ":cancel", "draft")
}

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
	if err := m.resources.Check(); err != nil {
		return err
	}
	if m.resources.Editor() != nil {
		m.resources.ResetEditor()
	}
	expected, err := recoveryExpected(pending)
	if err != nil {
		return err
	}
	writer, transport, err := m.resources.Writer()
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
	m.importCommitted(pending.Change, commit.Refs)
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	if m.resources != nil && m.resources.Editor() != nil {
		m.resources.ResetEditor()
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
	if m.resources != nil && m.resources.Editor() != nil {
		m.resources.ResetEditor()
	}
	m.clearPending()
	return nil
}

// followImportCommit returns receipts advanced by one authenticated owner
// commit and whether the committed intent's own alias was receipted. Every
// dirty commit re-versions all objects and FinishOwnerChange moves every alias
// to the commit's ref for the same object ID, so earlier receipts may only
// follow the exact commit refs; unmatched receipts stay stale and later exact
// checks fail closed. A commit that is not the in-flight import intent never
// moves anything.
func followImportCommit(plan []vault.ImportSecret, receipts map[string]string, inflight string, current map[string]vault.SecretBinding, change vault.OwnerChange, refs []appstoreref.Ref) (map[string]string, bool) {
	next := make(map[string]string, len(receipts)+1)
	for alias, ref := range receipts {
		next[alias] = ref
	}
	if inflight == "" || inflight != change.AliasID {
		return next, false
	}
	byObject := make(map[[16]byte]appstoreref.Ref, len(refs))
	for _, ref := range refs {
		object := ref.ObjectID()
		if _, duplicate := byObject[object]; duplicate {
			return next, false
		}
		byObject[object] = ref
	}
	// exact encodes the commit ref when the alias's metadata equals it byte for byte.
	exact := func(binding vault.SecretBinding, ref appstoreref.Ref) (string, bool) {
		encoded, err := appstoreplaceholder.Encode(ref)
		return string(encoded), err == nil && binding.Ref == string(encoded)
	}
	own := false
	for _, secret := range plan {
		if secret.AliasID == change.AliasID {
			own = true
		}
		receipt, receipted := receipts[secret.AliasID]
		if !receipted {
			continue
		}
		old, err := appstoreplaceholder.Parse([]byte(receipt))
		if err != nil {
			continue
		}
		ref, found := byObject[old.ObjectID()]
		binding, exists := current[secret.AliasID]
		if !found || !exists || ref.StoreID() != old.StoreID() || binding.Name != secret.Name || binding.ServerID != secret.ServerID {
			continue
		}
		if encoded, same := exact(binding, ref); same {
			next[secret.AliasID] = encoded
		}
	}
	object, err := decodeOwnerID(change.ObjectID)
	ref, found := byObject[object]
	binding, exists := current[change.AliasID]
	if !own || err != nil || !found || !exists || binding.Name != change.Name || binding.ServerID != change.ServerID {
		return next, false
	}
	encoded, same := exact(binding, ref)
	if same {
		next[change.AliasID] = encoded
	}
	return next, same
}

// importCommitted receipts an authenticated owner commit for the import; the
// metadata is read before m.mu is taken.
func (m *Manager) importCommitted(change vault.OwnerChange, refs []appstoreref.Ref) {
	metadata, err := m.db.Metadata()
	if err != nil {
		return
	}
	m.importCommittedWith(change, refs, metadata.Secrets)
}

func (m *Manager) importCommittedWith(change vault.OwnerChange, refs []appstoreref.Ref, secrets map[string]vault.SecretBinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.imp.owns() {
		return
	}
	next, ok := followImportCommit(m.imp.preview.Secrets, m.imp.published, m.imp.inflight, secrets, change, refs)
	if len(next) > 0 || ok {
		m.imp.published = next
	}
	if ok {
		m.imp.inflight = ""
	}
}
