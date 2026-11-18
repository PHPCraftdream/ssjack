package ownerdb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerclone"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerpublication"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func cipherDigest(path string) ([32]byte, error) {
	var result [32]byte
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > keyfile.MaxSize {
		return result, errors.New("owner database is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return result, errors.New("owner database identity changed")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, keyfile.MaxSize+1))
	if err != nil || n > keyfile.MaxSize {
		return result, errors.New("owner database ciphertext could not be checked")
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func syncDatabase(ctx context.Context, path string, db *vault.Session) error {
	if err := db.Flush(ctx); err != nil {
		return err
	}
	expected, err := db.SavedCipherDigest()
	if err != nil {
		return err
	}
	before, err := cipherDigest(path)
	if err != nil || before != expected {
		return errors.New("owner database changed before durable intent publication")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ownerpublication.Sync(path); err != nil {
		return err
	}
	after, err := cipherDigest(path)
	if err != nil || after != expected {
		return errors.New("owner database changed during durable intent publication")
	}
	return ctx.Err()
}

// errImportEntries is fixed text for an alias this import cannot prove it owns.
var errImportEntries = errors.New("imported entries changed")

// importArchive runs steps in a fixed order on the single worker. Its return
// value becomes m.err only when destination effects exist; a failure without
// effects leaves the plan staged and the manager fully usable.
func (m *Manager) importArchive(ctx context.Context, resume bool) error {
	m.mu.Lock()
	staged := m.imp.staged
	m.mu.Unlock()
	effects := resume
	err := m.applyImport(ctx, staged, resume, &effects)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imp.effects = effects
	if err != nil && m.imp.aborted {
		err = ErrImportAborted
	}
	switch {
	case err == nil:
		staged.Close()
		m.imp.staged, m.imp.phase, m.imp.err = nil, ImportComplete, nil
		return nil
	case !effects:
		m.imp.err = safeImportError(err)
		m.imp.phase = ImportStaged
		if errors.Is(err, ErrImportAborted) {
			m.imp.reset()
			m.imp.phase = ImportIdle
		}
		return nil
	}
	m.imp.phase, m.imp.err = ImportPartial, safeImportError(err)
	return err
}

func (m *Manager) applyImport(ctx context.Context, staged *vault.OwnerImport, resume bool, effects *bool) error {
	if err := m.importStopped(ctx); err != nil {
		return err
	}
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	preview := staged.Preview()
	if len(preview.Secrets) > 0 {
		// The store must be reachable before any destination mutation.
		if m.resources == nil {
			resource, err := openResources(ctx, m.link)
			if err != nil {
				return err
			}
			m.resources = resource
		}
		if err := m.resources.Check(); err != nil {
			return err
		}
	}
	if resume {
		// Exact proof that servers, accounts and credentials are still ours.
		if err := m.db.VerifyOwnerImportDirectory(staged); err != nil {
			return err
		}
	} else {
		if err := m.db.ApplyOwnerImportDirectory(staged); err != nil {
			return err
		}
		*effects = true
		m.mu.Lock()
		m.imp.effects = true
		m.mu.Unlock()
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return err
		}
	}
	for index, secret := range preview.Secrets {
		// Abort and timeouts stop before the next secret is staged.
		if err := m.importStopped(ctx); err != nil {
			return err
		}
		metadata, err := m.db.Metadata()
		if err != nil {
			return err
		}
		if binding, present := metadata.Secrets[secret.AliasID]; present {
			// Never skip or overwrite an alias this import cannot prove it published.
			if err := m.adoptImportAlias(secret, binding); err != nil {
				return err
			}
			continue
		}
		id, err := m.stageImportSecret(staged, index)
		if err != nil {
			return err
		}
		if err := m.process(ctx, id); err != nil {
			return err
		}
		if err := m.recordImportReceipt(secret); err != nil {
			return err
		}
	}
	return nil
}

// importPublished counts plan secrets whose alias still carries exactly the
// receipted ref under the plan's name and scope.
func importPublished(plan []vault.ImportSecret, receipts map[string]string, current map[string]vault.SecretBinding) int {
	count := 0
	for _, secret := range plan {
		receipt, receipted := receipts[secret.AliasID]
		binding, exists := current[secret.AliasID]
		if receipted && exists && binding.Name == secret.Name && binding.ServerID == secret.ServerID && binding.Ref == receipt {
			count++
		}
	}
	return count
}

// importAliasOwned is pure: an existing alias is import-owned only when its
// ref equals the receipt exactly (receipts advance solely via importCommitted)
// and name and scope equal the plan.
func importAliasOwned(secret vault.ImportSecret, binding vault.SecretBinding, receipts map[string]string) bool {
	receipt, receipted := receipts[secret.AliasID]
	return receipted && binding.Name == secret.Name && binding.ServerID == secret.ServerID && binding.Ref == receipt
}

// adoptImportAlias only checks ownership; it never writes a receipt.
func (m *Manager) adoptImportAlias(secret vault.ImportSecret, binding vault.SecretBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !importAliasOwned(secret, binding, m.imp.published) {
		return errImportEntries
	}
	return nil
}

// recordImportReceipt verifies that the commit hook already receipted the
// published alias; metadata alone never creates or moves a receipt.
func (m *Manager) recordImportReceipt(secret vault.ImportSecret) error {
	metadata, err := m.db.Metadata()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !importAliasOwned(secret, metadata.Secrets[secret.AliasID], m.imp.published) {
		return errImportEntries
	}
	return nil
}

// stageImportSecret stages the same durable owner intent Submit does; the
// existing explicit recovery owns it if publication fails.
func (m *Manager) stageImportSecret(staged *vault.OwnerImport, index int) (string, error) {
	change, err := staged.SecretChange(index)
	if err != nil {
		return "", err
	}
	defer clear(change.Value)
	var pending *vault.OwnerIntent
	err = m.db.Apply(func(v *vault.Vault) error {
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
		return "", err
	}
	m.mu.Lock()
	m.pending, m.imp.inflight = pending, change.AliasID
	m.mu.Unlock()
	return pending.ID, nil
}

type Snapshot struct {
	Directory    vault.DirectoryMetadata
	Status       Status
	Import       ImportStatus
	Rotation     *vault.RotationInfo
	CipherDigest [32]byte
}

func (m *Manager) Snapshot() (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.db == nil {
		return Snapshot{}, ErrPending
	}
	metadata, database, digest, err := m.db.MetadataSnapshot()
	if err != nil {
		return Snapshot{}, err
	}
	return m.ownerSnapshot(metadata, database, digest)
}

func (m *Manager) OwnerPeer(binding [32]byte) (*ownerpacket.Server, error) {
	return m.db.OwnerPeer(m.path, binding)
}
func (m *Manager) OwnerBinding() ([32]byte, error) { return m.db.OwnerBinding() }

func (m *Manager) LocalOwnerPeer(binding [32]byte) (*ownerpacket.Client, error) {
	return m.db.LocalOwnerPeer(binding)
}
func (m *Manager) MetadataSnapshot() (vault.DirectoryMetadata, vault.SessionStatus, [32]byte, error) {
	return m.db.MetadataSnapshot()
}

func (m *Manager) AgentSSHAt(expected uint64, digest [32]byte, profile string) (*ssh.ClientConfig, string, string, error) {
	return m.db.AgentSSHAt(expected, digest, profile)
}

func clonePreview(p vault.ImportPreview) vault.ImportPreview { return ownerclone.Preview(p) }

func (m *Manager) readImport(ctx context.Context, path string, password []byte) (*vault.OwnerImport, error) {
	if err := m.importStopped(ctx); err != nil {
		return nil, err
	}
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return nil, err
	}
	opened, err := ownerarchive.ReadFile(ctx, path, password)
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	return vault.ParseOwnerImport(opened)
}

func (m *Manager) queueRecovery(expected *uint64, command, phase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending == nil || m.pending.Phase != phase || m.rotationBlocksMutation() {
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

func (m *Manager) SetSSHStatus(status func() sshstatus.Status) { m.db.SetSSHStatus(status) }

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
