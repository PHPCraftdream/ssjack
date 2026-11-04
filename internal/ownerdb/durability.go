package ownerdb

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
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
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
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
		if err := m.resources.check(); err != nil {
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

// importAliasOwned is pure: an existing alias is import-owned only with a
// receipt for the exact same ref, or as the in-flight alias whose intent was
// resolved; name and scope must always equal the plan.
func importAliasOwned(secret vault.ImportSecret, binding vault.SecretBinding, receipts map[string]string, inflight string) bool {
	if binding.Name != secret.Name || binding.ServerID != secret.ServerID {
		return false
	}
	if ref, receipted := receipts[secret.AliasID]; receipted {
		return binding.Ref == ref
	}
	return inflight != "" && inflight == secret.AliasID
}

// adoptImportAlias receipts an existing alias when it is provably ours. An
// in-flight alias counts only once its owner intent is resolved (no pending).
func (m *Manager) adoptImportAlias(secret vault.ImportSecret, binding vault.SecretBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inflight := m.imp.inflight
	if m.pending != nil {
		inflight = ""
	}
	if !importAliasOwned(secret, binding, m.imp.published, inflight) {
		return errImportEntries
	}
	m.imp.receipt(secret.AliasID, binding.Ref)
	return nil
}

// recordImportReceipt stores the published ref as this import's receipt.
func (m *Manager) recordImportReceipt(secret vault.ImportSecret) error {
	metadata, err := m.db.Metadata()
	if err != nil {
		return err
	}
	binding, present := metadata.Secrets[secret.AliasID]
	if _, err := appstoreplaceholder.Parse([]byte(binding.Ref)); !present || err != nil || binding.Name != secret.Name || binding.ServerID != secret.ServerID {
		return errImportEntries
	}
	m.mu.Lock()
	m.imp.receipt(secret.AliasID, binding.Ref)
	m.mu.Unlock()
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
