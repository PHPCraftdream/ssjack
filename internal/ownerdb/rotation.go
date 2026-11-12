package ownerdb

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (m *Manager) ownerSnapshot(metadata vault.DirectoryMetadata, database vault.SessionStatus, digest [32]byte) (Snapshot, error) {
	rotation, err := m.rotationSnapshot()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Directory: metadata, Status: Status{Database: database, Busy: m.busy, Pending: m.pending != nil, Err: m.err}, Import: m.importStatus(&metadata), Rotation: rotation, CipherDigest: digest}, nil
}

func (m *Manager) rotationSnapshot() (*vault.RotationInfo, error) {
	info, err := m.db.RotationSnapshot()
	if err != nil || info.PlanID == 0 {
		return nil, err
	}
	return &info, nil
}

// PrepareRotation runs a keeper-backed rotation synchronously under m.mu; it
// reuses the session's unlocked context and excludes all manager writers.
func (m *Manager) PrepareRotation(ctx context.Context, revision uint64, serverID, account string) (ownerrotation.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rotationAdmission(false); err != nil {
		return ownerrotation.Plan{}, err
	}
	engine, err := m.rotationEngine()
	if err != nil {
		return ownerrotation.Plan{}, err
	}
	return engine.Prepare(ctx, revision, serverID, account)
}

// DecideRotation applies one closed, identity-bound operation. recover inspects;
// archive preserves the completed rotation's exact saved ciphertext locally.
func (m *Manager) DecideRotation(ctx context.Context, revision, planID uint64, id, action string) (ownerrotation.Plan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rotationAdmission(true); err != nil {
		return ownerrotation.Plan{}, err
	}
	if len(id) != 32 || planID == 0 {
		return ownerrotation.Plan{}, errors.New("invalid rotation identity")
	}
	switch action {
	case "recover", "install", "verify", "commit", "cancel", "archive":
	default:
		return ownerrotation.Plan{}, errors.New("unsupported rotation action")
	}
	info, err := m.db.RotationSnapshot()
	if err != nil || info.ID != id || info.PlanID != planID {
		return ownerrotation.Plan{}, vault.ErrOwnerRevision
	}
	engine, err := m.rotationEngine()
	if err != nil {
		return ownerrotation.Plan{}, err
	}
	switch action {
	case "recover":
		return engine.Inspect(ctx, revision, planID)
	case "archive":
		if info.Phase != vault.RotationComplete {
			return ownerrotation.Plan{}, errors.New("only a completed rotation may be archived")
		}
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return ownerrotation.Plan{}, err
		}
		archived, err := m.db.ArchiveRotationAt(ctx, m.path, revision, planID, id)
		if err != nil {
			return ownerrotation.Plan{}, err
		}
		if archived.ID != id || archived.PlanID != planID || archived.Phase != vault.RotationArchived {
			return ownerrotation.Plan{}, errors.New("rotation archive receipt did not match the selected plan")
		}
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return ownerrotation.Plan{}, err
		}
		plan, err := engine.Inspect(ctx, m.db.Status().Revision, planID)
		if err != nil {
			return ownerrotation.Plan{}, err
		}
		if plan.Info.ID != id || plan.Info.Phase != vault.RotationArchived {
			return ownerrotation.Plan{}, errors.New("durable rotation archive receipt unavailable")
		}
		return plan, nil
	case "install":
		if info.Phase != vault.RotationPrepared {
			return ownerrotation.Plan{}, errors.New("only a prepared rotation may install")
		}
		if err := engine.Install(ctx, revision, planID, true); err != nil {
			return ownerrotation.Plan{}, err
		}
		return engine.Inspect(ctx, m.db.Status().Revision, planID)
	case "verify":
		if err := engine.Verify(ctx, revision, planID); err != nil {
			return ownerrotation.Plan{}, err
		}
		return engine.Inspect(ctx, m.db.Status().Revision, planID)
	case "commit":
		plan, err := engine.Commit(ctx, revision, planID)
		if err != nil {
			return ownerrotation.Plan{}, err
		}
		return engine.Inspect(ctx, plan.Revision, planID)
	case "cancel":
		if err := engine.Cancel(ctx, revision, planID); err != nil {
			return ownerrotation.Plan{}, err
		}
		return engine.Inspect(ctx, m.db.Status().Revision, planID)
	default:
		return ownerrotation.Plan{}, errors.New("unsupported rotation action")
	}
}

func activeImportPhase(phase ImportPhase) bool {
	switch phase {
	case ImportInspecting, ImportStaged, ImportApplying, ImportPartial:
		return true
	default:
		return false
	}
}

func activeRotationInfo(info vault.RotationInfo) bool {
	switch info.Phase {
	case vault.RotationPrepared, vault.RotationAttempting, vault.RotationUnknown, vault.RotationAdded, vault.RotationVerified, vault.RotationCommitted:
		return true
	default:
		return false
	}
}

// rotationBlocksMutation fails closed if journal state cannot be read. Local
// database persistence retry remains a separate, explicitly local operation.
func (m *Manager) rotationBlocksMutation() bool {
	if m == nil || m.db == nil {
		return true
	}
	info, err := m.db.RotationSnapshot()
	return err != nil || activeRotationInfo(info)
}

func (m *Manager) rotationAdmission(deciding bool) error {
	if m == nil || m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || activeImportPhase(m.imp.phase) {
		return ErrPending
	}
	if !deciding {
		info, err := m.db.RotationSnapshot()
		if err != nil || activeRotationInfo(info) {
			return ErrPending
		}
	}
	status := m.db.Status()
	if status.Err != nil || status.Pending || status.Revision != status.SavedRevision {
		return ErrPending
	}
	return nil
}

func (m *Manager) rotationEngine() (*ownerrotation.Engine, error) {
	return ownerrotation.New(m.db, ownerrotation.SSHRemote{}, func(ctx context.Context) (ownerrotation.Evidence, error) {
		if err := syncDatabase(ctx, m.path, m.db); err != nil {
			return ownerrotation.Evidence{}, err
		}
		_, status, digest, err := m.db.MetadataSnapshot()
		if err != nil {
			return ownerrotation.Evidence{}, err
		}
		if status.Err != nil || status.Pending || digest == ([32]byte{}) {
			return ownerrotation.Evidence{}, ErrPending
		}
		return ownerrotation.Evidence{Revision: status.Revision, Digest: digest}, nil
	})
}
