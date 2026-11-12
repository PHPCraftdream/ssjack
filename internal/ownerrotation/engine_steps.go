package ownerrotation

import (
	"bytes"
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Install records and durably saves attempting before the only Add call. Every
// Add error, including a lost acknowledgement, becomes unknown and is not retried.
func (e *Engine) Install(ctx context.Context, expected, planID uint64, confirmed bool) error {
	if err := e.available(); err != nil {
		return err
	}
	ctx, cancel, err := operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !confirmed {
		return errors.New("key addition requires explicit owner confirmation")
	}
	info, err := e.require(ctx, expected, planID, vault.RotationPrepared)
	if err != nil {
		return err
	}
	original, replacement, err := e.keeper.RotationMaterialAt(expected, planID)
	if err != nil {
		return err
	}
	defer clearTarget(&original)
	defer clearTarget(&replacement)
	if err := e.preflightAdd(ctx, original, replacement, info); err != nil {
		return err
	}
	if err := e.keeper.SetRotationPhaseAt(expected, planID, vault.RotationAttempting); err != nil {
		return err
	}
	attemptRevision := e.keeper.Status().Revision
	if _, err := e.durable(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	addCtx, stop := context.WithTimeout(ctx, 30*time.Second)
	err = e.remote.Add(addCtx, original, info.OldPublic, info.NewPublic)
	stop()
	if err != nil {
		if phaseErr := e.keeper.SetRotationPhaseAt(attemptRevision, planID, vault.RotationUnknown); phaseErr == nil {
			_, _ = e.durable(ctx)
		}
		return errors.Join(ErrUncertain, err)
	}
	if err := e.keeper.SetRotationPhaseAt(attemptRevision, planID, vault.RotationAdded); err != nil {
		return err
	}
	_, err = e.durable(ctx)
	return err
}

// preflightAdd rejects every no-effect failure while the plan is still prepared:
// attempting cannot be cancelled, so it must not be persisted for a doomed Add.
func (e *Engine) preflightAdd(ctx context.Context, original, replacement vault.Target, info vault.RotationInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < minAddWindow {
		return errors.New("insufficient time remains for key addition; rotation stays prepared")
	}
	return e.remote.Preflight(ctx, original, replacement, info.OldPublic, info.NewPublic)
}

// Verify is recovery-safe and uses only the replacement key. Attempting after
// restart is also verify-only; Add is never replayed.
func (e *Engine) Verify(ctx context.Context, expected, planID uint64) error {
	if err := e.available(); err != nil {
		return err
	}
	ctx, cancel, err := operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	info, err := e.keeper.RotationAt(expected, planID)
	if err != nil {
		return err
	}
	switch info.Phase {
	case vault.RotationAttempting, vault.RotationUnknown, vault.RotationAdded:
	default:
		return errors.New("key rotation is not awaiting new-key-only verification")
	}
	if _, err := e.require(ctx, expected, planID, info.Phase); err != nil {
		return err
	}
	original, replacement, err := e.keeper.RotationMaterialAt(expected, planID)
	if err != nil {
		return err
	}
	defer clearTarget(&original)
	defer clearTarget(&replacement)
	if err := ctx.Err(); err != nil {
		return err
	}
	verifyCtx, stop := context.WithTimeout(ctx, 30*time.Second)
	err = e.remote.Verify(verifyCtx, replacement)
	stop()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.keeper.SetRotationPhaseAt(expected, planID, vault.RotationVerified); err != nil {
		return err
	}
	_, err = e.durable(ctx)
	return err
}

// Commit completes a verified plan or recovers an already committed one. The
// exact saved revision and ciphertext digest are recorded before completion.
func (e *Engine) Commit(ctx context.Context, expected, planID uint64) (Plan, error) {
	if err := e.available(); err != nil {
		return Plan{}, err
	}
	ctx, cancel, err := operation(ctx)
	if err != nil {
		return Plan{}, err
	}
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	info, err := e.keeper.RotationAt(expected, planID)
	if err != nil {
		return Plan{}, err
	}
	if info.Phase != vault.RotationVerified && info.Phase != vault.RotationCommitted {
		return Plan{}, errors.New("key rotation is not verified for commit or recovery")
	}
	if _, err := e.require(ctx, expected, planID, info.Phase); err != nil {
		return Plan{}, err
	}
	if info.Phase == vault.RotationVerified {
		if err := ctx.Err(); err != nil {
			return Plan{}, err
		}
		if err := e.keeper.CommitRotationAt(expected, planID); err != nil {
			return Plan{}, err
		}
	}
	committed, err := e.durable(ctx)
	if err != nil {
		return Plan{}, err
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if err := e.keeper.CompleteRotationAt(committed.Revision, planID, committed.Digest); err != nil {
		return Plan{}, err
	}
	complete, err := e.durable(ctx)
	if err != nil {
		return Plan{}, err
	}
	info, err = e.keeper.RotationAt(complete.Revision, planID)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Info: info, Revision: complete.Revision, Digest: complete.Digest}, nil
}
func (e *Engine) Cancel(ctx context.Context, expected, planID uint64) error {
	if err := e.available(); err != nil {
		return err
	}
	ctx, cancel, err := operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.require(ctx, expected, planID, vault.RotationPrepared); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.keeper.CancelRotationAt(expected, planID); err != nil {
		return err
	}
	_, err = e.durable(ctx)
	return err
}

func clearTarget(target *vault.Target) {
	if target == nil {
		return
	}
	clear(target.PrivateKey)
	clear(target.Password)
	target.Proxy.Clear()
}

// Fingerprint formats public-only confirmation metadata.
func Fingerprint(encoded []byte) (string, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey(encoded)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid rotation public key")
	}
	return ssh.FingerprintSHA256(key), nil
}
