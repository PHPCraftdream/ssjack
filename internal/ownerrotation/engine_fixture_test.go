package ownerrotation

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type memoryKeeper struct {
	info                    vault.RotationInfo
	revision, saved         uint64
	trace                   *[]string
	digest, completionProof [32]byte
	failSet                 error
	failCommit              error
	failComplete            error
}

func (k *memoryKeeper) record(event string) {
	if k.trace != nil {
		*k.trace = append(*k.trace, event)
	}
}

func (k *memoryKeeper) Status() vault.SessionStatus {
	return vault.SessionStatus{Revision: k.revision, SavedRevision: k.saved}
}

func (k *memoryKeeper) PrepareKeyRotationAt(uint64, string, string) (vault.RotationInfo, error) {
	return k.info, nil
}

func (k *memoryKeeper) RotationAt(revision, planID uint64) (vault.RotationInfo, error) {
	if revision != k.revision || planID != k.info.PlanID {
		return vault.RotationInfo{}, vault.ErrOwnerRevision
	}
	return k.info, nil
}

func (k *memoryKeeper) RotationMaterialAt(revision, planID uint64) (vault.Target, vault.Target, error) {
	if _, err := k.RotationAt(revision, planID); err != nil {
		return vault.Target{}, vault.Target{}, err
	}
	return vault.Target{Address: "test:22"}, vault.Target{Address: "test:22"}, nil
}

func (k *memoryKeeper) SetRotationPhaseAt(revision, planID uint64, phase string) error {
	if _, err := k.RotationAt(revision, planID); err != nil {
		return err
	}
	if k.failSet != nil {
		return k.failSet
	}
	valid := k.info.Phase == vault.RotationPrepared && phase == vault.RotationAttempting ||
		k.info.Phase == vault.RotationAttempting && (phase == vault.RotationUnknown || phase == vault.RotationAdded || phase == vault.RotationVerified) ||
		(k.info.Phase == vault.RotationUnknown || k.info.Phase == vault.RotationAdded) && phase == vault.RotationVerified
	if !valid {
		return errors.New("phase")
	}
	k.info.Phase = phase
	k.revision++
	return nil
}

func (k *memoryKeeper) CommitRotationAt(revision, planID uint64) error {
	k.record("commit")
	if k.failCommit != nil {
		return k.failCommit
	}
	if _, err := k.RotationAt(revision, planID); err != nil || k.info.Phase != vault.RotationVerified || k.saved != revision {
		return errors.New("not verified and durable")
	}
	k.info.Phase = vault.RotationCommitted
	k.revision++
	return nil
}

func (k *memoryKeeper) CompleteRotationAt(revision, planID uint64, proof [32]byte) error {
	k.record("complete")
	if k.failComplete != nil {
		return k.failComplete
	}
	if revision != k.revision || k.saved != revision || planID != k.info.PlanID || k.info.Phase != vault.RotationCommitted || proof == ([32]byte{}) || proof != k.digest {
		return errors.New("commit lacks durable proof")
	}
	k.info.Phase = vault.RotationComplete
	k.info.CommitRevision = revision
	k.completionProof = proof
	k.info.CommitDigest = hex.EncodeToString(proof[:])
	k.revision++
	return nil
}

func (k *memoryKeeper) CancelRotationAt(revision, planID uint64) error {
	if _, err := k.RotationAt(revision, planID); err != nil || k.info.Phase != vault.RotationPrepared {
		return errors.New("effectful")
	}
	k.info.Phase = vault.RotationCancelled
	k.revision++
	return nil
}

type memoryRemote struct {
	calls                     []string
	addErr, verifyErr         error
	persistCalls, failPersist int
	preflightErr              error
	preflights                int
}

func (r *memoryRemote) Preflight(context.Context, vault.Target, vault.Target, []byte, []byte) error {
	r.preflights++
	return r.preflightErr
}

func (r *memoryRemote) Add(context.Context, vault.Target, []byte, []byte) error {
	r.calls = append(r.calls, "add")
	return r.addErr
}

func (r *memoryRemote) Verify(context.Context, vault.Target) error {
	r.calls = append(r.calls, "verify")
	return r.verifyErr
}

func testEngine(t *testing.T, addErr error) (*Engine, *memoryKeeper, *memoryRemote) {
	t.Helper()
	keeper := &memoryKeeper{
		info: vault.RotationInfo{
			PlanID: 4, Phase: vault.RotationPrepared,
			OldPublic: []byte("old"), NewPublic: []byte("new"),
		},
		revision: 8,
		saved:    8,
	}
	remote := &memoryRemote{addErr: addErr}
	keeper.trace = &remote.calls
	persist := func(context.Context) (Evidence, error) {
		remote.calls = append(remote.calls, "persist")
		remote.persistCalls++
		if remote.failPersist == remote.persistCalls {
			return Evidence{}, errors.New("save failed")
		}
		keeper.saved = keeper.revision
		keeper.digest = [32]byte{byte(keeper.revision), 1}
		return Evidence{Revision: keeper.revision, Digest: keeper.digest}, nil
	}
	engine, err := New(keeper, remote, persist)
	if err != nil {
		t.Fatal(err)
	}
	return engine, keeper, remote
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
