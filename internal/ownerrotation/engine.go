// Package ownerrotation coordinates keeper-backed owner key rotation.
package ownerrotation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const (
	operationLimit = 90 * time.Second
	// minAddWindow covers the 30s Add timeout plus margin before attempting is saved.
	minAddWindow = 35 * time.Second
)

var ErrUncertain = errors.New("remote key addition outcome is uncertain; inspect and verify only")

type Keeper interface {
	Status() vault.SessionStatus
	PrepareKeyRotationAt(uint64, string, string) (vault.RotationInfo, error)
	RotationAt(uint64, uint64) (vault.RotationInfo, error)
	RotationMaterialAt(uint64, uint64) (vault.Target, vault.Target, error)
	SetRotationPhaseAt(uint64, uint64, string) error
	CommitRotationAt(uint64, uint64) error
	CompleteRotationAt(uint64, uint64, [32]byte) error
	CancelRotationAt(uint64, uint64) error
}

type Evidence struct {
	Revision uint64
	Digest   [32]byte
}
type Persist func(context.Context) (Evidence, error)
type Remote interface {
	// Preflight fails only for conditions that need no remote effect.
	Preflight(ctx context.Context, original, replacement vault.Target, oldPublic, newPublic []byte) error
	Add(context.Context, vault.Target, []byte, []byte) error
	Verify(context.Context, vault.Target) error
}
type SSHRemote struct{}
type Plan struct {
	Info     vault.RotationInfo
	Revision uint64
	Digest   [32]byte
}
type Engine struct {
	mu      sync.Mutex
	keeper  Keeper
	remote  Remote
	persist Persist
}

func (SSHRemote) Preflight(_ context.Context, original, replacement vault.Target, oldPublic, newPublic []byte) error {
	config, err := original.ClientConfig()
	if err != nil {
		return err
	}
	if err := remote.PreflightAdd(config, oldPublic, newPublic); err != nil {
		return err
	}
	_, err = replacement.ClientConfig()
	return err
}
func (SSHRemote) Add(ctx context.Context, target vault.Target, oldPublic, newPublic []byte) error {
	config, err := target.ClientConfig()
	if err != nil {
		return err
	}
	return remote.AddAuthorizedKey(ctx, target.Address, config, oldPublic, newPublic)
}
func (SSHRemote) Verify(ctx context.Context, target vault.Target) error {
	config, err := target.ClientConfig()
	if err != nil {
		return err
	}
	return remote.Check(ctx, target.Address, config)
}

func New(keeper Keeper, remote Remote, persist Persist) (*Engine, error) {
	if keeper == nil || remote == nil || persist == nil {
		return nil, errors.New("owner rotation requires a keeper, remote and durable persistence")
	}
	return &Engine{keeper: keeper, remote: remote, persist: persist}, nil
}
func operation(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, errors.New("owner rotation requires an active context")
	}
	ctx, cancel := context.WithTimeout(parent, operationLimit)
	return ctx, cancel, nil
}
func (e *Engine) available() error {
	if e == nil || e.keeper == nil || e.remote == nil || e.persist == nil {
		return errors.New("owner rotation is unavailable")
	}
	return nil
}
func (e *Engine) durable(ctx context.Context) (Evidence, error) {
	evidence, err := e.persist(ctx)
	if ctx.Err() != nil {
		return Evidence{}, ctx.Err()
	}
	status := e.keeper.Status()
	if err != nil {
		return Evidence{}, err
	}
	if status.Err != nil || status.Pending || status.Revision != status.SavedRevision || evidence.Revision != status.Revision || evidence.Digest == ([32]byte{}) {
		return Evidence{}, errors.New("rotation state lacks exact durable revision evidence")
	}
	return evidence, nil
}

func (e *Engine) Prepare(ctx context.Context, expected uint64, serverID, account string) (Plan, error) {
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
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	info, err := e.keeper.PrepareKeyRotationAt(expected, serverID, account)
	if err != nil {
		return Plan{}, err
	}
	evidence, err := e.durable(ctx)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Info: info, Revision: evidence.Revision, Digest: evidence.Digest}, nil
}

// Inspect reads plan-specific metadata and evidence without remote operations.
func (e *Engine) Inspect(ctx context.Context, expected, planID uint64) (Plan, error) {
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
	status := e.keeper.Status()
	if status.Err != nil || status.Pending || status.Revision != expected || status.SavedRevision != expected {
		return Plan{}, errors.New("rotation requires explicit database-save recovery")
	}
	evidence, err := e.persist(ctx)
	if err != nil {
		return Plan{}, err
	}
	if evidence.Revision != expected || evidence.Digest == ([32]byte{}) {
		return Plan{}, errors.New("rotation inspection lacks durable evidence")
	}
	return Plan{Info: info, Revision: evidence.Revision, Digest: evidence.Digest}, nil
}
func (e *Engine) require(ctx context.Context, expected, planID uint64, phase string) (vault.RotationInfo, error) {
	status := e.keeper.Status()
	if err := ctx.Err(); err != nil {
		return vault.RotationInfo{}, err
	}
	if status.Err != nil || status.Pending || status.Revision != expected || status.SavedRevision != expected {
		return vault.RotationInfo{}, vault.ErrOwnerRevision
	}
	info, err := e.keeper.RotationAt(expected, planID)
	if err != nil {
		return vault.RotationInfo{}, err
	}
	if info.Phase != phase {
		return vault.RotationInfo{}, errors.New("key rotation phase does not admit this operation")
	}
	if _, err := e.durable(ctx); err != nil {
		return vault.RotationInfo{}, err
	}
	return info, nil
}
