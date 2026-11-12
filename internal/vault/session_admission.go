package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

// AdmitAt checks and publishes owner queue state under the revision lock.
// The callback must not call Session methods or retain database buffers.
func (s *Session) AdmitAt(expected uint64, admit func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || admit == nil {
		return errors.New("database session does not accept owner admission")
	}
	if expected != s.revision {
		return ErrOwnerRevision
	}
	return admit()
}

const (
	RotationPrepared   = "prepared"
	RotationAttempting = "attempting"
	RotationUnknown    = "unknown"
	RotationAdded      = "added"
	RotationVerified   = "verified"
	RotationCommitted  = "committed"
	RotationComplete   = "complete"
	RotationCancelled  = "cancelled"
	RotationArchived   = "archived"
)

// RotationInfo exposes metadata and public keys only. Returned slices are owned.
type RotationInfo struct {
	ID, Phase, ServerID, Account, Profile string
	PlanID, BaseRevision, CommitRevision  uint64
	Address, User, Usage, CommitDigest    string
	RecoveryPath, RecoveryDigest          string
	OldPublic, NewPublic                  []byte
	HostKeys                              []string
}

// PrepareKeyRotationAt creates a replacement identity with the retained
// unlock context. It does not run the KDF and requires exact saved revision.
func (s *Session) PrepareKeyRotationAt(expected uint64, serverID, account string) (RotationInfo, error) {
	s.mu.Lock()
	if s.closed || s.closing || s.state == nil || s.exportKey == nil || s.revision != expected || s.saved != expected || s.saveErr != nil || (s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil) {
		s.mu.Unlock()
		return RotationInfo{}, ErrOwnerRevision
	}
	old := s.state.Rotation
	if old != nil && old.Phase != RotationCancelled && old.Phase != RotationArchived {
		s.mu.Unlock()
		return RotationInfo{}, errors.New("key rotation journal is retained; archival is required before another rotation")
	}
	var prior uint64
	if old != nil {
		prior = old.PlanID
	}
	if prior == math.MaxUint64 {
		s.mu.Unlock()
		return RotationInfo{}, errors.New("key rotation plan sequence exhausted")
	}
	profile, err := s.state.AccountProfile(serverID, account)
	if err != nil {
		s.mu.Unlock()
		return RotationInfo{}, err
	}
	original := ownTarget(s.state.Targets[profile])
	// The session lock protects the retained context from concurrent Close.
	newPublic, newPrivate, err := s.exportKey.GenerateIdentity()
	s.mu.Unlock()
	defer clear(original.PrivateKey)
	defer clear(original.Password)
	defer original.Proxy.Clear()
	defer clear(newPrivate)
	defer clear(newPublic)
	if err != nil {
		return RotationInfo{}, err
	}
	if original.Proxy != nil {
		return RotationInfo{}, errors.New("key rotation currently requires a direct SSH route")
	}
	if len(original.Password) != 0 {
		return RotationInfo{}, errors.New("rotation requires a public-key account")
	}
	id, err := rotationID()
	if err != nil {
		return RotationInfo{}, err
	}
	journal := &RotationJournal{ID: id, PlanID: prior + 1, BaseRevision: expected, Phase: RotationPrepared, ServerID: serverID, Account: account, Profile: profile, Original: ownTarget(original), NewPrivate: append([]byte(nil), newPrivate...), NewPublic: append([]byte(nil), newPublic...)}
	journal.OldPublic, err = keyfile.PublicSSH(original.PrivateKey)
	if err != nil {
		journal.clear()
		return RotationInfo{}, err
	}
	err = s.applyRotationAt(expected, func(v *Vault) error {
		if v.Rotation != nil && v.Rotation.PlanID != prior {
			return ErrOwnerRevision
		}
		if got, ok := v.stateProfile(serverID, account); !ok || got != profile {
			return ErrOwnerRevision
		}
		if v.Rotation != nil {
			v.Rotation.clear()
		}
		v.Rotation = cloneRotationJournal(journal)
		return v.validateRotation()
	})
	journal.clear()
	if err != nil {
		return RotationInfo{}, err
	}
	return s.RotationAt(expected+1, prior+1)
}

func cloneRotationJournal(j *RotationJournal) *RotationJournal {
	if j == nil {
		return nil
	}
	copy := *j
	copy.Original = ownTarget(j.Original)
	copy.NewPrivate = append([]byte(nil), j.NewPrivate...)
	copy.NewPublic = append([]byte(nil), j.NewPublic...)
	copy.OldPublic = append([]byte(nil), j.OldPublic...)
	return &copy
}

func (v *Vault) stateProfile(serverID, account string) (string, bool) {
	server, ok := v.Servers[serverID]
	if !ok {
		return "", false
	}
	profile, ok := server.Accounts[account]
	return profile, ok
}

func rotationInfo(j *RotationJournal) RotationInfo {
	info := RotationInfo{
		ID: j.ID, PlanID: j.PlanID, BaseRevision: j.BaseRevision, Phase: j.Phase,
		ServerID: j.ServerID, Account: j.Account, Profile: j.Profile,
		Address: j.Original.Address, User: j.Original.User, Usage: j.Original.EffectiveUsage(),
		OldPublic: append([]byte(nil), j.OldPublic...), NewPublic: append([]byte(nil), j.NewPublic...),
		HostKeys:       append([]string(nil), j.Original.HostKeys...),
		CommitRevision: j.CommitRevision, CommitDigest: j.CommitDigest,
		RecoveryPath: j.RecoveryPath, RecoveryDigest: j.RecoveryDigest,
	}
	if j.Phase == RotationArchived || j.Phase == RotationCancelled {
		info.Address, info.User, info.Usage = "", "", ""
		info.HostKeys, info.OldPublic, info.NewPublic = nil, nil, nil
	}
	return info
}

func (s *Session) RotationAt(expected, planID uint64) (RotationInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil || s.revision != expected || s.state.Rotation == nil || s.state.Rotation.PlanID != planID {
		return RotationInfo{}, ErrOwnerRevision
	}
	return rotationInfo(s.state.Rotation), nil
}

// RotationSnapshot reads metadata without a supplied plan ID. With no journal,
// it returns zero info and nil error. A zero-value session has no journal;
// metadata does not grant mutation authority. Returned slices are independent clones.
func (s *Session) RotationSnapshot() (RotationInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing {
		return RotationInfo{}, errors.New("database session is closed")
	}
	if s.state == nil {
		return RotationInfo{}, nil
	}
	if s.state.Rotation == nil {
		return RotationInfo{}, nil
	}
	return rotationInfo(s.state.Rotation), nil
}

// RotationMaterialAt is keeper-only. The caller owns and clears the targets.
func (s *Session) RotationMaterialAt(expected, planID uint64) (Target, Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil || s.revision != expected || s.state.Rotation == nil {
		return Target{}, Target{}, ErrOwnerRevision
	}
	j := s.state.Rotation
	if j.PlanID != planID || j.Phase == RotationCancelled || j.Phase == RotationComplete {
		return Target{}, Target{}, ErrOwnerRevision
	}
	current, exists := s.state.Targets[j.Profile]
	if !exists || !rotationScopeEqual(current, j.Original) {
		return Target{}, Target{}, errors.New("key rotation scope changed")
	}
	original, replacement := ownTarget(j.Original), ownTarget(current)
	if j.Phase != RotationCommitted {
		clear(replacement.PrivateKey)
		replacement.PrivateKey = append([]byte(nil), j.NewPrivate...)
	}
	return original, replacement, nil
}

// SetRotationPhaseAt permits only journaled forward transitions; attempting
// may move to verify-only but can never return to remote installation.
func (s *Session) SetRotationPhaseAt(expected, planID uint64, phase string) error {
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID {
			return ErrOwnerRevision
		}
		valid := j.Phase == RotationPrepared && phase == RotationAttempting ||
			j.Phase == RotationAttempting && (phase == RotationUnknown || phase == RotationAdded || phase == RotationVerified) ||
			(j.Phase == RotationUnknown || j.Phase == RotationAdded) && phase == RotationVerified
		if !valid {
			return errors.New("invalid key rotation phase transition")
		}
		j.Phase = phase
		return nil
	})
}

// CommitRotationAt changes only the selected profile's private key.
func (s *Session) CommitRotationAt(expected, planID uint64) error {
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID || j.Phase != RotationVerified {
			return errors.New("key rotation is not verified for commit")
		}
		current, exists := v.Targets[j.Profile]
		if !exists || !rotationScopeEqual(current, j.Original) || !bytes.Equal(current.PrivateKey, j.Original.PrivateKey) {
			return errors.New("key rotation target changed before commit")
		}
		if err := v.ReplaceKey(j.Profile, j.NewPrivate); err != nil {
			return err
		}
		j.Phase = RotationCommitted
		return nil
	})
}

// CompleteRotationAt records exact saved evidence while accepting the revision
// counter of the current process epoch after recovery.
func (s *Session) CompleteRotationAt(expected, planID uint64, proof [32]byte) error {
	s.mu.Lock()
	valid := !s.closed && !s.closing && s.state != nil && s.revision == expected && s.saved == expected && s.saveErr == nil && proof != ([32]byte{}) && proof == s.savedCipher && s.state.Rotation != nil && s.state.Rotation.PlanID == planID && s.state.Rotation.Phase == RotationCommitted
	s.mu.Unlock()
	if !valid {
		return ErrOwnerRevision
	}
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID || j.Phase != RotationCommitted {
			return ErrOwnerRevision
		}
		if j.CommitRevision != 0 && j.CommitRevision != expected {
			return ErrOwnerRevision
		}
		j.Phase, j.CommitRevision, j.CommitDigest = RotationComplete, expected, hex.EncodeToString(proof[:])
		return nil
	})
}

// CancelRotationAt is limited to a prepared plan, before any remote effect.
func (s *Session) CancelRotationAt(expected, planID uint64) error {
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID || j.Phase != RotationPrepared {
			return errors.New("effectful rotation cannot be cancelled")
		}
		j.clear()
		j.Original, j.NewPrivate, j.NewPublic, j.OldPublic = Target{}, nil, nil, nil
		j.Phase = RotationCancelled
		return nil
	})
}
