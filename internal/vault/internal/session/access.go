package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerpublication"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/approval"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
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
	if old != nil && old.Phase != core.RotationCancelled && old.Phase != core.RotationArchived {
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
	original := record.OwnTarget(s.state.Targets[profile])
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
	id, err := core.RotationID()
	if err != nil {
		return RotationInfo{}, err
	}
	journal := &RotationJournal{ID: id, PlanID: prior + 1, BaseRevision: expected, Phase: core.RotationPrepared, ServerID: serverID, Account: account, Profile: profile, Original: record.OwnTarget(original), NewPrivate: append([]byte(nil), newPrivate...), NewPublic: append([]byte(nil), newPublic...)}
	journal.OldPublic, err = keyfile.PublicSSH(original.PrivateKey)
	if err != nil {
		core.ClearJournal(journal)
		return RotationInfo{}, err
	}
	err = s.applyRotationAt(expected, func(v *Vault) error {
		if v.Rotation != nil && v.Rotation.PlanID != prior {
			return ErrOwnerRevision
		}
		if got, ok := core.StateProfile(v, serverID, account); !ok || got != profile {
			return ErrOwnerRevision
		}
		if v.Rotation != nil {
			core.ClearJournal(v.Rotation)
		}
		v.Rotation = cloneRotationJournal(journal)
		return core.ValidateRotation(v)
	})
	core.ClearJournal(journal)
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
	copy.Original = record.OwnTarget(j.Original)
	copy.NewPrivate = append([]byte(nil), j.NewPrivate...)
	copy.NewPublic = append([]byte(nil), j.NewPublic...)
	copy.OldPublic = append([]byte(nil), j.OldPublic...)
	return &copy
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
	if j.Phase == core.RotationArchived || j.Phase == core.RotationCancelled {
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

// WithRotationMaterialAt is keeper-only. It lends the targets to use and clears
// them on return, so callers cannot leak key material or forget to wipe it. use
// must not retain the targets or their buffers.
func (s *Session) WithRotationMaterialAt(expected, planID uint64, use func(original, replacement Target) error) error {
	if use == nil {
		return errors.New("rotation material requires a callback")
	}
	original, replacement, err := s.rotationMaterialAt(expected, planID)
	if err != nil {
		return err
	}
	defer clearRotationTarget(&original)
	defer clearRotationTarget(&replacement)
	return use(original, replacement)
}

// WithRetirementMaterialAt is keeper-only. For a completed rotation it lends the
// account's current credential, which is the committed replacement key, and
// both public keys, so the old remote key can be retired. It clears the
// credential on return; use must not retain it.
func (s *Session) WithRetirementMaterialAt(expected, planID uint64, use func(current Target, oldPublic, newPublic []byte) error) error {
	if use == nil {
		return errors.New("retirement material requires a callback")
	}
	current, oldPublic, newPublic, err := s.retirementMaterialAt(expected, planID)
	if err != nil {
		return err
	}
	defer clearRotationTarget(&current)
	return use(current, oldPublic, newPublic)
}

func (s *Session) retirementMaterialAt(expected, planID uint64) (Target, []byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil || s.revision != expected || s.state.Rotation == nil {
		return Target{}, nil, nil, ErrOwnerRevision
	}
	j := s.state.Rotation
	if j.PlanID != planID || j.Phase != core.RotationComplete {
		return Target{}, nil, nil, ErrOwnerRevision
	}
	current, exists := s.state.Targets[j.Profile]
	if !exists || !core.RotationScopeEqual(current, j.Original) || !bytes.Equal(current.PrivateKey, j.NewPrivate) {
		return Target{}, nil, nil, errors.New("completed rotation no longer matches the account credential")
	}
	for name, other := range s.state.Targets {
		if name != j.Profile && other.Address == current.Address && other.User == current.User && bytes.Equal(other.PrivateKey, j.Original.PrivateKey) {
			return Target{}, nil, nil, errors.New("another saved profile still uses the old key for this remote account; rotate or change it before retiring the key")
		}
	}
	return record.OwnTarget(current), append([]byte(nil), j.OldPublic...), append([]byte(nil), j.NewPublic...), nil
}

func clearRotationTarget(target *Target) {
	clear(target.PrivateKey)
	clear(target.Password)
	target.Proxy.Clear()
}

func (s *Session) rotationMaterialAt(expected, planID uint64) (Target, Target, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil || s.revision != expected || s.state.Rotation == nil {
		return Target{}, Target{}, ErrOwnerRevision
	}
	j := s.state.Rotation
	if j.PlanID != planID || j.Phase == core.RotationCancelled || j.Phase == core.RotationComplete {
		return Target{}, Target{}, ErrOwnerRevision
	}
	current, exists := s.state.Targets[j.Profile]
	if !exists || !core.RotationScopeEqual(current, j.Original) {
		return Target{}, Target{}, errors.New("key rotation scope changed")
	}
	original, replacement := record.OwnTarget(j.Original), record.OwnTarget(current)
	if j.Phase != core.RotationCommitted {
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
		valid := j.Phase == core.RotationPrepared && phase == core.RotationAttempting ||
			j.Phase == core.RotationAttempting && (phase == core.RotationUnknown || phase == core.RotationAdded || phase == core.RotationVerified) ||
			(j.Phase == core.RotationUnknown || j.Phase == core.RotationAdded) && phase == core.RotationVerified
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
		if j == nil || j.PlanID != planID || j.Phase != core.RotationVerified {
			return errors.New("key rotation is not verified for commit")
		}
		current, exists := v.Targets[j.Profile]
		if !exists || !core.RotationScopeEqual(current, j.Original) || !bytes.Equal(current.PrivateKey, j.Original.PrivateKey) {
			return errors.New("key rotation target changed before commit")
		}
		if err := v.ReplaceKey(j.Profile, j.NewPrivate); err != nil {
			return err
		}
		j.Phase = core.RotationCommitted
		return nil
	})
}

// CompleteRotationAt records exact saved evidence while accepting the revision
// counter of the current process epoch after recovery.
func (s *Session) CompleteRotationAt(expected, planID uint64, proof [32]byte) error {
	s.mu.Lock()
	valid := !s.closed && !s.closing && s.state != nil && s.revision == expected && s.saved == expected && s.saveErr == nil && proof != ([32]byte{}) && proof == s.savedCipher && s.state.Rotation != nil && s.state.Rotation.PlanID == planID && s.state.Rotation.Phase == core.RotationCommitted
	s.mu.Unlock()
	if !valid {
		return ErrOwnerRevision
	}
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID || j.Phase != core.RotationCommitted {
			return ErrOwnerRevision
		}
		if j.CommitRevision != 0 && j.CommitRevision != expected {
			return ErrOwnerRevision
		}
		j.Phase, j.CommitRevision, j.CommitDigest = core.RotationComplete, expected, hex.EncodeToString(proof[:])
		return nil
	})
}

// CancelRotationAt is limited to a prepared plan, before any remote effect.
func (s *Session) CancelRotationAt(expected, planID uint64) error {
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID || j.Phase != core.RotationPrepared {
			return errors.New("effectful rotation cannot be cancelled")
		}
		discardRotationJournal(j)
		return nil
	})
}

// AbandonRotationAt discards an uncommitted rotation whose remote addition was
// attempted. The unused new private key is destroyed and the current key stays
// in use. The new public key may remain authorized remotely; the journal is
// recorded as cancelled, the same terminal state as a prepared cancellation.
func (s *Session) AbandonRotationAt(expected, planID uint64) error {
	return s.applyRotationAt(expected, func(v *Vault) error {
		j := v.Rotation
		if j == nil || j.PlanID != planID || !core.RotationAwaitsVerification(j.Phase) {
			return errors.New("only an uncommitted rotation after a remote addition attempt can be abandoned")
		}
		discardRotationJournal(j)
		return nil
	})
}

func discardRotationJournal(j *RotationJournal) {
	core.ClearJournal(j)
	j.Original, j.NewPrivate, j.NewPublic, j.OldPublic = Target{}, nil, nil, nil
	j.Phase = core.RotationCancelled
}

func (s *Session) ArchiveRotationAt(ctx context.Context, path string, expected, planID uint64, id string) (RotationInfo, error) {
	if ctx == nil {
		return RotationInfo{}, errors.New("rotation archive requires a bounded context")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return RotationInfo{}, errors.New("rotation archive requires a bounded context")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return RotationInfo{}, err
	}
	if s.closed || s.closing || s.state == nil || s.revision != expected || s.saved != expected || s.saveErr != nil || s.savedCipher == ([sha256.Size]byte{}) || (s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil) {
		return RotationInfo{}, ErrOwnerRevision
	}
	j := s.state.Rotation
	if j == nil || j.ID != id || j.PlanID != planID || j.Phase != core.RotationComplete || !core.ValidOwnerHash(j.CommitDigest) || j.RecoveryPath != "" || j.RecoveryDigest != "" || core.ValidateRotation(s.state) != nil {
		return RotationInfo{}, ErrOwnerRevision
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		return RotationInfo{}, err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if digest != s.savedCipher {
		return RotationInfo{}, errors.New("completed rotation ciphertext changed; archive refused")
	}
	archive, err := store.RecoveryPath(path, "rotation-"+id)
	if err != nil {
		return RotationInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return RotationInfo{}, err
	}
	if err := store.Commit(archive, encoded, nil); err != nil {
		return RotationInfo{}, err
	}
	verify, err := store.ReadEncoded(archive)
	if err != nil || sha256.Sum256(verify) != digest {
		clear(verify)
		return RotationInfo{}, errors.New("rotation archive ciphertext proof failed; both files were preserved")
	}
	clear(verify)
	if err := ownerpublication.Sync(archive); err != nil {
		return RotationInfo{}, errors.New("rotation archive durability is uncertain; both files were preserved")
	}
	verify, err = store.ReadEncoded(archive)
	if err != nil || sha256.Sum256(verify) != digest {
		clear(verify)
		return RotationInfo{}, errors.New("rotation archive changed after sync; both files were preserved")
	}
	clear(verify)
	if err := ctx.Err(); err != nil {
		return RotationInfo{}, err
	}
	encodedDigest, commitDigest := hex.EncodeToString(digest[:]), j.CommitDigest
	if err := s.applyWithRotationLocked(&expected, func(v *Vault) error {
		journal := v.Rotation
		if journal == nil || journal.ID != id || journal.PlanID != planID || journal.Phase != core.RotationComplete || journal.CommitDigest != commitDigest {
			return ErrOwnerRevision
		}
		journal.Phase, journal.RecoveryPath, journal.RecoveryDigest = core.RotationArchived, archive, encodedDigest
		core.ClearJournal(journal)
		journal.Original, journal.NewPrivate, journal.NewPublic, journal.OldPublic = Target{}, nil, nil, nil
		return nil
	}, true); err != nil {
		return RotationInfo{}, err
	}
	return rotationInfo(s.state.Rotation), nil
}

type AccountMetadata struct {
	Name           string
	Profile        string
	User           string
	Authentication string
	Usage          string
}

type ServerMetadata struct {
	ID           string
	Name         string
	Address      string
	Fingerprints []string
	Accounts     []AccountMetadata
	Proxy        sshproxy.Metadata
}

type OwnerStoreMetadata struct {
	Directory    string
	StoreID      string
	PendingID    string
	PendingPhase string
}

type DirectoryMetadata struct {
	Servers    []ServerMetadata
	Secrets    map[string]SecretBinding
	OwnerStore *OwnerStoreMetadata
	RemoteMCP  mcpdirectory.Metadata
	// Approvals lists owner application approvals sorted by name.
	Approvals []approval.Record
}

// Metadata returns owned display data, never credentials or pending values.
func (s *Session) Metadata() (DirectoryMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata()
}

func (s *Session) SetSSHStatus(status func() sshstatus.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshStatus = status
}

func (s *Session) sshSnapshot() *sshstatus.Status {
	if s.sshStatus == nil {
		return nil
	}
	status := s.sshStatus()
	return &status
}

// MetadataSnapshot binds display data and persistence evidence to one revision.
func (s *Session) MetadataSnapshot() (DirectoryMetadata, SessionStatus, [32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, err := s.metadata()
	status := SessionStatus{Revision: s.revision, SavedRevision: s.saved, Pending: s.saved != s.revision, Err: s.saveErr, SSH: s.sshSnapshot()}
	var digest [32]byte
	if err == nil && s.saveErr == nil && s.saved == s.revision {
		digest = s.savedCipher
	}
	return metadata, status, digest, err
}

func (s *Session) metadata() (DirectoryMetadata, error) {
	if s.closed {
		return DirectoryMetadata{}, errors.New("database session is closed")
	}
	result := DirectoryMetadata{Servers: make([]ServerMetadata, 0, len(s.state.Servers)), Secrets: make(map[string]SecretBinding), RemoteMCP: s.state.RemoteMCP.Metadata()}
	for id, server := range s.state.Servers {
		metadata := ServerMetadata{ID: id, Name: server.Name}
		for name, profile := range server.Accounts {
			target := s.state.Targets[profile]
			metadata.Address = target.Address
			metadata.Proxy = target.Proxy.Metadata()
			if len(metadata.Fingerprints) == 0 {
				for _, encoded := range target.HostKeys {
					key, err := record.ParseHostKey([]byte(encoded))
					if err != nil {
						return DirectoryMetadata{}, err
					}
					metadata.Fingerprints = append(metadata.Fingerprints, ssh.FingerprintSHA256(key))
				}
				sort.Strings(metadata.Fingerprints)
			}
			authentication := "key"
			if len(target.Password) != 0 {
				authentication = "password"
			}
			metadata.Accounts = append(metadata.Accounts, AccountMetadata{Name: name, Profile: profile, User: target.User, Authentication: authentication, Usage: target.EffectiveUsage()})
		}
		sort.Slice(metadata.Accounts, func(i, j int) bool { return metadata.Accounts[i].Name < metadata.Accounts[j].Name })
		result.Servers = append(result.Servers, metadata)
	}
	sort.Slice(result.Servers, func(i, j int) bool { return result.Servers[i].Name < result.Servers[j].Name })
	for id, secret := range s.state.Secrets {
		result.Secrets[id] = secret
	}
	for _, record := range s.state.Approvals {
		result.Approvals = append(result.Approvals, record)
	}
	sort.Slice(result.Approvals, func(i, j int) bool { return result.Approvals[i].Name < result.Approvals[j].Name })
	if owner := s.state.OwnerStore; owner != nil {
		result.OwnerStore = &OwnerStoreMetadata{Directory: owner.Directory, StoreID: owner.StoreID}
		if owner.Pending != nil {
			result.OwnerStore.PendingID = owner.Pending.ID
			result.OwnerStore.PendingPhase = owner.Pending.Phase
		}
	}
	return result, nil
}

func (s *Session) AgentSSHAt(expected uint64, digest [32]byte, profile string) (*ssh.ClientConfig, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unavailable := errors.New("agent SSH configuration unavailable")
	if s.closed || s.closing || s.state == nil || s.state.Version != 2 || s.revision != expected || s.saved != expected || s.saveErr != nil || digest == ([32]byte{}) || digest != s.savedCipher || (s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil) {
		return nil, "", "", unavailable
	}
	var serverID, account string
	for id, server := range s.state.Servers {
		for name, selected := range server.Accounts {
			if selected == profile {
				if serverID != "" {
					return nil, "", "", unavailable
				}
				serverID, account = id, name
			}
		}
	}
	original, exists := s.state.Targets[profile]
	if serverID == "" || !exists {
		return nil, "", "", unavailable
	}
	target := record.OwnTarget(original)
	defer clear(target.PrivateKey)
	defer clear(target.Password)
	defer target.Proxy.Clear()
	if target.Proxy != nil || target.RequireUsage("agent") != nil {
		return nil, "", "", unavailable
	}
	config, err := target.ClientConfig()
	if err != nil || config.User != target.User {
		return nil, "", "", unavailable
	}
	pins := make([]string, 0, len(target.HostKeys))
	for _, encoded := range target.HostKeys {
		key, err := record.ParseHostKey([]byte(encoded))
		if err != nil {
			return nil, "", "", unavailable
		}
		pins = append(pins, hex.EncodeToString(key.Marshal()))
	}
	sort.Strings(pins)
	policy := struct {
		HostKeys     []string `json:"host_keys"`
		KeyExchanges []string `json:"key_exchanges"`
		Ciphers      []string `json:"ciphers"`
		MACs         []string `json:"macs"`
	}{
		HostKeys:     append([]string{}, target.SSHPolicy.HostKeys...),
		KeyExchanges: append([]string{}, target.SSHPolicy.KeyExchanges...),
		Ciphers:      append([]string{}, target.SSHPolicy.Ciphers...),
		MACs:         append([]string{}, target.SSHPolicy.MACs...),
	}
	authentication := "key"
	if len(target.Password) != 0 {
		authentication = "password"
	}
	canonical, err := json.Marshal(struct {
		Profile        string   `json:"profile"`
		ServerID       string   `json:"server_id"`
		Account        string   `json:"account"`
		Address        string   `json:"address"`
		User           string   `json:"user"`
		Authentication string   `json:"authentication"`
		Usage          string   `json:"usage"`
		HostKeys       []string `json:"host_keys"`
		Policy         any      `json:"ssh_policy"`
	}{profile, serverID, account, target.Address, target.User, authentication, target.EffectiveUsage(), pins, policy})
	if err != nil {
		return nil, "", "", unavailable
	}
	scopeDigest := sha256.Sum256(canonical)
	scope := hex.EncodeToString(scopeDigest[:])
	return config, target.Address, scope, nil
}

// HumanSSH is the single narrow credential path for an owner-selected
// interactive connection: it yields a host-pin verified client configuration,
// never raw credential bytes, and only for human-permitted accounts.
func (s *Session) HumanSSH(serverID, account string) (*ssh.ClientConfig, string, error) {
	return s.humanSSH(nil, serverID, account)
}
func (s *Session) HumanSSHAt(expected uint64, serverID, account string) (*ssh.ClientConfig, string, error) {
	return s.humanSSH(&expected, serverID, account)
}
func (s *Session) humanSSH(expected *uint64, serverID, account string) (*ssh.ClientConfig, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != nil && *expected != s.revision {
		return nil, "", ErrOwnerRevision
	}
	if s.closed {
		return nil, "", errors.New("database session is closed")
	}
	profile, err := s.state.AccountProfile(serverID, account)
	if err != nil {
		return nil, "", err
	}
	// The copy keeps later Apply or close zeroization away from the config, and
	// is itself cleared once the config holds its own derived material.
	target := record.OwnTarget(s.state.Targets[profile])
	defer clear(target.PrivateKey)
	defer clear(target.Password)
	defer target.Proxy.Clear()
	if err := target.RequireUsage("human"); err != nil {
		return nil, "", err
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	return config, target.Address, nil
}

// RemoteMCPCaptureAt revalidates one exact saved session state under the
// session-managed revision and saved-cipher gates and privately captures the
// enabled confirmed records. It returns capability material only: credential
// values never leave the session, and no network effect, second unlock or
// per-operation KDF occurs.
func (s *Session) RemoteMCPCaptureAt(ctx context.Context, expected uint64, digest [32]byte, profile string, bindings []mcpdirectory.Binding) (*mcpgrant.Capture, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, mcpgrant.ErrGrant
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Same fixed-state gate as OutputGuardAt: the capture is only valid for the
	// exact saved revision whose digest the caller already proved.
	if s.closed || s.closing || s.state == nil || s.revision != expected || s.saved != expected || s.saveErr != nil || digest == ([32]byte{}) || digest != s.savedCipher {
		return nil, mcpgrant.ErrGrant
	}
	if s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil {
		return nil, mcpgrant.ErrGrant
	}
	if _, exists := s.state.Targets[profile]; !exists {
		return nil, mcpgrant.ErrGrant
	}
	if s.state.RemoteMCP == nil {
		return nil, mcpgrant.ErrGrant
	}
	records, err := core.ConfirmedMCPRecords(s.state.RemoteMCP, bindings)
	if err != nil {
		return nil, err
	}
	return mcpgrant.NewCapture(ctx, profile, expected, digest, records)
}

// RememberRemoteMCPAt records a private preference, never a launch grant.
// Success queues encrypted persistence; the caller must inspect its save receipt.
func (s *Session) RememberRemoteMCPAt(ctx context.Context, expected uint64, digest [32]byte, profile string, selected []mcpdirectory.Binding) error {
	if s == nil || ctx == nil || ctx.Err() != nil || digest == ([32]byte{}) || len(selected) > mcpdirectory.MaxSelections {
		return mcpdirectory.ErrChanged
	}
	owned := append([]mcpdirectory.Binding{}, selected...)
	return s.ApplyAt(expected, func(candidate *Vault) error {
		// Apply holds s.mu; do not call another Session method here.
		if ctx.Err() != nil || s.saved != expected || s.saveErr != nil || s.savedCipher != digest || (candidate.OwnerStore != nil && candidate.OwnerStore.Pending != nil) {
			return mcpdirectory.ErrChanged
		}
		if _, exists := candidate.Targets[profile]; !exists {
			return mcpdirectory.ErrChanged
		}
		if candidate.RemoteMCP == nil {
			if len(owned) != 0 {
				return mcpdirectory.ErrChanged
			}
			return nil
		}
		if err := candidate.RemoteMCP.Remember(profile, owned); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return mcpdirectory.ErrChanged
		}
		return nil
	})
}

// OutputGuardAt returns a private capability for one confirmed database state.
// Linked application values must be added separately before model admission.
func (s *Session) OutputGuardAt(expected uint64, digest [32]byte) (*outputguard.Snapshot, error) {
	if s == nil {
		return nil, outputguard.ErrGuard
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.state == nil || s.revision != expected || s.saved != expected || s.saveErr != nil || digest == ([32]byte{}) || digest != s.savedCipher {
		return nil, outputguard.ErrGuard
	}
	if s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil {
		return nil, outputguard.ErrGuard
	}
	return core.CredentialGuard(s.state)
}

// OwnerPeer borrows only the closed owner protocol capability, never its master.
func (s *Session) OwnerPeer(path string, binding [32]byte) (*ownerpacket.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.exportKey == nil || s.state == nil || s.state.Version != 2 || s.savedCipher == ([32]byte{}) {
		return nil, errors.New("owner channel requires an authenticated saved ciphertext origin")
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil || sha256.Sum256(encoded) != s.savedCipher {
		return nil, ErrOwnerRevision
	}
	return ownerpacket.NewServer(s.exportKey, binding, s.savedCipher)
}

// LocalOwnerPeer shares the current invocation's unlock, not an application grant.
func (s *Session) LocalOwnerPeer(binding [32]byte) (*ownerpacket.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.exportKey == nil {
		return nil, errors.New("owner channel context is unavailable")
	}
	return ownerpacket.NewClient(s.exportKey, binding)
}

// OwnerUnlock owns one helper unlock and can rotate only its protocol peers.
// It has no plaintext, stored-secret, password, or master getter.
type OwnerUnlock struct {
	mu      sync.Mutex
	key     *keyfile.Unlocked
	binding [32]byte
}

func OpenOwnerUnlock(path string, password []byte, binding [32]byte) (*OwnerUnlock, error) {
	loaded, err := core.Load(path, password)
	if err != nil {
		return nil, errors.New("cannot authenticate owner database")
	}
	return AdoptOwnerUnlock(loaded, binding)
}

// AdoptOwnerUnlock consumes a read-only authenticated vault without another KDF.
func AdoptOwnerUnlock(loaded *Vault, binding [32]byte) (*OwnerUnlock, error) {
	if loaded == nil {
		return nil, errors.New("owner channel requires an authenticated vault")
	}
	key := core.DetachReadOnlyKey(loaded)
	if key == nil || binding == ([32]byte{}) {
		key.Close()
		loaded.Close()
		return nil, errors.New("owner channel requires a read-only directory unlock")
	}
	loaded.Close()
	return &OwnerUnlock{key: key, binding: binding}, nil
}
func (u *OwnerUnlock) Peer() (*ownerpacket.Client, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key == nil {
		return nil, errors.New("owner helper context is closed")
	}
	return ownerpacket.NewClient(u.key, u.binding)
}
func (u *OwnerUnlock) Close() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key != nil {
		u.key.Close()
		u.key = nil
	}
}

// HumanSSH privately captures one human-permitted login from an exact saved file.
// It never returns stored credential bytes or adopts a different ciphertext.
func (u *OwnerUnlock) HumanSSH(path string, expected [32]byte, server, account string) (*ssh.ClientConfig, string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.key == nil || expected == ([32]byte{}) {
		return nil, "", errors.New("owner human SSH context is unavailable")
	}
	encoded, err := store.ReadEncoded(path)
	if err != nil || sha256.Sum256(encoded) != expected {
		return nil, "", ErrOwnerRevision
	}
	plaintext, err := u.key.Open(encoded)
	if err != nil {
		return nil, "", errors.New("owner human SSH snapshot did not authenticate")
	}
	defer clear(plaintext)
	loaded, err := core.Unmarshal(plaintext)
	if err != nil {
		return nil, "", errors.New("owner human SSH snapshot is invalid")
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, account)
	if err != nil {
		return nil, "", err
	}
	target := loaded.Targets[profile]
	if err := target.RequireUsage("human"); err != nil {
		return nil, "", err
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	return config, target.Address, nil
}
