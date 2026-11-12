package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func (t Target) validateAuthentication() error {
	if len(t.Password) != 0 {
		if len(t.PrivateKey) != 0 || len(t.Password) > 4096 {
			return errors.New("select exactly one bounded SSH password or private key")
		}
		return nil
	}
	if len(t.PrivateKey) == 0 || len(t.PrivateKey) > keyfile.MaxPlaintext {
		return errors.New("invalid private key size")
	}
	if _, err := ssh.ParsePrivateKey(t.PrivateKey); err != nil {
		return errors.New("vault private key must be an unencrypted in-memory SSH key")
	}
	return nil
}

// RotationJournal retains the encrypted state needed to recover a key change.
type RotationJournal struct {
	ID             string `json:"id"`
	PlanID         uint64 `json:"plan_id"`
	BaseRevision   uint64 `json:"base_revision"`
	Phase          string `json:"phase"`
	ServerID       string `json:"server_id"`
	Account        string `json:"account"`
	Profile        string `json:"profile"`
	Original       Target `json:"original"`
	NewPrivate     []byte `json:"new_private"`
	NewPublic      []byte `json:"new_public"`
	OldPublic      []byte `json:"old_public"`
	CommitRevision uint64 `json:"commit_revision"`
	CommitDigest   string `json:"commit_digest"`
	RecoveryPath   string `json:"recovery_path"`
	RecoveryDigest string `json:"recovery_digest"`
}

func (j *RotationJournal) clear() {
	if j == nil {
		return
	}
	clear(j.Original.PrivateKey)
	clear(j.Original.Password)
	j.Original.Proxy.Clear()
	clear(j.NewPrivate)
	clear(j.NewPublic)
	clear(j.OldPublic)
}

func rotationID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil || id == ([16]byte{}) {
		return "", errors.New("cannot create rotation identity")
	}
	return hex.EncodeToString(id[:]), nil
}

func rotationTargetEmpty(target Target) bool {
	return target.Address == "" && target.User == "" && len(target.PrivateKey) == 0 && len(target.Password) == 0 && len(target.HostKeys) == 0 && target.Usage == "" && target.SSHPolicy.Empty() && target.Proxy == nil
}

func rotationPublic(private []byte) ([]byte, error) { return keyfile.PublicSSH(private) }
func rotationScopeEqual(a, b Target) bool {
	a.PrivateKey, b.PrivateKey, a.Password, b.Password = nil, nil, nil, nil
	return sameImportTarget(a, b)
}
func (v *Vault) validateRotation() error { return validateRotationVault(v) }

// RotationActive reports whether a journal still blocks edits and legacy rotate.
func RotationActive(j *RotationJournal) bool {
	return j != nil && j.Phase != RotationCancelled && j.Phase != RotationComplete && j.Phase != RotationArchived
}

func validateRotationVault(v *Vault) error {
	j := v.Rotation
	if j == nil {
		return nil
	}
	if v.Version != 2 || !validDirectoryID(j.ID) || j.PlanID == 0 || j.Profile == "" || j.Account == "" || j.ServerID == "" {
		return errors.New("invalid key rotation binding")
	}
	if j.Phase == RotationCancelled {
		if !rotationTargetEmpty(j.Original) || len(j.NewPrivate)+len(j.NewPublic)+len(j.OldPublic) != 0 || j.CommitRevision != 0 || j.CommitDigest != "" || j.RecoveryPath != "" || j.RecoveryDigest != "" {
			return errors.New("cancelled key rotation retains material")
		}
		return nil
	}
	if j.Phase == RotationArchived {
		if !rotationTargetEmpty(j.Original) || len(j.NewPrivate)+len(j.NewPublic)+len(j.OldPublic) != 0 || !validOwnerHash(j.CommitDigest) || j.RecoveryPath == "" || len(j.RecoveryPath) > 4096 || !validOwnerHash(j.RecoveryDigest) {
			return errors.New("invalid archived rotation evidence")
		}
		return nil
	}
	if j.RecoveryPath != "" || j.RecoveryDigest != "" || j.Original.Validate() != nil || len(j.Original.Password) != 0 || j.Original.Proxy != nil || len(j.NewPrivate) == 0 || len(j.NewPublic) == 0 {
		return errors.New("invalid key rotation recovery material")
	}
	oldPublic, err := rotationPublic(j.Original.PrivateKey)
	newPublic, newErr := rotationPublic(j.NewPrivate)
	if err != nil || newErr != nil || !bytes.Equal(oldPublic, j.OldPublic) || !bytes.Equal(newPublic, j.NewPublic) || bytes.Equal(oldPublic, j.NewPublic) {
		return errors.New("invalid replacement key in rotation journal")
	}
	if j.Phase == RotationComplete {
		if !validOwnerHash(j.CommitDigest) {
			return errors.New("invalid completed rotation evidence")
		}
		return nil // Completed recovery evidence survives unrelated later edits.
	}
	switch j.Phase {
	case RotationPrepared, RotationAttempting, RotationUnknown, RotationAdded, RotationVerified, RotationCommitted:
	default:
		return errors.New("invalid key rotation phase")
	}
	if j.CommitRevision != 0 || j.CommitDigest != "" {
		return errors.New("incomplete rotation contains completion evidence")
	}
	server, exists := v.Servers[j.ServerID]
	if !exists || server.Accounts[j.Account] != j.Profile {
		return errors.New("key rotation selection changed")
	}
	current, exists := v.Targets[j.Profile]
	if !exists || len(current.Password) != 0 || current.Proxy != nil || !rotationScopeEqual(current, j.Original) {
		return errors.New("key rotation scope changed")
	}
	if j.Phase == RotationCommitted {
		if !bytes.Equal(current.PrivateKey, j.NewPrivate) {
			return errors.New("committed rotation key mismatch")
		}
	} else if !bytes.Equal(current.PrivateKey, j.Original.PrivateKey) {
		return errors.New("uncommitted rotation changed the target")
	}
	return nil
}
