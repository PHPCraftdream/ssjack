package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerpublication"
)

func verifiedEncoded(path string, password []byte) ([]byte, error) {
	encoded, err := readEncoded(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := keyfile.Open(encoded, password)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	v, err := unmarshal(plaintext)
	if err != nil {
		return nil, err
	}
	v.Close()
	return encoded, nil
}

// Backup copies exactly the ciphertext that was authenticated and validated.
func Backup(ctx context.Context, source, destination string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := verifiedEncoded(source, password)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return commit(destination, encoded, nil)
}

func Verify(path string, password []byte) error {
	_, err := verifiedEncoded(path, password)
	return err
}

func RecoveryPath(path, label string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil || random == ([16]byte{}) {
		return "", errors.New("cannot create recovery snapshot identity")
	}
	return fmt.Sprintf("%s.%s-%s-%s.ssjack.ktav", path, label, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(random[:])), nil
}

// Snapshot preserves the revision previously authenticated by Load.
func Snapshot(path string, v *Vault) (string, error) {
	encoded, err := readEncoded(path)
	if err != nil {
		return "", err
	}
	if sha256.Sum256(encoded) != v.revision {
		return "", errors.New("vault changed before recovery snapshot; reload it first")
	}
	backup, err := RecoveryPath(path, "snapshot")
	if err != nil {
		return "", err
	}
	if err := commit(backup, encoded, nil); err != nil {
		return "", err
	}
	return backup, nil
}

type RestorePlan struct {
	destination string
	replacement []byte
	previous    []byte
}

func (p *RestorePlan) Commit(ctx context.Context) (string, error) {
	return restoreVerified(ctx, p.destination, p.replacement, p.previous)
}

func Restore(ctx context.Context, destination, source string, sourcePassword, currentPassword []byte) (string, error) {
	plan, err := PrepareRestore(destination, source, sourcePassword, currentPassword)
	if err != nil {
		return "", err
	}
	return plan.Commit(ctx)
}

func PrepareRestore(destination, source string, sourcePassword, currentPassword []byte) (*RestorePlan, error) {
	if left, err := os.Stat(destination); err == nil {
		if right, err := os.Stat(source); err == nil && os.SameFile(left, right) {
			return nil, errors.New("restore source and destination must be different files")
		}
	}
	replacement, err := verifiedEncoded(source, sourcePassword)
	if err != nil {
		return nil, err
	}
	var previous []byte
	if _, err := os.Lstat(destination); err == nil {
		previous, err = verifiedEncoded(destination, currentPassword)
		if err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return &RestorePlan{destination: destination, replacement: replacement, previous: previous}, nil
}

func restoreVerified(ctx context.Context, destination string, replacement, previous []byte) (string, error) {
	return replaceVerified(ctx, destination, replacement, previous, "before-restore")
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
	if j == nil || j.ID != id || j.PlanID != planID || j.Phase != RotationComplete || !validOwnerHash(j.CommitDigest) || j.RecoveryPath != "" || j.RecoveryDigest != "" || s.state.validateRotation() != nil {
		return RotationInfo{}, ErrOwnerRevision
	}
	encoded, err := readEncoded(path)
	if err != nil {
		return RotationInfo{}, err
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	if digest != s.savedCipher {
		return RotationInfo{}, errors.New("completed rotation ciphertext changed; archive refused")
	}
	archive, err := RecoveryPath(path, "rotation-"+id)
	if err != nil {
		return RotationInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return RotationInfo{}, err
	}
	if err := commit(archive, encoded, nil); err != nil {
		return RotationInfo{}, err
	}
	verify, err := readEncoded(archive)
	if err != nil || sha256.Sum256(verify) != digest {
		clear(verify)
		return RotationInfo{}, errors.New("rotation archive ciphertext proof failed; both files were preserved")
	}
	clear(verify)
	if err := ownerpublication.Sync(archive); err != nil {
		return RotationInfo{}, errors.New("rotation archive durability is uncertain; both files were preserved")
	}
	verify, err = readEncoded(archive)
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
		if journal == nil || journal.ID != id || journal.PlanID != planID || journal.Phase != RotationComplete || journal.CommitDigest != commitDigest {
			return ErrOwnerRevision
		}
		journal.Phase, journal.RecoveryPath, journal.RecoveryDigest = RotationArchived, archive, encodedDigest
		journal.clear()
		journal.Original, journal.NewPrivate, journal.NewPublic, journal.OldPublic = Target{}, nil, nil, nil
		return nil
	}, true); err != nil {
		return RotationInfo{}, err
	}
	return rotationInfo(s.state.Rotation), nil
}

func replaceVerified(ctx context.Context, destination string, replacement, previous []byte, label string) (backup string, result error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if previous == nil {
		return "", commit(destination, replacement, nil)
	}
	role, err := claimWriterRole(destination)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := role.close(); err != nil {
			result = ErrWriterRole
		}
	}()
	expected := sha256.Sum256(previous)
	current, err := readEncoded(destination)
	if err != nil || sha256.Sum256(current) != expected {
		return "", errors.New("vault changed before restore; current file preserved")
	}
	backup, err = RecoveryPath(destination, label)
	if err != nil {
		return "", err
	}
	if err := commit(backup, previous, nil); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return backup, err
	}
	if err := commitWithRole(destination, replacement, &expected, role); err != nil {
		return backup, fmt.Errorf("restore failed; previous encrypted snapshot retained: %w", err)
	}
	return backup, nil
}
