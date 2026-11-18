// Package recovery backs up, verifies, restores and upgrades encrypted vault files.
package recovery

import (
	"context"
	"errors"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
)

func verifiedEncoded(path string, password []byte) ([]byte, error) {
	encoded, err := store.ReadEncoded(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := keyfile.Open(encoded, password)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	v, err := core.Unmarshal(plaintext)
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
	return store.Commit(destination, encoded, nil)
}

func Verify(path string, password []byte) error {
	_, err := verifiedEncoded(path, password)
	return err
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
	return store.ReplaceVerified(ctx, destination, replacement, previous, "before-restore")
}
