// Package store reads and publishes encrypted vault files under a single-writer role.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerpublication"
)

func ReadEncoded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > keyfile.MaxSize {
		return nil, errors.New("vault must be a regular encrypted file within the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, keyfile.MaxSize+1))
	if err != nil || len(data) > keyfile.MaxSize {
		return nil, errors.New("failed to read encrypted vault")
	}
	return data, nil
}

func writeAndClose(file *os.File, data []byte) error {
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func Commit(path string, encoded []byte, expected *[sha256.Size]byte) error {
	return CommitWithRole(path, encoded, expected, nil)
}

func commitFile(path string, encoded []byte, expected *[sha256.Size]byte) error {
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot lock vault; another operation or a stale lock may exist: %w", err)
	}
	defer os.Remove(lockPath)
	if err := lock.Close(); err != nil {
		return err
	}
	if expected == nil {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if err := writeAndClose(file, encoded); err != nil {
			return fmt.Errorf("new vault may be incomplete: %w", err)
		}
		return nil
	}
	current, err := ReadEncoded(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(current) != *expected {
		return errors.New("vault changed since it was read; refusing to overwrite newer credentials")
	}
	stage, err := os.CreateTemp(filepath.Dir(path), ".ssjack-vault-*")
	if err != nil {
		return err
	}
	defer os.Remove(stage.Name())
	if err := writeAndClose(stage, encoded); err != nil {
		return err
	}
	current, err = ReadEncoded(path)
	if err != nil || sha256.Sum256(current) != *expected {
		return errors.New("vault changed before replacement; original file preserved")
	}
	return ownerpublication.Replace(stage.Name(), path)
}
func RecoveryPath(path, label string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil || random == ([16]byte{}) {
		return "", errors.New("cannot create recovery snapshot identity")
	}
	return fmt.Sprintf("%s.%s-%s-%s.ssjack.ktav", path, label, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(random[:])), nil
}

// Snapshot preserves the revision previously authenticated by Load.
func ReplaceVerified(ctx context.Context, destination string, replacement, previous []byte, label string) (backup string, result error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if previous == nil {
		return "", Commit(destination, replacement, nil)
	}
	role, err := ClaimRole(destination)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := role.Close(); err != nil {
			result = ErrWriterRole
		}
	}()
	expected := sha256.Sum256(previous)
	current, err := ReadEncoded(destination)
	if err != nil || sha256.Sum256(current) != expected {
		return "", errors.New("vault changed before restore; current file preserved")
	}
	backup, err = RecoveryPath(destination, label)
	if err != nil {
		return "", err
	}
	if err := Commit(backup, previous, nil); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return backup, err
	}
	if err := CommitWithRole(destination, replacement, &expected, role); err != nil {
		return backup, fmt.Errorf("restore failed; previous encrypted snapshot retained: %w", err)
	}
	return backup, nil
}
func CommitWithRole(path string, encoded []byte, expected *[sha256.Size]byte, role *Role) (result error) {
	if role == nil {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			if expected != nil {
				return ErrWriterRole
			}
			// Initial publication remains exclusive and cannot overwrite a file.
			return commitFile(path, encoded, expected)
		} else if err != nil {
			return ErrWriterRole
		}
		var err error
		role, err = ClaimRole(path)
		if err != nil {
			return err
		}
		defer func() {
			if err := role.Close(); err != nil {
				result = ErrWriterRole
			}
		}()
	}
	return role.Write(path, func(canonical string) error { return commitFile(canonical, encoded, expected) })
}
