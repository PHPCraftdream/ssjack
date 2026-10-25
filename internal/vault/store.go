package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"storagehost/internal/keyfile"
)

func readEncoded(path string) ([]byte, error) {
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

func Load(path string, password []byte) (*Vault, error) {
	encoded, err := readEncoded(path)
	if err != nil {
		return nil, err
	}
	plaintext, unlocked, err := keyfile.Unlock(encoded, password)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	v, err := unmarshal(plaintext)
	if err != nil {
		unlocked.Close()
		return nil, err
	}
	v.unlocked = unlocked
	v.revision = sha256.Sum256(encoded)
	v.format, err = keyfile.Format(encoded)
	if err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

// NewUnlocked prepares one master for generation and initial database storage.
func NewUnlocked(password []byte) (*Vault, error) {
	unlocked, err := keyfile.NewUnlocked(password, 2)
	if err != nil {
		return nil, err
	}
	v := New()
	v.unlocked = unlocked
	v.format = 2
	return v, nil
}

func (v *Vault) GenerateIdentity() ([]byte, []byte, error) {
	if v.unlocked == nil {
		return nil, nil, errors.New("vault has no unlocked encryption context")
	}
	return v.unlocked.GenerateIdentity()
}

func CreateUnlocked(ctx context.Context, path string, v *Vault) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.unlocked == nil {
		return errors.New("vault has no unlocked encryption context")
	}
	plaintext, err := marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encoded, err := v.unlocked.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commit(path, encoded, nil); err != nil {
		return err
	}
	v.revision = sha256.Sum256(encoded)
	return nil
}

func Create(path string, password []byte) error {
	return CreateContext(context.Background(), path, password)
}

func CreateContext(ctx context.Context, path string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v := New()
	defer v.Close()
	return CreateWithRecords(ctx, path, v, password)
}

func CreateWithRecords(ctx context.Context, path string, v *Vault, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plaintext, err := marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encoded, err := keyfile.Seal(plaintext, password)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return commit(path, encoded, nil)
}

func Save(path string, v *Vault, password []byte) error {
	return SaveContext(context.Background(), path, v, password)
}

func SaveContext(ctx context.Context, path string, v *Vault, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	plaintext, err := marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	unlocked, err := keyfile.NewUnlocked(password, v.format)
	if err != nil {
		return err
	}
	retained := false
	defer func() {
		if !retained {
			unlocked.Close()
		}
	}()
	encoded, err := unlocked.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commit(path, encoded, &v.revision); err != nil {
		return err
	}
	v.revision = sha256.Sum256(encoded)
	v.unlocked.Close()
	v.unlocked = unlocked
	retained = true
	return nil
}

// SaveUnlocked uses only the master retained by Load, never the password again.
func SaveUnlocked(ctx context.Context, path string, v *Vault) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.unlocked == nil {
		return errors.New("vault has no unlocked encryption context")
	}
	plaintext, err := marshal(v)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	encoded, err := v.unlocked.Seal(plaintext)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commit(path, encoded, &v.revision); err != nil {
		return err
	}
	v.revision = sha256.Sum256(encoded)
	return nil
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

func commit(path string, encoded []byte, expected *[sha256.Size]byte) error {
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
	current, err := readEncoded(path)
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
	current, err = readEncoded(path)
	if err != nil || sha256.Sum256(current) != *expected {
		return errors.New("vault changed before replacement; original file preserved")
	}
	return os.Rename(stage.Name(), path)
}
