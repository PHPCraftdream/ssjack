package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

// DirectoryMigrationPlan retains verified ciphertext, never the database password.
type DirectoryMigrationPlan struct {
	source      string
	revision    [sha256.Size]byte
	replacement []byte
}

func PrepareDirectoryMigration(ctx context.Context, source string, password []byte) (*DirectoryMigrationPlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	previous, err := readEncoded(source)
	if err != nil {
		return nil, err
	}
	plaintext, unlocked, err := keyfile.Unlock(previous, password)
	if err != nil {
		return nil, err
	}
	defer unlocked.Close()
	defer clear(plaintext)
	v, err := unmarshal(plaintext)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	if err := v.UpgradeDirectory(); err != nil {
		return nil, err
	}
	migrated, err := marshal(v)
	if err != nil {
		return nil, err
	}
	defer clear(migrated)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	replacement, err := unlocked.Seal(migrated)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verified, err := keyfile.Open(replacement, password)
	if err != nil {
		return nil, err
	}
	defer clear(verified)
	if !bytes.Equal(verified, migrated) {
		return nil, errors.New("directory migration changed the verified payload")
	}
	decoded, err := unmarshal(verified)
	if err != nil {
		return nil, err
	}
	decoded.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &DirectoryMigrationPlan{source: source, revision: sha256.Sum256(previous), replacement: replacement}, nil
}

func (p *DirectoryMigrationPlan) checkSource() error {
	current, err := readEncoded(p.source)
	if err != nil || sha256.Sum256(current) != p.revision {
		return errors.New("source database changed; prepare migration again")
	}
	return nil
}

// Commit publishes a new encrypted file exclusively; source is never replaced.
func (p *DirectoryMigrationPlan) Commit(ctx context.Context, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || len(p.replacement) == 0 {
		return errors.New("invalid directory migration plan")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return errors.New("migration requires a new destination file")
	}
	lockPath := p.source + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot lock source database for migration")
	}
	defer os.Remove(lockPath)
	if err := lock.Close(); err != nil {
		return err
	}
	if err := p.checkSource(); err != nil {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(destination), ".ssjack-directory-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if err := writeAndClose(staged, p.replacement); err != nil {
		return err
	}
	written, err := readEncoded(staged.Name())
	if err != nil || !bytes.Equal(written, p.replacement) {
		return errors.New("staged encrypted migration verification failed")
	}
	if err := p.checkSource(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Link(staged.Name(), destination)
}
