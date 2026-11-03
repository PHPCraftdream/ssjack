package ownerdb

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func cipherDigest(path string) ([32]byte, error) {
	var result [32]byte
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > keyfile.MaxSize {
		return result, errors.New("owner database is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return result, errors.New("owner database identity changed")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, keyfile.MaxSize+1))
	if err != nil || n > keyfile.MaxSize {
		return result, errors.New("owner database ciphertext could not be checked")
	}
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func syncDatabase(ctx context.Context, path string, db *vault.Session) error {
	if err := db.Flush(ctx); err != nil {
		return err
	}
	expected, err := db.SavedCipherDigest()
	if err != nil {
		return err
	}
	before, err := cipherDigest(path)
	if err != nil || before != expected {
		return errors.New("owner database changed before durable intent publication")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	after, err := cipherDigest(path)
	if err != nil || after != expected {
		return errors.New("owner database changed during durable intent publication")
	}
	return ctx.Err()
}
