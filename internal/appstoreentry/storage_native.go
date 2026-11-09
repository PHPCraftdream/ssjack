//go:build darwin || windows

package appstoreentry

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

const maxBinding = 300 << 10
const bindingName = "binding.bin"

var ErrUnsupported = errors.New("protected installation storage unavailable on this filesystem")
var errStorage = errors.New("protected storage operation failed")

func Supported() bool { return true }

type Store struct {
	root        *ownerfs.Root
	unlock      func() error
	path        string
	dev, ino    uint64
	bindingStat ownerfs.Metadata
	loaded      bool
}

func Open(path string) (_ *Store, err error) {
	if !filepath.IsAbs(path) {
		return nil, errStorage
	}
	root, err := ownerfs.Open(path)
	if err != nil {
		return nil, errStorage
	}
	store := &Store{root: root, path: filepath.Clean(path)}
	defer func() {
		if err != nil {
			store.Close()
		}
	}()
	store.dev, store.ino, err = root.Identity()
	if err != nil || store.dev == 0 || store.ino == 0 {
		return nil, errStorage
	}
	store.unlock, err = root.LockName(".lock")
	if err != nil {
		return nil, errStorage
	}
	return store, nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var result error
	if s.unlock != nil {
		result = s.unlock()
		s.unlock = nil
	}
	if s.root != nil {
		if err := s.root.Close(); result == nil {
			result = err
		}
		s.root = nil
	}
	return result
}
func (s *Store) checkDir() error {
	if s == nil || s.root == nil {
		return errStorage
	}
	dev, ino, err := s.root.Identity()
	if err != nil || dev != s.dev || ino != s.ino {
		return errStorage
	}
	again, err := ownerfs.Open(s.path)
	if err != nil {
		return errStorage
	}
	defer again.Close()
	dev, ino, err = again.Identity()
	if err != nil || dev != s.dev || ino != s.ino {
		return errStorage
	}
	return nil
}
func (s *Store) Identity() (uint64, uint64, error) {
	if s.checkDir() != nil {
		return 0, 0, errStorage
	}
	return s.dev, s.ino, nil
}
func (s *Store) Root() (*os.File, error) {
	if s.checkDir() != nil {
		return nil, errStorage
	}
	return s.root.File()
}
func (s *Store) RequireUninstalled() error {
	if s.checkDir() != nil {
		return errStorage
	}
	file, err := s.root.Read(bindingName)
	if errors.Is(err, ownerfs.ErrMissing) {
		return nil
	}
	if file != nil {
		file.Close()
	}
	return errStorage
}
func (s *Store) readBinding() ([]byte, ownerfs.Metadata, error) {
	file, err := s.root.Read(bindingName)
	if err != nil {
		return nil, ownerfs.Metadata{}, errStorage
	}
	defer file.Close()
	before, err := ownerfs.Stat(file, false)
	if err != nil || before.Directory || before.Size <= 0 || before.Size > maxBinding {
		return nil, ownerfs.Metadata{}, errStorage
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxBinding+1))
	after, statErr := ownerfs.Stat(file, false)
	if err != nil || statErr != nil || int64(len(encoded)) != before.Size || before != after {
		return nil, ownerfs.Metadata{}, errStorage
	}
	named, err := s.root.Read(bindingName)
	if err != nil {
		return nil, ownerfs.Metadata{}, errStorage
	}
	identity, statErr := ownerfs.Stat(named, false)
	closeErr := named.Close()
	if statErr != nil || closeErr != nil || identity != after {
		return nil, ownerfs.Metadata{}, errStorage
	}
	return encoded, after, nil
}
func (s *Store) Install(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maxBinding || s.checkDir() != nil {
		return errStorage
	}
	file, err := s.root.Write(bindingName, true)
	if err != nil {
		return errStorage
	}
	n, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	installed, statErr := ownerfs.Stat(file, false)
	closeErr := file.Close()
	if writeErr != nil || n != len(encoded) || syncErr != nil || statErr != nil || closeErr != nil || s.root.Flush(bindingName) != nil {
		return errStorage
	}
	got, actual, err := s.readBinding()
	if err != nil || !bytes.Equal(got, encoded) || actual.Dev != installed.Dev || actual.Ino != installed.Ino {
		return errStorage
	}
	s.bindingStat, s.loaded = actual, true
	return nil
}
func (s *Store) Load() ([]byte, [32]byte, error) {
	if s.checkDir() != nil {
		return nil, [32]byte{}, errStorage
	}
	encoded, metadata, err := s.readBinding()
	if err != nil {
		return nil, [32]byte{}, err
	}
	s.bindingStat, s.loaded = metadata, true
	return encoded, sha256.Sum256(encoded), nil
}
func (s *Store) VerifyUnchanged(expected [32]byte) error {
	if s.checkDir() != nil || !s.loaded {
		return errStorage
	}
	encoded, metadata, err := s.readBinding()
	if err != nil || metadata != s.bindingStat || sha256.Sum256(encoded) != expected {
		return errStorage
	}
	return nil
}
