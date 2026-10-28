package operationstore

import (
	"os"
	"path/filepath"
	"time"
)

// Initialize creates a new store only; it never repairs or replaces existing state.
func Initialize(root string, wait time.Duration) (*Store, error) {
	p := systemPublicationIO()
	return initializeWithIO(root, wait, p)
}

func initialize(root string, wait time.Duration, p publicationIO) (*Store, error) {
	return initializeWithIO(root, wait, p)
}

func initializeWithIO(root string, wait time.Duration, p publicationIO) (*Store, error) {
	if !publicationSupported() {
		return nil, ErrRollbackProtectionUnavailable
	}
	if root == "" || !filepath.IsAbs(root) || wait <= 0 || wait > 30*time.Second {
		return nil, ErrUnavailable
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, ErrUnavailable
	}
	f, err := p.createFile(filepath.Join(root, ".pending"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	err = p.writeFile(f, []byte("pending"))
	if err == nil {
		err = p.syncFile(f)
	}
	closeErr := p.closeFile(f)
	if err == nil {
		err = closeErr
	}
	if err != nil || p.syncDir(root) != nil {
		return nil, ErrUnavailable
	}
	s := &Store{root: root, wait: wait}
	f, err = p.createFile(s.statePath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	err = p.writeFile(f, []byte(`{"version":1,"records":[],"quarantined":false}`))
	if err == nil {
		err = p.syncFile(f)
	}
	closeErr = p.closeFile(f)
	if err == nil {
		err = closeErr
	}
	if err != nil || p.syncDir(root) != nil {
		return nil, ErrUnavailable
	}
	if p.syncDir(filepath.Dir(root)) != nil {
		return nil, ErrUnavailable
	}
	if p.remove(filepath.Join(root, ".pending")) != nil || p.syncDir(root) != nil {
		s.poisoned = true
		return s, ErrUnavailable
	}
	return s, nil
}
