package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
)

var ErrWriterRole = errors.New("database writer role is occupied or unsafe; use the live owner channel or stop its keeper")

type writerRole struct {
	mu       sync.Mutex
	listener ownerlocal.Listener
	path     string
	binding  [32]byte
	closed   bool
	err      error
}

func claimWriterRole(path string) (*writerRole, error) {
	canonical, err := ownerlocal.CanonicalPath(path)
	if err != nil {
		return nil, ErrWriterRole
	}
	endpoint, err := ownerlocal.Identity(canonical)
	if err != nil {
		return nil, ErrWriterRole
	}
	listener, err := ownerlocal.Listen(canonical)
	if err != nil {
		return nil, ErrWriterRole
	}
	checked, err := ownerlocal.Identity(path)
	if err != nil || checked.Binding != endpoint.Binding {
		listener.Close()
		return nil, ErrWriterRole
	}
	return &writerRole{listener: listener, path: canonical, binding: endpoint.Binding}, nil
}

func (r *writerRole) write(path string, write func(string) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrWriterRole
	}
	endpoint, err := ownerlocal.Identity(path)
	if err != nil || endpoint.Binding != r.binding {
		return ErrWriterRole
	}
	return write(r.path)
}

func (r *writerRole) close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.err = r.listener.Close()
	}
	return r.err
}

func (r *writerRole) accept(ctx context.Context) (ownerlocal.Connection, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrWriterRole
	}
	listener := r.listener
	r.mu.Unlock()
	connection, err := listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		connection.Close()
		return nil, ErrWriterRole
	}
	return connection, nil
}

// ClaimWriter pins an authenticated unchanged database before owner effects.
func (v *Vault) ClaimWriter(path string) error {
	if v == nil || v.unlocked == nil || v.revision == ([sha256.Size]byte{}) {
		return ErrWriterRole
	}
	if v.writer != nil {
		return v.writer.write(path, func(canonical string) error {
			encoded, err := readEncoded(canonical)
			if err != nil || sha256.Sum256(encoded) != v.revision {
				return ErrWriterRole
			}
			return nil
		})
	}
	role, err := claimWriterRole(path)
	if err != nil {
		return err
	}
	encoded, err := readEncoded(role.path)
	if err != nil || sha256.Sum256(encoded) != v.revision {
		role.close()
		return ErrWriterRole
	}
	v.writer = role
	return nil
}

func commitWithRole(path string, encoded []byte, expected *[sha256.Size]byte, role *writerRole) (result error) {
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
		role, err = claimWriterRole(path)
		if err != nil {
			return err
		}
		defer func() {
			if err := role.close(); err != nil {
				result = ErrWriterRole
			}
		}()
	}
	return role.write(path, func(canonical string) error { return commitFile(canonical, encoded, expected) })
}
