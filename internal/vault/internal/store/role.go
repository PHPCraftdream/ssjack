package store

import (
	"context"
	"errors"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
)

var ErrWriterRole = errors.New("database writer role is occupied or unsafe; use the live owner channel or stop its keeper")

// Role is the exclusive single-writer claim on one database path.
type Role struct {
	mu       sync.Mutex
	listener ownerlocal.Listener
	path     string
	binding  [32]byte
	closed   bool
	err      error
}

func ClaimRole(path string) (*Role, error) {
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
	return &Role{listener: listener, path: canonical, binding: endpoint.Binding}, nil
}

// Path is the canonical database path the role was claimed for.
func (r *Role) Path() string { return r.path }

// Binding identifies the held endpoint, never an authorization grant.
func (r *Role) Binding() [32]byte { return r.binding }

func (r *Role) Write(path string, write func(string) error) error {
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

func (r *Role) Close() error {
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

func (r *Role) Accept(ctx context.Context) (ownerlocal.Connection, error) {
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
