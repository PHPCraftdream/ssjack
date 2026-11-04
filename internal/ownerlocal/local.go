// Package ownerlocal provides bounded local owner transport, never MCP access.
package ownerlocal

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
)

var (
	ErrUnavailable = errors.New("owner endpoint unavailable")
	ErrAbsent      = errors.New("owner endpoint absent")
	ErrBusy        = errors.New("owner endpoint occupied")
	ErrClosed      = errors.New("owner transport closed")
	ErrEndpoint    = errors.New("invalid owner endpoint")
)

// Connection owns its native handle. Cancellation terminates this connection.
type Connection interface {
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}

type Listener interface {
	Accept(context.Context) (Connection, error)
	Close() error
}

type Endpoint struct {
	Address string
	Binding [sha256.Size]byte
}

// Identity is metadata only; neither a path hash nor OS ownership authorizes edits.
func Identity(database string) (Endpoint, error) {
	absolute, err := filepath.Abs(database)
	if err != nil {
		return Endpoint{}, ErrEndpoint
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return Endpoint{}, ErrEndpoint
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return Endpoint{}, ErrEndpoint
	}
	canonical := normalize(filepath.Join(parent, filepath.Base(absolute)))
	if canonical == "" {
		return Endpoint{}, ErrEndpoint
	}
	binding := sha256.Sum256([]byte("ssjack/owner-endpoint/v1\x00" + canonical))
	address, err := endpointAddress(binding)
	return Endpoint{Address: address, Binding: binding}, err
}

func Listen(database string) (Listener, error) {
	endpoint, err := Identity(database)
	if err != nil {
		return nil, err
	}
	return listen(endpoint.Address)
}

func Dial(ctx context.Context, database string) (Connection, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	endpoint, err := Identity(database)
	if err != nil {
		return nil, err
	}
	return dial(ctx, endpoint.Address)
}
