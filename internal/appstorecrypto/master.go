// Package appstorecrypto owns dedicated app-store key material, not authority.
package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"runtime"
	"sync"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/kdfgate"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var ErrInvalid = errors.New("invalid application-store master derivation input")
var ErrDerivation = errors.New("application-store master derivation failed")

type deriveFunc func(password, salt []byte) []byte

type masterState struct {
	mu    sync.Mutex
	key   [32]byte
	store [16]byte
	salts [4][32]byte
	ready bool
}

// Copies share owned state, so Close clears the same key through every handle.
type Master struct{ state *masterState }

func argonDerive(password, salt []byte) []byte {
	part := argon2.IDKey(password, salt, 1, 1048576, 1, 32)
	runtime.GC()
	return part
}

// Derive does not verify a passphrase, authenticate a snapshot or permit encryption.
func Derive(ctx context.Context, header appstoreheader.Header, passphrase []byte) (*Master, error) {
	return deriveAdmitted(ctx, header, passphrase, argonDerive)
}

func deriveAdmitted(ctx context.Context, header appstoreheader.Header, passphrase []byte, fn deriveFunc) (*Master, error) {
	if ctx == nil || !header.Valid() {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	release, err := appstorebudget.TryAcquire(header.StoreID())
	if err != nil {
		if errors.Is(err, appstorebudget.ErrBusy) {
			return nil, ErrBusy
		}
		return nil, ErrInvalid
	}
	defer release()
	return derive(ctx, header, passphrase, fn)
}

func derive(ctx context.Context, header appstoreheader.Header, passphrase []byte, fn deriveFunc) (*Master, error) {
	if ctx == nil || !header.Valid() || len(passphrase) == 0 || len(passphrase) > 16384 || fn == nil {
		return nil, ErrInvalid
	}
	owned := append([]byte(nil), passphrase...)
	var release func()
	defer func() {
		clear(owned)
		if release != nil {
			release()
		}
	}()
	if !utf8.Valid(owned) || bytes.IndexByte(owned, 0) >= 0 {
		return nil, ErrInvalid
	}
	var err error
	release, err = kdfgate.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var combined [128]byte
	defer clear(combined[:])
	salts := header.Salts()
	for i := range salts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		part := fn(owned, salts[i][:])
		if len(part) != 32 {
			clear(part)
			return nil, ErrDerivation
		}
		copy(combined[i*32:(i+1)*32], part)
		clear(part)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	var key [32]byte
	defer clear(key[:])
	if _, err := io.ReadFull(hkdf.New(sha256.New, combined[:], nil, []byte("ssjack-appstore/v1/master")), key[:]); err != nil {
		return nil, ErrDerivation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Master{state: &masterState{key: key, store: header.StoreID(), salts: salts, ready: true}}, nil
}

func (m *Master) Closed() bool {
	if m == nil || m.state == nil {
		return true
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return !m.state.ready
}

// Matches checks the dedicated store/salt context, not snapshot authentication.
func (m *Master) Matches(header appstoreheader.Header) bool {
	if m == nil || m.state == nil || !header.Valid() {
		return false
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return m.state.ready && m.state.store == header.StoreID() && m.state.salts == header.Salts()
}

func (m *Master) Close() error {
	if m == nil || m.state == nil {
		return nil
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	clear(m.state.key[:])
	m.state.ready = false
	return nil
}
