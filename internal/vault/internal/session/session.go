// Package session owns the live decrypted vault state and its serialized, saved edits.
package session

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
)

type (
	Vault           = core.Vault
	Target          = record.Target
	Server          = record.Server
	SecretBinding   = record.SecretBinding
	RotationJournal = core.RotationJournal
	OwnerChange     = core.OwnerChange
	OwnerStore      = core.OwnerStore
	OwnerIntent     = core.OwnerIntent
	SSHPolicy       = record.SSHPolicy
)

type SessionStatus struct {
	Revision      uint64
	SavedRevision uint64
	Pending       bool
	Err           error
	// SSH is the last observed SSH metadata; metadata reads do not refresh it.
	SSH *sshstatus.Status
}

type sessionJob struct {
	revision uint64
	payload  []byte
}

// Session owns its decrypted state, one bounded save worker and its unlock key.
type Session struct {
	mu          sync.Mutex
	closeMu     sync.Mutex
	state       *Vault
	revision    uint64
	saved       uint64
	saveErr     error
	closing     bool
	closed      bool
	jobs        chan sessionJob
	changed     chan struct{}
	done        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	save        func(context.Context, []byte) error
	release     func()
	saveDigest  func() [sha256.Size]byte
	savedCipher [sha256.Size]byte
	exportKey   *keyfile.Unlocked
	writer      *store.Role
	sshStatus   func() sshstatus.Status
	closeErr    error
}

// OpenSession unlocks once. Close or explicit Discard must join its worker.
func OpenSession(ctx context.Context, path string, password []byte) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := core.Load(path, password)
	if err != nil {
		return nil, err
	}
	return StartSession(ctx, path, v)
}

// StartSession takes ownership of an unchanged authenticated vault, including on
// error. Callers must not retain or mutate its buffers after handing it over.
func StartSession(ctx context.Context, path string, v *Vault) (*Session, error) {
	if v == nil {
		return nil, errors.New("database session requires an authenticated vault")
	}
	if err := core.VerifyAdoption(ctx, path, v); err != nil {
		v.Close()
		return nil, err
	}
	if err := v.ClaimWriter(path); err != nil {
		v.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		v.Close()
		return nil, err
	}
	key, expected, role := core.Handoff(v)
	save := func(ctx context.Context, payload []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		encoded, err := key.Seal(payload)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := store.CommitWithRole(path, encoded, &expected, role); err != nil {
			return err
		}
		expected = sha256.Sum256(encoded)
		return nil
	}
	s := newSession(v, save, key.Close)
	s.mu.Lock()
	s.savedCipher, s.writer = expected, role
	s.exportKey = key
	s.saveDigest = func() [sha256.Size]byte { return expected }
	s.mu.Unlock()
	return s, nil
}

func newSession(state *Vault, save func(context.Context, []byte) error, release func()) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{state: state, jobs: make(chan sessionJob, 1), changed: make(chan struct{}), done: make(chan struct{}), ctx: ctx, cancel: cancel, save: save, release: release}
	go s.run()
	return s
}

func (s *Session) signal() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Session) enqueue(payload []byte) {
	select {
	case old := <-s.jobs:
		clear(old.payload)
	default:
	}
	s.jobs <- sessionJob{revision: s.revision, payload: payload}
	s.signal()
}

var ErrOwnerRevision = errors.New("owner database revision changed")

// Apply edits an owned candidate; failed or cancelled forms cannot change state.
// The callback must not start background work or retain the candidate's buffers.
func (s *Session) Apply(edit func(*Vault) error) error { return s.apply(nil, edit) }
func (s *Session) ApplyAt(expected uint64, edit func(*Vault) error) error {
	return s.apply(&expected, edit)
}
func (s *Session) apply(expected *uint64, edit func(*Vault) error) error {
	return s.applyWithRotation(expected, edit, false)
}
func (s *Session) applyRotationAt(expected uint64, edit func(*Vault) error) error {
	return s.applyWithRotation(&expected, edit, true)
}
func (s *Session) applyWithRotation(expected *uint64, edit func(*Vault) error, rotation bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyWithRotationLocked(expected, edit, rotation)
}
func (s *Session) applyWithRotationLocked(expected *uint64, edit func(*Vault) error, rotation bool) error {
	if s.closed || s.closing || edit == nil || s.revision == math.MaxUint64 {
		return errors.New("database session does not accept edits")
	}
	if !rotation && core.RotationActive(s.state.Rotation) {
		return errors.New("resolve the pending key rotation before editing the database")
	}
	if expected != nil && *expected != s.revision {
		return ErrOwnerRevision
	}
	raw, err := core.Marshal(s.state)
	if err != nil {
		return err
	}
	defer clear(raw)
	candidate, err := core.Unmarshal(raw)
	if err != nil {
		return err
	}
	defer candidate.Close()
	if err := edit(candidate); err != nil {
		return err
	}
	if candidate.Version != 2 {
		return errors.New("directory editing cannot change the database schema version")
	}
	payload, err := core.Marshal(candidate)
	if err != nil {
		return err
	}
	state, err := core.Unmarshal(payload)
	if err != nil {
		clear(payload)
		return err
	}
	s.state.Close()
	s.state = state
	s.revision++
	s.enqueue(payload)
	return nil
}

func (s *Session) Status() SessionStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionStatus{Revision: s.revision, SavedRevision: s.saved, Pending: s.saved != s.revision, Err: s.saveErr, SSH: s.sshSnapshot()}
}

// Retry is explicit; a revision conflict never authorizes overwriting the file.
func (s *Session) Retry() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing {
		return errors.New("database session is closing")
	}
	if s.saveErr == nil {
		return nil
	}
	payload, err := core.Marshal(s.state)
	if err != nil {
		return err
	}
	s.saveErr = nil
	s.enqueue(payload)
	return nil
}

func (s *Session) Flush(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.saved == s.revision {
			s.mu.Unlock()
			return nil
		}
		if s.saveErr != nil || s.closed {
			err := s.saveErr
			if err == nil {
				err = errors.New("database session closed before saving")
			}
			s.mu.Unlock()
			return err
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// Close preserves the live session on save failure or a caller timeout.
func (s *Session) Close(ctx context.Context) error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closing = true
	s.mu.Unlock()
	if err := s.Flush(ctx); err != nil {
		s.mu.Lock()
		s.closing = false
		s.mu.Unlock()
		return err
	}
	s.stop()
	return s.closeErr
}

// Discard is destructive; the UI must obtain explicit owner confirmation first.
func (s *Session) Discard() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.stop()
}

func (s *Session) stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.closing = true, true
	s.cancel()
	s.signal()
	s.mu.Unlock()
	<-s.done
	s.mu.Lock()
	s.state.Close()
	s.release()
	if err := s.writer.Close(); err != nil {
		s.closeErr = store.ErrWriterRole
	}
	s.mu.Unlock()
}

func (s *Session) run() {
	defer close(s.done)
	defer func() {
		for {
			select {
			case job := <-s.jobs:
				clear(job.payload)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.jobs:
			if s.ctx.Err() != nil {
				clear(job.payload)
				return
			}
			s.mu.Lock()
			paused := s.saveErr != nil || job.revision <= s.saved
			s.mu.Unlock()
			if paused {
				clear(job.payload)
				continue
			}
			err := s.save(s.ctx, job.payload)
			clear(job.payload)
			s.mu.Lock()
			if err != nil {
				s.saveErr = err
			} else {
				s.saved = job.revision
				if s.saveDigest != nil {
					s.savedCipher = s.saveDigest()
				}
			}
			s.signal()
			s.mu.Unlock()
		}
	}
}

func (s *Session) OwnerBinding() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writer == nil || s.closed || s.closing {
		return [32]byte{}, store.ErrWriterRole
	}
	return s.writer.Binding(), nil
}

// AcceptOwner borrows admission, not listener-close or database-key authority.
// The service must join its peers before closing this session.
func (s *Session) AcceptOwner(ctx context.Context) (ownerlocal.Connection, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, store.ErrWriterRole
	}
	s.mu.Lock()
	role, unavailable := s.writer, s.closed || s.closing
	s.mu.Unlock()
	if role == nil || unavailable {
		return nil, store.ErrWriterRole
	}
	return role.Accept(ctx)
}

// SavedCipherDigest identifies a completed encrypted snapshot, not authority.
// It never returns a plaintext digest, credential, passphrase or master key.
func (s *Session) SavedCipherDigest() ([sha256.Size]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.saveErr != nil || s.saved != s.revision || s.savedCipher == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, errors.New("database snapshot is not fully saved")
	}
	return s.savedCipher, nil
}
