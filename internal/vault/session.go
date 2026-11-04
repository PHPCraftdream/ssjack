package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

type SessionStatus struct {
	Revision      uint64
	SavedRevision uint64
	Pending       bool
	Err           error
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
}

// OpenSession unlocks once. Close or explicit Discard must join its worker.
func OpenSession(ctx context.Context, path string, password []byte) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := Load(path, password)
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
	if err := verifySessionAdoption(ctx, path, v); err != nil {
		v.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		v.Close()
		return nil, err
	}
	key, expected := v.unlocked, v.revision
	v.unlocked = nil
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
		if err := commit(path, encoded, &expected); err != nil {
			return err
		}
		expected = sha256.Sum256(encoded)
		return nil
	}
	s := newSession(v, save, key.Close)
	s.mu.Lock()
	s.savedCipher = expected
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || edit == nil || s.revision == math.MaxUint64 {
		return errors.New("database session does not accept edits")
	}
	if expected != nil && *expected != s.revision {
		return ErrOwnerRevision
	}
	raw, err := marshal(s.state)
	if err != nil {
		return err
	}
	defer clear(raw)
	candidate, err := unmarshal(raw)
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
	payload, err := marshal(candidate)
	if err != nil {
		return err
	}
	state, err := unmarshal(payload)
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
	return SessionStatus{Revision: s.revision, SavedRevision: s.saved, Pending: s.saved != s.revision, Err: s.saveErr}
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
	payload, err := marshal(s.state)
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
		s.mu.Unlock()
		return nil
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
	return nil
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
	s.mu.Unlock()
}
