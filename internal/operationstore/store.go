package operationstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxRecords  = 64
	maxState    = 128 * 1024
	maxIdentity = 256
)

var ErrUnavailable = errors.New("operation state unavailable, corrupt, or quarantined")
var ErrConflict = errors.New("operation binding conflict; resource quarantined")
var ErrRollbackProtectionUnavailable = errors.New("filesystem state is not rollback protected; no authorization or invocation permitted")

type Reservation struct {
	Key               string `json:"key"`
	CanonicalTarget   string `json:"canonical_target"`
	CanonicalResource string `json:"canonical_resource"`
	PlanDigest        string `json:"plan_digest"`
	Quarantined       bool   `json:"quarantined"`
}
type state struct {
	Version     int           `json:"version"`
	Records     []Reservation `json:"records"`
	Quarantined bool          `json:"quarantined"`
}
type Store struct {
	root     string
	wait     time.Duration
	saveHook func(string) error
	io       publicationIO
	poisoned bool
}

func Open(root string, wait time.Duration) (*Store, error) {
	if !publicationSupported() {
		return nil, ErrRollbackProtectionUnavailable
	}
	if root == "" || !filepath.IsAbs(root) || wait <= 0 || wait > 30*time.Second {
		return nil, ErrUnavailable
	}
	i, e := os.Lstat(root)
	if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnavailable
	}
	return nil, ErrUnavailable
}

func valid(s string) bool {
	if len(s) == 0 || len(s) > maxIdentity || strings.TrimSpace(s) != s {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil && strings.ToLower(s) == s
}
func (s *Store) statePath() string { return filepath.Join(s.root, "state.json") }
func (s *Store) lock(ctx context.Context, fn func() error) error {
	p := filepath.Join(s.root, ".lock")
	timer := time.NewTimer(s.wait)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			if _, e = f.Write([]byte("lock")); e == nil {
				e = f.Sync()
			}
			c := f.Close()
			if e == nil {
				e = c
			}
			if e != nil {
				return ErrUnavailable
			}
			defer os.Remove(p)
			return fn()
		}
		if !errors.Is(e, os.ErrExist) {
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case <-timer.C:
			return ErrUnavailable
		case <-tick.C:
		}
	}
}
func (s *Store) load() (state, error) {
	if s.poisoned {
		return state{}, ErrUnavailable
	}
	if _, err := os.Lstat(filepath.Join(s.root, ".pending")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return state{}, ErrUnavailable
	}
	if _, e := os.Lstat(s.statePath() + ".new"); e == nil || !errors.Is(e, os.ErrNotExist) {
		return state{}, ErrUnavailable
	}
	if _, e := os.Lstat(s.statePath()); errors.Is(e, os.ErrNotExist) {
		return state{}, ErrUnavailable
	} else if e != nil {
		return state{}, ErrUnavailable
	}
	f, e := os.Open(s.statePath())
	if e != nil {
		return state{}, ErrUnavailable
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxState+1))
	if e != nil || len(b) > maxState {
		return state{}, ErrUnavailable
	}
	st, e := parseState(b)
	if e != nil {
		return st, e
	}
	return st, nil
}
func (s *Store) save(st state) error {
	b, e := json.Marshal(st)
	if e != nil || len(b) > maxState {
		return ErrUnavailable
	}
	p := s.publication()
	marker := filepath.Join(s.root, ".pending")
	mf, err := p.createFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	if err = p.writeFile(mf, []byte("pending")); err == nil {
		err = p.syncFile(mf)
	}
	closeErr := p.closeFile(mf)
	if err == nil {
		err = closeErr
	}
	if err != nil || p.syncDir(s.root) != nil {
		return ErrUnavailable
	}
	if s.saveHook != nil && s.saveHook(s.statePath()+".new") != nil {
		return ErrUnavailable
	}
	tmp := s.statePath() + ".new"
	f, err := p.createFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	err = p.writeFile(f, b)
	if err == nil {
		err = p.syncFile(f)
	}
	closeErr = p.closeFile(f)
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return ErrUnavailable
	}
	if p.rename(tmp, s.statePath()) != nil || p.syncDir(s.root) != nil {
		return ErrUnavailable
	}
	if p.syncDir(s.root) != nil {
		return ErrUnavailable
	}
	if p.remove(marker) != nil {
		s.poisoned = true
		return ErrUnavailable
	}
	if p.syncDir(s.root) != nil {
		s.poisoned = true
		return ErrUnavailable
	}
	return nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (s *Store) Reserve(ctx context.Context, r Reservation) (Reservation, error) {
	if r.Quarantined {
		return Reservation{}, ErrUnavailable
	}
	if !valid(r.Key) || !valid(r.CanonicalTarget) || !valid(r.CanonicalResource) || !digest(r.PlanDigest) {
		return Reservation{}, ErrUnavailable
	}
	var out Reservation
	e := s.lock(ctx, func() error {
		st, e := s.load()
		if e != nil {
			return e
		}
		for _, x := range st.Records {
			if x.Key == r.Key {
				if x.CanonicalTarget != r.CanonicalTarget || x.CanonicalResource != r.CanonicalResource || x.PlanDigest != r.PlanDigest || x.Quarantined {
					return ErrConflict
				}
				out = x
				return nil
			}
			if x.CanonicalTarget == r.CanonicalTarget && x.CanonicalResource == r.CanonicalResource {
				st.Quarantined = true
				for j := range st.Records {
					st.Records[j].Quarantined = true
				}
				if s.save(st) != nil {
					return ErrUnavailable
				}
				return ErrConflict
			}
		}
		if len(st.Records) >= maxRecords {
			return ErrUnavailable
		}
		out = r
		st.Records = append(st.Records, r)
		return s.save(st)
	})
	if e != nil {
		return Reservation{}, e
	}
	return out, nil
}
func (s *Store) Lookup(ctx context.Context, key string) (Reservation, error) {
	if !valid(key) {
		return Reservation{}, ErrUnavailable
	}
	var out Reservation
	e := s.lock(ctx, func() error {
		st, e := s.load()
		if e != nil {
			return e
		}
		for _, r := range st.Records {
			if r.Key == key {
				if r.Quarantined {
					return ErrConflict
				}
				out = r
				return nil
			}
		}
		return ErrUnavailable
	})
	return out, e
}
