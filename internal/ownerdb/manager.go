// Package ownerdb coordinates trusted-local owner operations, never MCP tools.
package ownerdb

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/ownerclone"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var ErrPending = errors.New("owner change requires explicit inspection or database-save recovery")

type Status struct {
	Database vault.SessionStatus
	Busy     bool
	Pending  bool
	Err      error
}

type Manager struct {
	mu             sync.Mutex
	closeMu        sync.Mutex
	path           string
	db             *vault.Session
	link           *vault.OwnerStore
	linking        *vault.OwnerStore
	pending        *vault.OwnerIntent
	confirmed      *appstorecrypto.SnapshotCommit
	resources      *resources
	exportRequest  *ExportRequest
	busy           bool
	closed         bool
	closing        bool
	err            error
	imp            importState
	importSequence uint64
	jobs           chan string
	changed        chan struct{}
	done           chan struct{}
	ctx            context.Context
	cancel         context.CancelFunc
}

func Open(ctx context.Context, path string, password []byte) (*Manager, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("owner session requires an active context")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	loaded, err := vault.Load(absolute, password)
	if err != nil {
		return nil, err
	}
	return Adopt(ctx, absolute, loaded)
}

// Adopt consumes one authenticated unchanged vault without another KDF.
func Adopt(ctx context.Context, path string, loaded *vault.Vault) (*Manager, error) {
	if loaded == nil {
		return nil, errors.New("owner adoption requires an authenticated vault")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		loaded.Close()
		return nil, err
	}
	link := copyLink(loaded.OwnerStore)
	db, err := vault.StartSession(ctx, absolute, loaded)
	if err != nil {
		clearLink(link)
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	m := &Manager{path: absolute, db: db, link: link, jobs: make(chan string, 1), changed: make(chan struct{}), done: make(chan struct{}), ctx: lifetime, cancel: cancel}
	if link != nil && link.Pending != nil {
		m.pending = copyIntent(link.Pending)
		m.err = ErrPending
	}
	go m.run()
	return m, nil
}

func copyLink(link *vault.OwnerStore) *vault.OwnerStore { return ownerclone.Link(link) }
func clearLink(link *vault.OwnerStore)                  { ownerclone.ClearLink(link) }

func (m *Manager) AcceptOwner(ctx context.Context) (ownerlocal.Connection, error) {
	return m.db.AcceptOwner(ctx)
}

func (m *Manager) ConfirmImportPlanAt(expected, plan uint64) error {
	return m.confirmImport(&expected, &plan)
}
func (m *Manager) ResumeImportPlanAt(expected, plan uint64) error {
	return m.resumeImport(&expected, &plan)
}
func (m *Manager) AbortImportPlanAt(expected, plan uint64) error {
	return m.abortImport(&expected, &plan)
}

func (m *Manager) signal() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *Manager) Metadata() (vault.DirectoryMetadata, error) { return m.db.Metadata() }

// Edit is a trusted owner form callback, not a public model-facing getter.
// While an import is applying or partial it is refused: an edit to an imported
// account or alias between a failure and resume would otherwise go unnoticed.
func (m *Manager) Edit(edit func(*vault.Vault) error) error { return m.edit(nil, edit) }
func (m *Manager) EditAt(expected uint64, edit func(*vault.Vault) error) error {
	return m.edit(&expected, edit)
}
func (m *Manager) edit(expected *uint64, edit func(*vault.Vault) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || edit == nil || m.imp.owns() {
		return ErrPending
	}
	apply := m.db.Apply
	if expected != nil {
		apply = func(edit func(*vault.Vault) error) error { return m.db.ApplyAt(*expected, edit) }
	}
	return apply(func(v *vault.Vault) error {
		owner := copyLink(v.OwnerStore)
		defer clearLink(owner)
		aliases := make(map[string]vault.SecretBinding, len(v.Secrets))
		for id, alias := range v.Secrets {
			aliases[id] = alias
		}
		if err := edit(v); err != nil {
			return err
		}
		if !reflect.DeepEqual(owner, v.OwnerStore) || !reflect.DeepEqual(aliases, v.Secrets) {
			return errors.New("server forms cannot change linked owner material or secret bindings")
		}
		return nil
	})
}

func (m *Manager) Submit(change vault.OwnerChange) error { return m.submit(nil, change) }
func (m *Manager) SubmitAt(expected uint64, change vault.OwnerChange) error {
	return m.submit(&expected, change)
}
func (m *Manager) submit(expected *uint64, change vault.OwnerChange) error {
	if !appstoreentry.Supported() {
		return errors.New("linked secret editing requires a supported native owner runtime")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.link == nil || m.imp.owns() {
		return ErrPending
	}
	var pending *vault.OwnerIntent
	apply := m.db.Apply
	if expected != nil {
		apply = func(edit func(*vault.Vault) error) error { return m.db.ApplyAt(*expected, edit) }
	}
	err := apply(func(v *vault.Vault) error {
		if _, err := v.StageOwnerChange(change); err != nil {
			return err
		}
		pending = copyIntent(v.OwnerStore.Pending)
		return nil
	})
	if err != nil {
		if pending != nil {
			clear(pending.Change.Value)
		}
		return err
	}
	m.pending, m.busy = pending, true
	m.jobs <- pending.ID
	m.signal()
	return nil
}

func (m *Manager) admit(expected *uint64, publish func() error) error {
	if expected == nil {
		return publish()
	}
	if m.db == nil {
		return ErrPending
	}
	return m.db.AdmitAt(*expected, publish)
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{Database: m.db.Status(), Busy: m.busy, Pending: m.pending != nil, Err: m.err}
}

func (m *Manager) Flush(ctx context.Context) error {
	for {
		m.mu.Lock()
		if !m.busy {
			err, pending := m.err, m.pending != nil
			m.mu.Unlock()
			if err != nil {
				return err
			}
			if pending {
				return ErrPending
			}
			return m.db.Flush(ctx)
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (m *Manager) Close(ctx context.Context) error {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closing = true
	m.mu.Unlock()
	if err := m.Flush(ctx); err != nil {
		m.mu.Lock()
		m.closing = false
		m.mu.Unlock()
		return err
	}
	if err := m.resources.CloseConsumers(ctx); err != nil {
		m.mu.Lock()
		m.closing = false
		m.mu.Unlock()
		return err
	}
	if err := m.db.Close(ctx); err != nil {
		m.mu.Lock()
		m.closing = false
		m.mu.Unlock()
		return err
	}
	m.stop()
	return nil
}

// Discard must follow explicit owner confirmation of any unsaved/pending state.
func (m *Manager) Discard() {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	m.stop()
	m.db.Discard()
}

func (m *Manager) stop() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	if m.imp.cancel != nil {
		m.imp.cancel()
	}
	m.signal()
	m.mu.Unlock()
	<-m.done
	m.resources.Close()
	clearLink(m.link)
	clearLink(m.linking)
	if m.pending != nil {
		clear(m.pending.Change.Value)
	}
	// Staged import material is RAM-only and is discarded on exit.
	m.mu.Lock()
	m.imp.reset()
	m.imp.phase = ImportIdle
	m.mu.Unlock()
}
