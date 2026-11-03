// Package appstoreanchorledger persists anchor metadata, not application secret bytes.
package appstoreanchorledger

import (
	"bytes"
	"errors"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
)

var ErrInvalid = errors.New("invalid anchor ledger")
var ErrUnavailable = errors.New("anchor ledger unavailable")
var ErrUncertain = errors.New("anchor ledger publication uncertain; backend fenced")
var ErrConflict = errors.New("anchor ledger canonical request collision")
var ErrCapacity = errors.New("anchor ledger lifetime capacity exhausted")
var ErrBusy = errors.New("anchor ledger busy")
var ErrClosed = errors.New("anchor ledger closed")
var ErrUnsupported = errors.New("anchor ledger unsupported on this platform")

const MaxRecords = 4096

type requestKey struct {
	credential [32]byte
	id         [16]byte
}
type mutationKey struct {
	credential [32]byte
	kind       appstoreanchorcore.Kind
	key        [32]byte
}
type record struct {
	request appstoreanchorcore.Request
	grant   appstoreanchorcore.Grant
	result  appstoreanchorcore.Result
}
type backendState struct {
	mu             sync.Mutex
	root, log      *os.File
	store          [16]byte
	limit          int
	records        []record
	requests       map[requestKey]int
	mutations      map[mutationKey]int
	current        appstoreanchorcore.Current
	head           [32]byte
	closed, fenced bool
	write          func([]byte) (int, error)
	syncFile       func(*os.File) error
}
type Backend struct{ state *backendState }

// StoreID returns immutable routing metadata, not backend health or authority.
func (b *Backend) StoreID() [16]byte {
	if b == nil || b.state == nil {
		return [16]byte{}
	}
	return b.state.store
}

// New owns separate directory/file handles. Caller must establish trusted durable root provenance.
func New(directory *os.File, store [16]byte, capacity int) (*Backend, error) {
	return openBackend(directory, store, capacity)
}

func keys(r appstoreanchorcore.Request, g appstoreanchorcore.Grant) (requestKey, mutationKey) {
	key, _ := r.Key()
	return requestKey{g.CredentialID(), r.RequestID()}, mutationKey{g.CredentialID(), r.Kind(), key}
}

// Execute returns a mutation outcome only after publication sync; errors return no outcome.
func (b *Backend) Execute(r appstoreanchorcore.Request, g appstoreanchorcore.Grant) (appstoreanchorcore.Result, error) {
	if b == nil || b.state == nil {
		return appstoreanchorcore.Result{}, ErrClosed
	}
	s := b.state
	if !s.mu.TryLock() {
		return appstoreanchorcore.Result{}, ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed {
		return appstoreanchorcore.Result{}, ErrClosed
	}
	if s.fenced {
		return appstoreanchorcore.Result{}, ErrUncertain
	}
	if !r.Valid() || !g.Valid() || r.StoreID() != s.store || g.StoreID() != s.store {
		return appstoreanchorcore.Result{}, ErrInvalid
	}
	if err := checkFiles(s, headerSize+recordSize*int64(len(s.records))); err != nil {
		s.fenced = true
		return appstoreanchorcore.Result{}, ErrUnavailable
	}
	// Unauthorized mutations are not accepted transactions and cannot consume durable capacity.
	if r.Kind() != appstoreanchorcore.Read && g.Role() != appstoreanchorcore.Writer {
		return appstoreanchorcore.Evaluate(r, g, appstoreanchorcore.Current{})
	}
	request, mutation := keys(r, g)
	byID, hasID := s.requests[request]
	byKey, hasKey := s.mutations[mutation]
	if r.Kind() == appstoreanchorcore.Read {
		if hasID {
			return appstoreanchorcore.Result{}, ErrConflict
		}
		return appstoreanchorcore.Evaluate(r, g, s.current)
	}
	if hasID || hasKey {
		if !hasID || !hasKey || byID != byKey || !bytes.Equal(s.records[byID].request.Bytes(), r.Bytes()) {
			return appstoreanchorcore.Result{}, ErrConflict
		}
		return s.records[byID].result, nil
	}
	if len(s.records) >= s.limit {
		return appstoreanchorcore.Result{}, ErrCapacity
	}
	result, err := appstoreanchorcore.Evaluate(r, g, s.current)
	if err != nil {
		return appstoreanchorcore.Result{}, ErrInvalid
	}
	item := record{request: r, grant: g, result: result}
	raw, head, err := encodeRecord(s, item)
	if err != nil {
		return appstoreanchorcore.Result{}, ErrInvalid
	}
	n, err := s.write(raw[:])
	if err != nil || n != len(raw) {
		s.fenced = true
		return appstoreanchorcore.Result{}, ErrUncertain
	}
	if s.syncFile(s.log) != nil || s.syncFile(s.root) != nil {
		s.fenced = true
		return appstoreanchorcore.Result{}, ErrUncertain
	}
	if err := checkFiles(s, headerSize+recordSize*int64(len(s.records)+1)); err != nil {
		s.fenced = true
		return appstoreanchorcore.Result{}, ErrUncertain
	}
	remember(s, item, head)
	return result, nil
}

func remember(s *backendState, item record, head [32]byte) {
	request, mutation := keys(item.request, item.grant)
	index := len(s.records)
	s.requests[request] = index
	s.mutations[mutation] = index
	s.records = append(s.records, item)
	s.head = head
	if next, changed := item.result.Next(); changed {
		s.current = next
	}
}

func (b *Backend) Close() error {
	if b == nil || b.state == nil {
		return nil
	}
	s := b.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	first := s.log.Close()
	second := s.root.Close()
	if first != nil || second != nil {
		return ErrUnavailable
	}
	return nil
}
