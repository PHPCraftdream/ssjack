package appstoreanchorcore

import (
	"encoding/binary"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

type Role byte

const (
	Reader Role = iota + 1
	Writer
)

type Grant struct {
	store      [16]byte
	credential [32]byte
	role       Role
}

// NewGrant admits fixed configuration only; TLS authentication must establish the credential.
func NewGrant(store [16]byte, credential [32]byte, role Role) (Grant, error) {
	if store == ([16]byte{}) || credential == ([32]byte{}) || (role != Reader && role != Writer) {
		return Grant{}, ErrInvalid
	}
	return Grant{store: store, credential: credential, role: role}, nil
}
func (g Grant) Valid() bool {
	return g.store != ([16]byte{}) && g.credential != ([32]byte{}) && (g.role == Reader || g.role == Writer)
}
func (g Grant) StoreID() [16]byte      { return g.store }
func (g Grant) CredentialID() [32]byte { return g.credential }
func (g Grant) Role() Role             { return g.role }

type Current struct {
	store   [16]byte
	state   appstoreanchorstate.State
	version uint64
	exists  bool
	checked bool
}

func Missing(store [16]byte) (Current, error) {
	if store == ([16]byte{}) {
		return Current{}, ErrInvalid
	}
	return Current{store: store, checked: true}, nil
}
func Existing(state appstoreanchorstate.State, version uint64) (Current, error) {
	if !state.Valid() {
		return Current{}, ErrInvalid
	}
	genesis, _ := appstoreanchorstate.Genesis(state.StoreID())
	if version == 0 && state != genesis {
		return Current{}, ErrInvalid
	}
	return Current{store: state.StoreID(), state: state, version: version, exists: true, checked: true}, nil
}
func (c Current) Valid() bool                              { return c.checked }
func (c Current) StoreID() [16]byte                        { return c.store }
func (c Current) Version() uint64                          { return c.version }
func (c Current) State() (appstoreanchorstate.State, bool) { return c.state, c.exists }

type Result struct {
	request Request
	outcome appstoreanchorreply.Outcome
	current Current
	changed bool
	checked bool
}

// Evaluate proposes one transition only; replay lookup and atomic durable publication are separate.
func Evaluate(request Request, grant Grant, current Current) (Result, error) {
	if !request.Valid() || !grant.Valid() || request.StoreID() != grant.store {
		return Result{}, ErrInvalid
	}
	result := Result{request: request, checked: true}
	if request.kind != Read && grant.role != Writer {
		result.outcome = appstoreanchorreply.Rejected
		return result, nil
	}
	if !current.checked || current.store != grant.store {
		return Result{}, ErrInvalid
	}
	result.current = current
	switch request.kind {
	case Read:
		result.outcome = appstoreanchorreply.NotFound
		if current.exists {
			result.outcome = appstoreanchorreply.ReadState
		}
	case Create:
		if current.exists {
			result.outcome = appstoreanchorreply.Conflict
			return result, nil
		}
		next, _ := Existing(request.state, 0)
		result.current = next
		result.changed = true
		result.outcome = appstoreanchorreply.Committed
	case Reserve, Commit:
		if !current.exists || current.version == ^uint64(0) {
			result.current = Current{}
			result.outcome = appstoreanchorreply.Rejected
		} else if current.state.Hash() != request.expected {
			result.outcome = appstoreanchorreply.Conflict
		} else {
			next, err := Existing(request.state, current.version+1)
			if err != nil {
				return Result{}, ErrInvalid
			}
			result.current = next
			result.changed = true
			result.outcome = appstoreanchorreply.Committed
		}
	default:
		return Result{}, ErrInvalid
	}
	return result, nil
}

// Rejected denies a valid request without returning backend state.
func Rejected(request Request) (Result, error) {
	if !request.Valid() {
		return Result{}, ErrInvalid
	}
	return Result{request: request, outcome: appstoreanchorreply.Rejected, checked: true}, nil
}

// Unknown asserts no outcome after an uncertain backend result.
func Unknown(request Request) (Result, error) {
	if !request.Valid() {
		return Result{}, ErrInvalid
	}
	return Result{request: request, outcome: appstoreanchorreply.Unknown, checked: true}, nil
}
func (r Result) Valid() bool                          { return r.checked }
func (r Result) Outcome() appstoreanchorreply.Outcome { return r.outcome }
func (r Result) Next() (Current, bool) {
	if !r.checked || !r.changed {
		return Current{}, false
	}
	return r.current, true
}

// Unsigned returns public correlation/state bytes for a separately enrolled service signer.
func (r Result) Unsigned() ([288]byte, error) {
	var b [288]byte
	if !r.checked || !r.request.Valid() {
		return b, ErrInvalid
	}
	copy(b[:8], "SSASRSP1")
	b[8] = byte(r.request.Operation())
	b[9] = byte(r.outcome)
	id, store := r.request.RequestID(), r.request.StoreID()
	copy(b[16:32], id[:])
	copy(b[32:48], store[:])
	binary.BigEndian.PutUint64(b[48:56], r.current.version)
	if r.outcome == appstoreanchorreply.ReadState || r.outcome == appstoreanchorreply.Committed || r.outcome == appstoreanchorreply.Conflict {
		if !r.current.checked || !r.current.exists {
			return [288]byte{}, ErrInvalid
		}
		binary.BigEndian.PutUint16(b[56:58], 192)
		raw, hash := r.current.state.Bytes(), r.current.state.Hash()
		copy(b[64:256], raw[:])
		copy(b[256:288], hash[:])
	}
	return b, nil
}
