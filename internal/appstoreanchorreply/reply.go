// Package appstoreanchorreply checks signatures, not enrolled transport authority.
package appstoreanchorreply

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

const Size = 352

type Operation byte

const (
	Read Operation = iota + 1
	CreateIfAbsent
	CAS
)

type Outcome byte

const (
	ReadState Outcome = iota + 1
	Committed
	Conflict
	Rejected
	Unknown
	NotFound
)

type Expected struct {
	Operation Operation
	RequestID [16]byte
	StoreID   [16]byte
}

type Reply struct {
	operation Operation
	outcome   Outcome
	request   [16]byte
	store     [16]byte
	version   uint64
	state     appstoreanchorstate.State
	hasState  bool
	checked   bool
}

var ErrInvalid = errors.New("invalid application-store signed anchor reply")

// Verify checks only the supplied key, expected correlation and reply encoding.
func Verify(raw []byte, publicKey ed25519.PublicKey, expected Expected) (Reply, error) {
	if len(raw) != Size || len(publicKey) != ed25519.PublicKeySize || zero(publicKey) || expected.Operation < Read || expected.Operation > CAS || expected.RequestID == ([16]byte{}) || expected.StoreID == ([16]byte{}) {
		return Reply{}, ErrInvalid
	}
	var message [Size]byte
	var key [ed25519.PublicKeySize]byte
	copy(message[:], raw)
	copy(key[:], publicKey)
	b := message[:]
	if !ed25519.Verify(ed25519.PublicKey(key[:]), b[:288], b[288:352]) {
		return Reply{}, ErrInvalid
	}
	if string(b[:8]) != "SSASRSP1" || Operation(b[8]) != expected.Operation || !zero(b[10:16]) || !zero(b[58:64]) || [16]byte(b[16:32]) != expected.RequestID || [16]byte(b[32:48]) != expected.StoreID {
		return Reply{}, ErrInvalid
	}
	outcome := Outcome(b[9])
	allowed := outcome == Rejected || outcome == Unknown
	if expected.Operation == Read {
		allowed = allowed || outcome == ReadState || outcome == NotFound
	} else {
		allowed = allowed || outcome == Committed || outcome == Conflict
	}
	if !allowed {
		return Reply{}, ErrInvalid
	}
	version := binary.BigEndian.Uint64(b[48:56])
	length := binary.BigEndian.Uint16(b[56:58])
	hasState := outcome == ReadState || outcome == Committed || outcome == Conflict
	var state appstoreanchorstate.State
	if hasState {
		if length != appstoreanchorstate.Size {
			return Reply{}, ErrInvalid
		}
		var err error
		state, err = appstoreanchorstate.Parse(b[64:256], expected.StoreID)
		if err != nil || state.Hash() != [32]byte(b[256:288]) {
			return Reply{}, ErrInvalid
		}
	} else if length != 0 || !zero(b[64:288]) {
		return Reply{}, ErrInvalid
	}
	if outcome == NotFound && version != 0 {
		return Reply{}, ErrInvalid
	}
	if expected.Operation == CreateIfAbsent && outcome == Committed {
		genesis, err := appstoreanchorstate.Genesis(expected.StoreID)
		if err != nil || state != genesis || version != 0 {
			return Reply{}, ErrInvalid
		}
	}
	if expected.Operation == CAS && outcome == Committed && version == 0 {
		return Reply{}, ErrInvalid
	}
	return Reply{operation: expected.Operation, outcome: outcome, request: expected.RequestID, store: expected.StoreID, version: version, state: state, hasState: hasState, checked: true}, nil
}

func zero(value []byte) bool {
	var bits byte
	for _, b := range value {
		bits |= b
	}
	return bits == 0
}

func (r Reply) SignatureValid() bool                     { return r.checked }
func (r Reply) Operation() Operation                     { return r.operation }
func (r Reply) Outcome() Outcome                         { return r.outcome }
func (r Reply) RequestID() [16]byte                      { return r.request }
func (r Reply) StoreID() [16]byte                        { return r.store }
func (r Reply) ServiceVersion() uint64                   { return r.version }
func (r Reply) State() (appstoreanchorstate.State, bool) { return r.state, r.hasState }
