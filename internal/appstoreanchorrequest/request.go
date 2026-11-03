// Package appstoreanchorrequest prepares bytes, never sends or authorizes mutations.
package appstoreanchorrequest

import (
	"crypto/sha256"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

type kind byte

const (
	readKind kind = iota + 1
	createKind
	reserveKind
	commitKind
)

var ErrInvalid = errors.New("invalid application-store anchor request plan")

type Request struct {
	raw   [304]byte
	size  int
	kind  kind
	state appstoreanchorstate.State
	entry appstorejournal.Entry
}

// NewRead requires a caller-generated fresh random ID; it does not generate or send it.
func NewRead(store, requestID [16]byte) (Request, error) {
	if store == ([16]byte{}) || requestID == ([16]byte{}) {
		return Request{}, ErrInvalid
	}
	return common(readKind, 1, 48, store, requestID), nil
}

func common(k kind, operation byte, size int, store, requestID [16]byte) Request {
	r := Request{kind: k, size: size}
	copy(r.raw[:8], "SSASREQ1")
	r.raw[8] = operation
	copy(r.raw[16:32], store[:])
	copy(r.raw[32:48], requestID[:])
	return r
}

func sum(domain string, parts ...[]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func mutation(k kind, next appstoreanchorstate.State, expectedHash, key [32]byte, requestDomain string) (Request, error) {
	if !next.Valid() || key == ([32]byte{}) {
		return Request{}, ErrInvalid
	}
	store := next.StoreID()
	requestDigest := sum(requestDomain, store[:], key[:])
	requestID := [16]byte(requestDigest[:16])
	if requestID == ([16]byte{}) {
		return Request{}, ErrInvalid
	}
	operation, size, offset := byte(3), 304, 80
	if k == createKind {
		operation, size, offset = 2, 272, 48
	} else if expectedHash == ([32]byte{}) || (k != reserveKind && k != commitKind) {
		return Request{}, ErrInvalid
	}
	r := common(k, operation, size, store, requestID)
	if operation == 3 {
		copy(r.raw[48:80], expectedHash[:])
	}
	stateBytes := next.Bytes()
	copy(r.raw[offset:offset+192], stateBytes[:])
	copy(r.raw[size-32:size], key[:])
	r.state = next
	return r, nil
}

// Valid describes a byte plan, not enrollment, durable intent or permission to encrypt.
func (r Request) Valid() bool         { return r.kind >= readKind && r.kind <= commitKind }
func (r Request) Operation() byte     { return r.raw[8] }
func (r Request) StoreID() [16]byte   { return [16]byte(r.raw[16:32]) }
func (r Request) RequestID() [16]byte { return [16]byte(r.raw[32:48]) }
func (r Request) Bytes() []byte {
	if !r.Valid() {
		return nil
	}
	return append([]byte(nil), r.raw[:r.size]...)
}
func (r Request) ProposedState() (appstoreanchorstate.State, bool) {
	return r.state, r.Valid() && r.kind != readKind
}
func (r Request) IdempotencyKey() ([32]byte, bool) {
	if !r.Valid() || r.kind == readKind {
		return [32]byte{}, false
	}
	return [32]byte(r.raw[r.size-32 : r.size]), true
}
func (r Request) ExpectedStateHash() ([32]byte, bool) {
	if r.kind != reserveKind && r.kind != commitKind {
		return [32]byte{}, false
	}
	return [32]byte(r.raw[48:80]), true
}
