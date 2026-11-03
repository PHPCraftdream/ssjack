// Package appstoreanchorcore models anchor DTOs and transitions, not transport authentication.
package appstoreanchorcore

import (
	"crypto/sha256"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

var ErrInvalid = errors.New("invalid anchor service input")

type Kind byte

const (
	Read Kind = iota + 1
	Create
	Reserve
	Commit
)

type Request struct {
	raw      [304]byte
	size     int
	kind     Kind
	state    appstoreanchorstate.State
	expected [32]byte
	key      [32]byte
}

// Parse checks fixed wire scope and shape, not caller identity or journal semantics.
func Parse(raw []byte, store [16]byte) (Request, error) {
	if store == ([16]byte{}) || (len(raw) != 48 && len(raw) != 272 && len(raw) != 304) {
		return Request{}, ErrInvalid
	}
	var r Request
	copy(r.raw[:], raw)
	r.size = len(raw)
	b := r.raw[:r.size]
	if string(b[:8]) != "SSASREQ1" || !zero(b[9:16]) || [16]byte(b[16:32]) != store || zero(b[32:48]) {
		return Request{}, ErrInvalid
	}
	switch appstoreanchorreply.Operation(b[8]) {
	case appstoreanchorreply.Read:
		if len(b) != 48 {
			return Request{}, ErrInvalid
		}
		r.kind = Read
		return r, nil
	case appstoreanchorreply.CreateIfAbsent:
		if len(b) != 272 {
			return Request{}, ErrInvalid
		}
		state, err := appstoreanchorstate.Parse(b[48:240], store)
		genesis, _ := appstoreanchorstate.Genesis(store)
		if err != nil || state != genesis {
			return Request{}, ErrInvalid
		}
		r.key = [32]byte(b[240:272])
		r.state = state
		r.kind = Create
		want := sum("SSAPP-CREATE-v1", store[:], b[48:240])
		if r.key != want || r.RequestID() != requestID("SSAPP-CREATE-REQUEST-ID-v1", store, r.key) {
			return Request{}, ErrInvalid
		}
	case appstoreanchorreply.CAS:
		if len(b) != 304 || zero(b[48:80]) || zero(b[272:304]) {
			return Request{}, ErrInvalid
		}
		state, err := appstoreanchorstate.Parse(b[80:272], store)
		if err != nil {
			return Request{}, ErrInvalid
		}
		r.state = state
		r.expected = [32]byte(b[48:80])
		r.key = [32]byte(b[272:304])
		reserve := r.RequestID() == requestID("SSAPP-RESERVE-REQUEST-ID-v1", store, r.key)
		commit := r.RequestID() == requestID("SSAPP-COMMIT-REQUEST-ID-v1", store, r.key)
		if reserve == commit {
			return Request{}, ErrInvalid
		}
		r.kind = Reserve
		if commit {
			transaction := state.CommittedTransactionID()
			candidate := state.CommittedFileHash()
			if transaction == ([16]byte{}) || candidate == ([32]byte{}) || r.key != sum("SSAPP-COMMIT-v1", store[:], transaction[:], candidate[:]) {
				return Request{}, ErrInvalid
			}
			r.kind = Commit
		}
	default:
		return Request{}, ErrInvalid
	}
	if r.key == ([32]byte{}) {
		return Request{}, ErrInvalid
	}
	return r, nil
}

func sum(domain string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, p := range parts {
		h.Write(p)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
func requestID(domain string, store [16]byte, key [32]byte) [16]byte {
	h := sum(domain, store[:], key[:])
	return [16]byte(h[:16])
}
func zero(b []byte) bool {
	var value byte
	for _, v := range b {
		value |= v
	}
	return value == 0
}

func (r Request) Valid() bool { return r.kind >= Read && r.kind <= Commit }
func (r Request) Kind() Kind  { return r.kind }
func (r Request) Operation() appstoreanchorreply.Operation {
	return appstoreanchorreply.Operation(r.raw[8])
}
func (r Request) StoreID() [16]byte     { return [16]byte(r.raw[16:32]) }
func (r Request) RequestID() [16]byte   { return [16]byte(r.raw[32:48]) }
func (r Request) Bytes() []byte         { return append([]byte(nil), r.raw[:r.size]...) }
func (r Request) Key() ([32]byte, bool) { return r.key, r.Valid() && r.kind != Read }
