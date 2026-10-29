package appstoreanchorreply_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
)

func TestResignedMalformedFields(t *testing.T) {
	original, public, expected := wire(appstoreanchorreply.Read, appstoreanchorreply.ReadState, stateWire(true), 2)
	for name, mutate := range map[string]func([]byte){
		"magic":                       func(b []byte) { b[0] = 'X' },
		"operation":                   func(b []byte) { b[8] = byte(appstoreanchorreply.CAS) },
		"request":                     func(b []byte) { b[31] ^= 1 },
		"store":                       func(b []byte) { b[47] ^= 1 },
		"state-length-zero":           func(b []byte) { binary.BigEndian.PutUint16(b[56:58], 0) },
		"state-length-short":          func(b []byte) { binary.BigEndian.PutUint16(b[56:58], 191) },
		"state-length-long":           func(b []byte) { binary.BigEndian.PutUint16(b[56:58], 193) },
		"state-length-max":            func(b []byte) { binary.BigEndian.PutUint16(b[56:58], 65535) },
		"state-hash":                  func(b []byte) { b[256] ^= 1 },
		"state-magic-correct-hash":    func(b []byte) { b[64] = 'X'; updateStateHash(b) },
		"state-scope-correct-hash":    func(b []byte) { copy(b[72:88], bytes.Repeat([]byte{3}, 16)); updateStateHash(b) },
		"state-reserved-correct-hash": func(b []byte) { b[200] = 1; updateStateHash(b) },
		"wrong-state-hash-domain": func(b []byte) {
			h := sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1\x00"), b[64:256]...))
			copy(b[256:288], h[:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), original...)
			mutate(b)
			sign(b)
			reject(t, b, public, expected)
		})
	}
	for _, offset := range []int{10, 11, 12, 13, 14, 15, 58, 59, 60, 61, 62, 63} {
		b := append([]byte(nil), original...)
		b[offset] = 1
		sign(b)
		reject(t, b, public, expected)
	}
}

func TestClosedOperationOutcomePairs(t *testing.T) {
	for _, pair := range [][2]byte{{1, 2}, {1, 3}, {2, 1}, {2, 6}, {3, 1}, {3, 6}} {
		var state []byte
		version := uint64(0)
		if pair[1] != 6 {
			state, version = stateWire(true), 2
		}
		b, public, expected := wire(appstoreanchorreply.Operation(pair[0]), appstoreanchorreply.Outcome(pair[1]), state, version)
		reject(t, b, public, expected)
	}
	for _, outcome := range []appstoreanchorreply.Outcome{0, 7, 255} {
		for _, operation := range []appstoreanchorreply.Operation{1, 2, 3} {
			b, public, expected := wire(operation, outcome, nil, 0)
			reject(t, b, public, expected)
		}
	}
}

func TestEmptySlotsAndCreationSemantics(t *testing.T) {
	for _, outcome := range []appstoreanchorreply.Outcome{appstoreanchorreply.Rejected, appstoreanchorreply.Unknown, appstoreanchorreply.NotFound} {
		for _, offset := range []int{64, 255, 256, 287} {
			b, public, expected := wire(appstoreanchorreply.Read, outcome, nil, 0)
			b[offset] = 1
			sign(b)
			reject(t, b, public, expected)
		}
		b, public, expected := wire(appstoreanchorreply.Read, outcome, nil, 0)
		binary.BigEndian.PutUint16(b[56:58], 192)
		sign(b)
		reject(t, b, public, expected)
	}
	b, public, expected := wire(appstoreanchorreply.Read, appstoreanchorreply.NotFound, nil, 1)
	reject(t, b, public, expected)
	b, public, expected = wire(appstoreanchorreply.CreateIfAbsent, appstoreanchorreply.Committed, stateWire(true), 0)
	reject(t, b, public, expected)
	b, public, expected = wire(appstoreanchorreply.CreateIfAbsent, appstoreanchorreply.Committed, stateWire(false), 1)
	reject(t, b, public, expected)
	b, public, expected = wire(appstoreanchorreply.CAS, appstoreanchorreply.Committed, stateWire(true), 0)
	reject(t, b, public, expected)
}
