package appstoreanchorreply_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
)

func id(value byte) [16]byte { return [16]byte(bytes.Repeat([]byte{value}, 16)) }

func key() (ed25519.PublicKey, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	return private.Public().(ed25519.PublicKey), private
}

func stateWire(committed bool) []byte {
	b := make([]byte, 192)
	copy(b[:4], "SSAS")
	binary.BigEndian.PutUint16(b[4:6], 1)
	copy(b[8:24], bytes.Repeat([]byte{2}, 16))
	s := id(2)
	head := sha256.Sum256(append([]byte("SSAPP-JOURNAL-GENESIS-v1"), s[:]...))
	copy(b[104:136], head[:])
	if committed {
		binary.BigEndian.PutUint64(b[24:32], 1)
		copy(b[32:48], bytes.Repeat([]byte{3}, 16))
		copy(b[48:80], bytes.Repeat([]byte{4}, 32))
		copy(b[80:96], bytes.Repeat([]byte{5}, 16))
		binary.BigEndian.PutUint64(b[96:104], 1)
		copy(b[104:136], bytes.Repeat([]byte{6}, 32))
	}
	return b
}

func sign(b []byte) {
	_, private := key()
	copy(b[288:352], ed25519.Sign(private, b[:288]))
}

func updateStateHash(b []byte) {
	h := sha256.Sum256(append([]byte("SSAPP-ANCHOR-STATE-v1"), b[64:256]...))
	copy(b[256:288], h[:])
}

func wire(op appstoreanchorreply.Operation, outcome appstoreanchorreply.Outcome, state []byte, version uint64) ([]byte, ed25519.PublicKey, appstoreanchorreply.Expected) {
	b := make([]byte, 352)
	copy(b[:8], "SSASRSP1")
	b[8], b[9] = byte(op), byte(outcome)
	copy(b[16:32], bytes.Repeat([]byte{1}, 16))
	copy(b[32:48], bytes.Repeat([]byte{2}, 16))
	binary.BigEndian.PutUint64(b[48:56], version)
	binary.BigEndian.PutUint16(b[56:58], uint16(len(state)))
	if len(state) != 0 {
		copy(b[64:256], state)
		updateStateHash(b)
	}
	sign(b)
	public, _ := key()
	return b, public, appstoreanchorreply.Expected{Operation: op, RequestID: id(1), StoreID: id(2)}
}
