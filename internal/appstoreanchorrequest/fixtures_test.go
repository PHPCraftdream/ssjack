package appstoreanchorrequest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func id(value byte) [16]byte   { return [16]byte(bytes.Repeat([]byte{value}, 16)) }
func hash(value byte) [32]byte { return [32]byte(bytes.Repeat([]byte{value}, 32)) }

func sum(domain string, parts ...[]byte) [32]byte {
	b := []byte(domain)
	for _, part := range parts {
		b = append(b, part...)
	}
	return sha256.Sum256(b)
}

func genesisWire() []byte {
	b := make([]byte, 192)
	copy(b[:4], "SSAS")
	binary.BigEndian.PutUint16(b[4:6], 1)
	store := id(1)
	copy(b[8:24], store[:])
	head := sum("SSAPP-JOURNAL-GENESIS-v1", store[:])
	copy(b[104:136], head[:])
	return b
}

func state(t *testing.T, b []byte) appstoreanchorstate.State {
	t.Helper()
	s, err := appstoreanchorstate.Parse(b, id(1))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func entry(t *testing.T, index uint64, snapshot, transaction byte) appstorejournal.Entry {
	t.Helper()
	b := binary.BigEndian.AppendUint64(nil, index)
	b = append(b, bytes.Repeat([]byte{snapshot}, 16)...)
	b = append(b, bytes.Repeat([]byte{transaction}, 16)...)
	e, err := appstorejournal.ParseEntry(b, index)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func common(operation byte, request [16]byte) []byte {
	b := append([]byte("SSASREQ1"), operation, 0, 0, 0, 0, 0, 0, 0)
	b = append(b, bytes.Repeat([]byte{1}, 16)...)
	return append(b, request[:]...)
}

func requestID(domain string, key [32]byte) [16]byte {
	store := id(1)
	h := sum(domain, store[:], key[:])
	return [16]byte(h[:16])
}

func mutationWire(operation byte, domain string, newState []byte, expected, key [32]byte) []byte {
	b := common(operation, requestID(domain, key))
	if operation == 3 {
		b = append(b, expected[:]...)
	}
	b = append(b, newState...)
	return append(b, key[:]...)
}
