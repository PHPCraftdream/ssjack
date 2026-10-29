package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

func recordHeader(t *testing.T, total uint64) appstoreheader.Header {
	t.Helper()
	b := header(t).Bytes()
	binary.BigEndian.PutUint64(b[64:72], total)
	binary.BigEndian.PutUint32(b[72:76], uint32((total+1048575)/1048576))
	h, err := appstoreheader.Parse(b[:])
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func finalRecord(h appstoreheader.Header) []byte {
	b := append([]byte("FIN1"), make([]byte, 44)...)
	binary.BigEndian.PutUint64(b[4:12], h.PlaintextSize())
	binary.BigEndian.PutUint32(b[12:16], h.ChunkCount())
	copy(b[16:48], bytes.Repeat([]byte{0x77}, 32))
	return b
}

func oracleLayer(t *testing.T, master [32]byte, h appstoreheader.Header, index uint32, layer int, final bool, plain int) (cipher.AEAD, []byte, []byte) {
	t.Helper()
	keyPrefix, noncePrefix, label := "ssjack-appstore/v1/data/chunk/", "ssjack-appstore/v1/nonce", "SSAPP chunk layer"
	if final {
		keyPrefix, noncePrefix, label = "ssjack-appstore/v1/data/final/", "ssjack-appstore/v1/nonce/final", "SSAPP final layer"
	}
	store, snapshot, base := h.StoreID(), h.SnapshotID(), h.NonceBase()
	contextBytes := append([]byte(keyPrefix), store[:]...)
	contextBytes = append(contextBytes, snapshot[:]...)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, index)
	contextBytes = binary.BigEndian.AppendUint32(contextBytes, uint32(layer))
	key := hkdfOracle(master[:], string(contextBytes))
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(noncePrefix), store[:]...)
	message = append(message, snapshot[:]...)
	message = binary.BigEndian.AppendUint32(message, index)
	message = binary.BigEndian.AppendUint32(message, uint32(layer))
	mac := hmac.New(sha256.New, base[:])
	_, _ = mac.Write(message)
	nonce := append([]byte(nil), mac.Sum(nil)[:12]...)
	raw := h.Bytes()
	aad := append(append([]byte(nil), raw[:208]...), base[:]...)
	for _, value := range []uint32{index, uint32(layer), uint32(plain), uint32(plain + 16000)} {
		aad = binary.BigEndian.AppendUint32(aad, value)
	}
	aad = append(aad, label...)
	return aead, nonce, aad
}

func oracleOpen(t *testing.T, master [32]byte, h appstoreheader.Header, index uint32, final bool, plain, last int, input []byte) []byte {
	t.Helper()
	data := append([]byte(nil), input...)
	for layer := 999; layer >= last; layer-- {
		aead, nonce, aad := oracleLayer(t, master, h, index, layer, final, plain)
		opened, err := aead.Open(data[:0], nonce, data, aad)
		if err != nil {
			t.Fatalf("independent layer %d: %v", layer, err)
		}
		clear(data[len(opened):])
		data = opened
	}
	return data
}

func oracleSeal(t *testing.T, master [32]byte, h appstoreheader.Header, index uint32, final bool, plain, first int, input []byte) []byte {
	t.Helper()
	data := make([]byte, len(input), plain+16000)
	copy(data, input)
	for layer := first; layer < 1000; layer++ {
		aead, nonce, aad := oracleLayer(t, master, h, index, layer, final, plain)
		data = aead.Seal(data[:0], nonce, data, aad)
	}
	return data
}

func TestExact1000LayersAndIndependentOracle(t *testing.T) {
	for _, row := range []struct {
		total uint64
		index uint32
		final bool
		size  int
	}{
		{2097152, 0, false, 1048576}, {1048579, 1, false, 3}, {1048576, ^uint32(0), true, 48},
	} {
		h := recordHeader(t, row.total)
		m, err := derive(context.Background(), h, []byte("synthetic layered-record fixture"), fake)
		if err != nil {
			t.Fatal(err)
		}
		plain := bytes.Repeat([]byte{0x42}, row.size)
		if row.final {
			plain = finalRecord(h)
		}
		before := append([]byte(nil), plain...)
		calls := 0
		sealed, err := m.transformRecord(context.Background(), h, row.index, row.final, plain, true, func(layer uint32) {
			if layer != uint32(calls) {
				t.Error("encryption layer order")
			}
			calls++
		})
		if err != nil || calls != 1000 || len(sealed) != len(plain)+16000 || !bytes.Equal(plain, before) {
			t.Fatalf("exact layered encryption: %v", err)
		}
		independent := oracleOpen(t, m.state.key, h, row.index, row.final, len(plain), 0, sealed)
		if !bytes.Equal(independent, plain) {
			t.Fatal("independent all-layer opening differs")
		}
		clear(independent)
		copyCipher := append([]byte(nil), sealed...)
		calls = 0
		opened, err := m.transformRecord(context.Background(), h, row.index, row.final, sealed, false, func(layer uint32) {
			if layer != uint32(999-calls) {
				t.Error("opening layer order")
			}
			calls++
		})
		if err != nil || calls != 1000 || !bytes.Equal(opened, plain) || !bytes.Equal(sealed, copyCipher) || !bytes.Equal(opened[len(opened):cap(opened)], make([]byte, cap(opened)-len(opened))) {
			t.Fatalf("all tags/input/tail: %v", err)
		}
		if !row.final && row.index == 0 {
			wrong, err := m.openRecord(context.Background(), h, 1, false, sealed)
			if !errors.Is(err, ErrAuthentication) || wrong != nil {
				t.Fatal("index binding was not authenticated")
			}
		}
		clear(opened)
		clear(sealed)
		clear(copyCipher)
		m.Close()
	}
}

func TestInnerTagAndHeaderBinding(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic inner-tag fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	plain := finalRecord(h)
	sealed, err := m.sealRecord(context.Background(), h, ^uint32(0), true, plain)
	if err != nil {
		t.Fatal(err)
	}
	wrongMaster, err := derive(context.Background(), h, []byte("different synthetic passphrase"), fake)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := wrongMaster.openRecord(context.Background(), h, ^uint32(0), true, sealed)
	wrongMaster.Close()
	if !errors.Is(err, ErrAuthentication) || wrong != nil {
		t.Fatal("different passphrase master authenticated a record")
	}
	inner := oracleOpen(t, m.state.key, h, ^uint32(0), true, 48, 1, sealed)
	inner[len(inner)-1] ^= 1
	wrapped := oracleSeal(t, m.state.key, h, ^uint32(0), true, 48, 1, inner)
	opened, err := m.openRecord(context.Background(), h, ^uint32(0), true, wrapped)
	if !errors.Is(err, ErrAuthentication) || opened != nil {
		t.Fatal("invalid inner tag survived valid outer layers")
	}
	for _, offset := range []int{28, 208} {
		raw := h.Bytes()
		raw[offset] ^= 0x80
		changed, err := appstoreheader.Parse(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		opened, err := m.openRecord(context.Background(), changed, ^uint32(0), true, sealed)
		if !errors.Is(err, ErrAuthentication) || opened != nil {
			t.Fatal("snapshot/nonce binding missing")
		}
	}
	badFinal := append([]byte(nil), plain...)
	badFinal[0] = 'X'
	validTags := oracleSeal(t, m.state.key, h, ^uint32(0), true, 48, 0, badFinal)
	opened, err = m.openRecord(context.Background(), h, ^uint32(0), true, validTags)
	if !errors.Is(err, ErrRecord) || opened != nil {
		t.Fatal("authenticated malformed final framing admitted")
	}
	clear(inner)
	clear(wrapped)
	clear(validTags)
	clear(sealed)
}

func snapshotWire(t *testing.T, m *Master, h appstoreheader.Header, badCatalog, badTranscript bool) ([]byte, ExpectedSnapshot) {
	t.Helper()
	if h.PlaintextSize() != 1048579 || h.ChunkCount() != 2 {
		t.Fatal("snapshot fixture expects catalog plus three bytes")
	}
	catalog := make([]byte, 1048576)
	defer clear(catalog)
	copy(catalog[:8], "SSCAT001")
	store, snapshot := h.StoreID(), h.SnapshotID()
	copy(catalog[8:24], store[:])
	copy(catalog[24:40], snapshot[:])
	binary.BigEndian.PutUint32(catalog[40:44], 1)
	copy(catalog[44:60], bytes.Repeat([]byte{3}, 16))
	copy(catalog[60:76], bytes.Repeat([]byte{4}, 16))
	binary.BigEndian.PutUint64(catalog[76:84], 3)
	copy(catalog[92:108], "bin")
	if badCatalog {
		binary.BigEndian.PutUint64(catalog[76:84], 4)
	}
	header := h.Bytes()
	wire := append([]byte(nil), header[:]...)
	for index, plain := range [][]byte{catalog, []byte("abc")} {
		ciphertext, err := m.sealRecord(context.Background(), h, uint32(index), false, plain)
		if err != nil {
			t.Fatal(err)
		}
		wire = binary.BigEndian.AppendUint32(wire, uint32(index))
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(plain)))
		wire = binary.BigEndian.AppendUint32(wire, uint32(len(ciphertext)))
		wire = append(wire, ciphertext...)
		clear(ciphertext)
	}
	transcript := sha256.Sum256(wire[220:])
	final := finalRecord(h)
	copy(final[16:48], transcript[:])
	if badTranscript {
		final[16] ^= 1
	}
	ciphertext, err := m.sealRecord(context.Background(), h, ^uint32(0), true, final)
	clear(final)
	if err != nil {
		t.Fatal(err)
	}
	wire = append(wire, "FIN1"...)
	wire = binary.BigEndian.AppendUint64(wire, 16048)
	wire = append(wire, ciphertext...)
	clear(ciphertext)
	return wire, ExpectedSnapshot{StoreID: store, SnapshotID: snapshot, EncodedHash: sha256.Sum256(wire)}
}
