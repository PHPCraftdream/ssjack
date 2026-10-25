package keyfile

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ktav-lang/golang/pure"
)

func TestOpaqueMaximumPayloadAndOuterMetadata(t *testing.T) {
	plaintext := bytes.Repeat([]byte{0xff}, MaxPlaintext)
	encoded, err := seal(plaintext, []byte("secret"), testDerive)
	if err != nil {
		t.Fatal(err)
	}
	value, err := pure.LoadsStrict(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 1 || root["data"] == nil {
		t.Fatal("outer container has readable profile fields")
	}
	for _, text := range []string{"argon2id-", "aes-", "memory_kib:", "version:", "purpose:", "cipher:"} {
		if bytes.Contains(encoded, []byte(text)) {
			t.Fatalf("outer metadata contains %q", text)
		}
	}
	opened, err := open(encoded, []byte("secret"), testDerive)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("maximum payload: %v", err)
	}
	defer clear(opened)
	if version, err := Format(encoded); err != nil || version != 2 {
		t.Fatalf("format: %d %v", version, err)
	}
}

func TestOpaqueInvalidPacketsRejectBeforeKDF(t *testing.T) {
	never := func(_, _ []byte) []byte { t.Fatal("invalid packet reached KDF"); return nil }
	packet := make([]byte, packetPrefix+Layers*tagSize+1)
	for i := range 4 {
		packet[i*saltSize] = byte(i + 1)
	}
	outer := func(data string) []byte {
		body, err := pure.EmitCanonical(opaqueDocument{Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return []byte(body)
	}
	duplicate := append([]byte(nil), packet...)
	copy(duplicate[saltSize:2*saltSize], duplicate[:saltSize])
	for _, bad := range [][]byte{
		[]byte("data: true\n"), []byte("data: not-base64\n"),
		outer(base64.StdEncoding.EncodeToString(packet[:packetPrefix+Layers*tagSize])),
		outer(base64.StdEncoding.EncodeToString(duplicate)),
		outer(base64.StdEncoding.EncodeToString(make([]byte, packetPrefix+maxEnvelope+Layers*tagSize+1))),
		outer(base64.StdEncoding.EncodeToString(packet) + "\n"),
		append(outer(base64.StdEncoding.EncodeToString(packet)), []byte("\nunknown: true\n")...),
		append(outer(base64.StdEncoding.EncodeToString(packet)), []byte("\ndata: duplicate\n")...),
		[]byte("data: " + strings.Repeat("A", MaxSize)),
	} {
		if _, err := open(bad, []byte("secret"), never); err == nil {
			t.Fatal("invalid opaque packet accepted")
		}
	}
}

func TestOpaquePublicBytesAndFormatAreAuthenticated(t *testing.T) {
	encoded, err := seal([]byte("payload"), []byte("secret"), testDerive)
	if err != nil {
		t.Fatal(err)
	}
	d, ciphertext, err := decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		changed := d
		changed.Salts = append([]string(nil), d.Salts...)
		if i < 4 {
			salt, _ := decodeFixed(d.Salts[i], saltSize)
			salt[0] ^= 128
			changed.Salts[i] = base64.StdEncoding.EncodeToString(salt)
		} else {
			nonce, _ := decodeFixed(d.Nonce, nonceSize)
			nonce[0] ^= 128
			changed.Nonce = base64.StdEncoding.EncodeToString(nonce)
		}
		bad, err := encode(changed, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := open(bad, []byte("secret"), testDerive); err == nil {
			t.Fatal("changed bootstrap byte authenticated")
		}
	}
	// A v2 ciphertext relabeled with a valid v1 header must not decrypt.
	d.Version = 1
	bad, err := encode(d, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(bad, []byte("secret"), testDerive); err == nil {
		t.Fatal("cross-format ciphertext accepted")
	}
	legacy, err := sealLegacy(t, []byte("legacy"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := open(legacy, []byte("secret"), testDerive)
	if err != nil || string(opened) != "legacy" {
		t.Fatalf("v1 compatibility: %v", err)
	}
	d, ciphertext, err = decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	d.Version = 2
	bad, err = encode(d, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(bad, []byte("secret"), testDerive); err == nil {
		t.Fatal("v1 ciphertext accepted in v2 envelope")
	}
}

func TestOpaqueAuthenticatedInnerProfileIsStrict(t *testing.T) {
	d, err := newOpaqueDocument()
	if err != nil {
		t.Fatal(err)
	}
	header, salts, nonce, err := d.header()
	if err != nil {
		t.Fatal(err)
	}
	master, err := masterKey([]byte("secret"), salts, testDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	valid, err := wrapPayload(d, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope innerEnvelope
	if err := pure.LoadsInto(string(valid), &envelope); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*innerEnvelope){
		func(e *innerEnvelope) { e.Version = 1 },
		func(e *innerEnvelope) { e.KDF = "unknown" },
		func(e *innerEnvelope) { e.MemoryKiB-- },
		func(e *innerEnvelope) { e.Passes++ },
		func(e *innerEnvelope) { e.Parallelism++ },
		func(e *innerEnvelope) { e.Layers-- },
		func(e *innerEnvelope) { e.Cipher = "unknown" },
		func(e *innerEnvelope) { e.Purpose = "keygen" },
		func(e *innerEnvelope) { e.Payload = "" },
		func(e *innerEnvelope) { e.Payload = "!" },
		func(e *innerEnvelope) { e.Payload = base64.StdEncoding.EncodeToString(make([]byte, MaxPlaintext+1)) },
	}
	var bodies [][]byte
	for _, mutate := range mutations {
		changed := envelope
		mutate(&changed)
		body, err := pure.EmitCanonical(changed)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, []byte(body))
	}
	bodies = append(bodies, append(append([]byte(nil), valid...), []byte("\nunknown: true\n")...))
	for _, body := range bodies {
		ciphertext, err := encryptLayers(body, master, nonce, header, "storage")
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encode(d, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := open(encoded, []byte("secret"), testDerive); err == nil {
			t.Fatal("authenticated but unsupported inner profile accepted")
		}
	}
}
