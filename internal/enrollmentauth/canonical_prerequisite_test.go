package enrollmentauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func signedBytes(t *testing.T, manifest, signed []byte) ([]byte, TrustRoot) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	root, err := NewTrustRoot(pub, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("ssjack-enrollment-signature-v1\x00"), signed...)
	e := envelope{Format: Format, KeyID: root.keyID, Manifest: base64.RawURLEncoding.EncodeToString(manifest), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return data, root
}

func TestCanonicalPrerequisiteSignedBytes(t *testing.T) {
	good := []byte(`{"a":1,"b":"é"}`)
	data, root := signedBytes(t, good, good)
	v, err := VerifyCanonicalBytes(data, root)
	if err != nil || string(v.Manifest()) != string(good) {
		t.Fatalf("canonical signed bytes: %v", err)
	}
	h := sha256.Sum256(append([]byte("ssjack-enrollment-v1\x00"), good...))
	if v.Digest() != hex.EncodeToString(h[:]) {
		t.Fatal("digest is not bound to signed bytes")
	}
	for _, altered := range [][]byte{[]byte(`{"a":2,"b":"é"}`), []byte(`{"a":1,"b":"e"}`)} {
		data, root := signedBytes(t, altered, good)
		if _, err := VerifyCanonicalBytes(data, root); err == nil {
			t.Fatal("accepted changed signed bytes")
		}
	}
}

func TestCanonicalPrerequisiteRejectsSignedNoncanonicalAndMalformed(t *testing.T) {
	cases := map[string][]byte{
		"whitespace":        []byte(`{ "a":1}`),
		"order":             []byte(`{"b":1,"a":2}`),
		"escaped string":    []byte(`{"a":"\u0061"}`),
		"negative zero":     []byte(`{"a":-0}`),
		"duplicate":         []byte(`{"a":1,"a":2}`),
		"escaped duplicate": []byte(`{"a":1,"\u0061":2}`),
		"trailing":          []byte(`{} {}`),
		"surrogate":         []byte(`{"a":"\ud800"}`),
		"float":             []byte(`{"a":1.0}`),
		"unsafe integer":    []byte(`{"a":9007199254740992}`),
		"invalid utf8":      {'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'},
	}
	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			data, root := signedBytes(t, manifest, manifest)
			if _, err := VerifyCanonicalBytes(data, root); err == nil {
				t.Fatal("accepted signed noncanonical or malformed bytes")
			}
		})
	}
}

func TestCanonicalPrerequisiteDoesNotValidateEnrollmentOrSchemas(t *testing.T) {
	// These canonical values contain missing fields or prohibited schema constructs.
	// Signature and canonicality alone must never be interpreted as conformance.
	for _, manifest := range []string{
		`{}`,
		`{"schemas":[{"document":{"$ref":"https://example.invalid/schema"}}]}`,
		`{"schemas":[{"document":{"additionalProperties":true,"type":"object"}}]}`,
		`{"schemas":[{"document":{"$schema":"wrong","type":"string"}}]}`,
	} {
		data, root := signedBytes(t, []byte(manifest), []byte(manifest))
		if _, err := VerifyCanonicalBytes(data, root); err != nil {
			t.Fatalf("byte prerequisite unexpectedly performed schema validation: %v", err)
		}
	}
}
