package enrollmentauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func signedFixture(t *testing.T) ([]byte, TrustRoot) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(pub)
	root, err := NewTrustRoot(pub, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"fixture":true}`)
	message := append([]byte("ssjack-enrollment-signature-v1\x00"), manifest...)
	sig := ed25519.Sign(priv, message)
	e := envelope{Format: Format, KeyID: root.keyID, Manifest: base64.RawURLEncoding.EncodeToString(manifest), Signature: base64.RawURLEncoding.EncodeToString(sig)}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return data, root
}

func TestVerifyDetachedSnapshot(t *testing.T) {
	data, root := signedFixture(t)
	originalPublic := append([]byte(nil), root.key...)
	inputKey := append([]byte(nil), originalPublic...)
	fingerprint := sha256.Sum256(inputKey)
	pinned, err := NewTrustRoot(inputKey, hex.EncodeToString(fingerprint[:]))
	if err != nil {
		t.Fatal(err)
	}
	inputKey[0] ^= 0xff
	got, err := Verify(data, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Manifest()) != `{"fixture":true}` {
		t.Fatal("manifest mismatch")
	}
	copy := got.Manifest()
	copy[0] ^= 0xff
	if string(got.Manifest()) != `{"fixture":true}` {
		t.Fatal("snapshot exposed mutable storage")
	}
	expected := sha256.Sum256(append([]byte("ssjack-enrollment-v1\x00"), []byte(`{"fixture":true}`)...))
	if got.Digest() != hex.EncodeToString(expected[:]) {
		t.Fatal("incorrect enrollment-domain digest")
	}
	if string(originalPublic) != string(pinned.key) {
		t.Fatal("trust root exposed mutable key storage")
	}
}

func TestValidSignatureCannotCrossDomain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(pub)
	root, err := NewTrustRoot(pub, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"fixture":true}`)
	wrongDomain := append([]byte("other-enrollment-signature-v1\x00"), manifest...)
	sig := ed25519.Sign(priv, wrongDomain)
	input, _ := json.Marshal(envelope{Format: Format, KeyID: root.keyID, Manifest: base64.RawURLEncoding.EncodeToString(manifest), Signature: base64.RawURLEncoding.EncodeToString(sig)})
	if _, err := Verify(input, root); err == nil {
		t.Fatal("accepted signature under wrong domain")
	}
}

func TestVerifyRejectsAdversarialEnvelopes(t *testing.T) {
	data, root := signedFixture(t)
	manifestMutation := strings.Replace(string(data), `eyJmaXh0dXJlIjp0cnVlfQ`, `eyJmaXh0dXJlIjp0cnVlfA`, 1)
	sigMutation := strings.Replace(string(data), `"signature":"`, `"signature":"A`, 1)
	if sigMutation != string(data) {
		sigMutation = strings.Replace(sigMutation, `"signature":"A`, `"signature":"B`, 1)
	}
	wrongKeyID := strings.Replace(string(data), root.keyID, strings.Repeat("0", 64), 1)
	fieldOrder := strings.Replace(string(data), `{"format":"`+Format+`","key_id":"`+root.keyID+`"`, `{"key_id":"`+root.keyID+`","format":"`+Format+`"`, 1)
	missingField := strings.Replace(string(data), `,"key_id":"`+root.keyID+`"`, "", 1)
	nullField := strings.Replace(string(data), `"manifest":"`, `"manifest":null`, 1)
	tests := map[string][]byte{
		"manifest mutation with valid signature length": []byte(manifestMutation),
		"signature byte mutation preserving encoded length": []byte(func() string {
			raw, _ := json.Marshal(envelope{Format: Format, KeyID: root.keyID, Manifest: base64.RawURLEncoding.EncodeToString([]byte(`{"fixture":true}`)), Signature: strings.Repeat("A", 86)})
			return string(raw)
		}()),
		"wrong key id":                []byte(wrongKeyID),
		"field reorder":               []byte(fieldOrder),
		"missing field":               []byte(missingField),
		"null field":                  []byte(nullField),
		"tampered signature":          []byte(sigMutation),
		"duplicate key":               []byte(strings.Replace(string(data), `{"format":`, `{"format":"wrong","format":`, 1)),
		"trailing data":               append(append([]byte(nil), data...), []byte(` {}`)...),
		"noncanonical whitespace":     append([]byte(" "), data...),
		"strict base64 trailing bits": []byte(strings.Replace(string(data), base64.RawURLEncoding.EncodeToString([]byte(`{"fixture":true}`)), "eyJmaXh0dXJlIjp0cnVlfR", 1)),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(input, root); err == nil {
				t.Fatal("accepted adversarial input")
			}
		})
	}
}

func TestOperatorRootRejectsMismatchedSigner(t *testing.T) {
	data, root := signedFixture(t)
	pub := append([]byte(nil), root.key...)
	if _, err := NewTrustRoot(pub, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted mismatched fingerprint")
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(otherPub)
	other, err := NewTrustRoot(otherPub, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, other); err == nil {
		t.Fatal("accepted envelope signed by a different key")
	}
	if _, err := Verify(data, TrustRoot{}); err == nil {
		t.Fatal("accepted missing trust root")
	}
}

func TestSubstitutedSelfFingerprintedKeyVerifies(t *testing.T) {
	// A self-consistent fingerprint proves key identity, not provenance. Callers
	// must independently obtain the intended root through a trusted channel.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(pub)
	root, err := NewTrustRoot(pub, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"substituted":true}`)
	message := append([]byte("ssjack-enrollment-signature-v1\x00"), manifest...)
	sig := ed25519.Sign(priv, message)
	data, err := json.Marshal(envelope{Format: Format, KeyID: root.keyID, Manifest: base64.RawURLEncoding.EncodeToString(manifest), Signature: base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(data, root); err != nil {
		t.Fatalf("self-fingerprinted substituted key should verify when supplied as root: %v", err)
	}
}

func TestStrictBase64AndBounds(t *testing.T) {
	data, root := signedFixture(t)
	if _, err := Verify(data[:len(data)-1], root); err == nil {
		t.Fatal("accepted truncated envelope")
	}
	if _, err := Verify(make([]byte, MaxEnvelope+1), root); err == nil {
		t.Fatal("accepted oversized envelope")
	}
	if _, err := strictB64("a="); err == nil {
		t.Fatal("accepted padded base64url")
	}
	if _, err := NewTrustRoot([]byte{1}, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted malformed root")
	}
}
