package enrollmentauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const Format = "ssjack-enrollment-signed-v1"
const MaxEnvelope = 131072

// TrustRoot holds a caller-supplied Ed25519 public key and its fingerprint.
// The caller must obtain the key through an independent trusted channel.
type TrustRoot struct {
	keyID string
	key   ed25519.PublicKey
}

// NewTrustRoot pins a caller-supplied Ed25519 public key to its fingerprint.
// Fingerprint matching does not establish where the key came from.
func NewTrustRoot(publicKey []byte, expectedFingerprint string) (TrustRoot, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return TrustRoot{}, errors.New("invalid operator public key")
	}
	h := sha256.Sum256(publicKey)
	fingerprint := hex.EncodeToString(h[:])
	if len(expectedFingerprint) != 64 || fingerprint != expectedFingerprint {
		return TrustRoot{}, errors.New("operator fingerprint mismatch")
	}
	return TrustRoot{keyID: fingerprint, key: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

// Verified is a detached immutable copy of signed bytes. It authorizes nothing.
type Verified struct {
	manifest []byte
	digest   string
}

func (v Verified) Manifest() []byte { return append([]byte(nil), v.manifest...) }
func (v Verified) Digest() string   { return v.digest }

// Verify checks a strict envelope and signature before exposing the manifest.
// Canonical JCS-SSJACK-1 parsing and enrollment validation remain separate prerequisites.
func Verify(data []byte, root TrustRoot) (Verified, error) {
	if len(data) == 0 || len(data) > MaxEnvelope || len(root.key) != ed25519.PublicKeySize || root.keyID == "" {
		return Verified{}, errors.New("invalid verification input")
	}
	fields, err := parseEnvelope(data)
	if err != nil {
		return Verified{}, err
	}
	if fields["format"] != `"`+Format+`"` || fields["key_id"] != `"`+root.keyID+`"` {
		return Verified{}, errors.New("unknown format or operator key")
	}
	manifestText, err := jsonString(fields["manifest"])
	if err != nil {
		return Verified{}, err
	}
	sigText, err := jsonString(fields["signature"])
	if err != nil {
		return Verified{}, err
	}
	manifest, err := strictB64(manifestText)
	if err != nil || len(manifest) == 0 {
		return Verified{}, errors.New("invalid manifest encoding")
	}
	sig, err := strictB64(sigText)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Verified{}, errors.New("invalid signature encoding")
	}
	message := append([]byte("ssjack-enrollment-signature-v1\x00"), manifest...)
	if !ed25519.Verify(root.key, message, sig) {
		return Verified{}, errors.New("signature verification failed")
	}
	h := sha256.Sum256(append([]byte("ssjack-enrollment-v1\x00"), manifest...))
	return Verified{append([]byte(nil), manifest...), hex.EncodeToString(h[:])}, nil
}

type envelope struct {
	Format    string `json:"format"`
	KeyID     string `json:"key_id"`
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

// parseEnvelope enforces no duplicate/unknown/missing keys and exact canonical JSON spacing/order.
func parseEnvelope(data []byte) (map[string]string, error) {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	var e envelope
	if err := d.Decode(&e); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing envelope data")
	}
	canonical, _ := json.Marshal(e)
	if string(canonical) != string(data) {
		return nil, errors.New("noncanonical or duplicate envelope fields")
	}
	return map[string]string{"format": string(mustJSON(e.Format)), "key_id": string(mustJSON(e.KeyID)), "manifest": string(mustJSON(e.Manifest)), "signature": string(mustJSON(e.Signature))}, nil
}
func mustJSON(v string) []byte { b, _ := json.Marshal(v); return b }
func jsonString(raw string) (string, error) {
	var s string
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return "", fmt.Errorf("invalid envelope string: %w", err)
	}
	return s, nil
}
func strictB64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errors.New("noncanonical base64url")
	}
	return b, nil
}
