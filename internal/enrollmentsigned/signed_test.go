package enrollmentsigned

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/enrollmentauth"
	"github.com/PHPCraftdream/ssjack/internal/enrollmentvalidator"
	"github.com/PHPCraftdream/ssjack/internal/externalschemasubset"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	d := strings.Repeat("a", 64)
	doc := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "boolean"}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte("ssjack-schema-v1\x00"), b...))
	m := map[string]any{
		"artifact_digests": map[string]any{"artifact": d}, "dependency_digests": map[string]any{}, "aliases": []any{}, "capabilities": []any{"observe"}, "configuration_digest": d, "driver_id": "driver", "driver_protocol": 1, "enrollment_id": "AAAAAAAAAAAAAAAAAAAAAA", "effects": []any{map[string]any{"class": "read", "summary_id": "read", "decision": "delegated", "destructive": false}}, "environment": map[string]any{}, "resource_sinks": []any{},
		"executable": map[string]any{"path": "/driver", "sha256": d, "interpreter": map[string]any{"path": "/interp", "sha256": d}, "argv": []any{}}, "working_directory": map[string]any{"path": "/private", "device": "1", "file_id": "2"}, "os_identity": map[string]any{"platform": "posix", "uid": 1, "gid": 1, "groups": []any{}}, "principal": map[string]any{"issuer": "issuer", "subject": "subject"}, "provenance": map[string]any{"source": "source", "revision": "rev", "dependencies": []any{}},
		"limits": map[string]any{"process_slots": 1, "session_operations": 1, "global_operations": 1, "emergency_cancellations": 1, "storage_bytes": 1, "records": 1, "cancellation_reserve_bytes": 4096}, "network": map[string]any{"policy": "deny_all", "targets": []any{}, "policy_digest": d}, "schemas": []any{map[string]any{"id": "schema", "digest": hex.EncodeToString(h[:]), "document": doc}}, "kinds": []any{map[string]any{"name": "kind", "desired_schema_id": "schema", "projection_schema_id": "schema"}}, "targets": []any{map[string]any{"name": "target", "canonical_target": "remote"}},
	}
	b, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err = canonicaljson.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signed(t *testing.T, manifest []byte, key ed25519.PrivateKey, id string) []byte {
	t.Helper()
	sig := ed25519.Sign(key, append([]byte("ssjack-enrollment-signature-v1\x00"), manifest...))
	b, err := json.Marshal(struct {
		Format    string `json:"format"`
		KeyID     string `json:"key_id"`
		Manifest  string `json:"manifest"`
		Signature string `json:"signature"`
	}{enrollmentauth.Format, id, base64.RawURLEncoding.EncodeToString(manifest), base64.RawURLEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyComposition(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	id := hex.EncodeToString(h[:])
	root, err := enrollmentauth.NewTrustRoot(pub, id)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixture(t)
	envelope := signed(t, manifest, key, id)
	verified, err := Verify(envelope, root)
	if err != nil || !bytes.Equal(verified.Manifest(), manifest) {
		t.Fatalf("valid enrollment: %v", err)
	}
	digest := sha256.Sum256(append([]byte("ssjack-enrollment-v1\x00"), manifest...))
	if verified.Digest() != hex.EncodeToString(digest[:]) {
		t.Fatal("digest mismatch")
	}
	copyOfManifest := verified.Manifest()
	copyOfManifest[0] ^= 1
	if !bytes.Equal(verified.Manifest(), manifest) {
		t.Fatal("manifest not detached")
	}

	invalidRecord := bytes.Replace(manifest, []byte(`"driver_id":"driver"`), []byte(`"driver_id":"INVALID"`), 1)
	if bytes.Equal(invalidRecord, manifest) {
		t.Fatal("fixture mutation failed")
	}
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	cases := map[string]struct {
		data []byte
		root enrollmentauth.TrustRoot
	}{
		"invalid record":        {signed(t, invalidRecord, key, id), root},
		"canonical wrong shape": {signed(t, []byte(`{}`), key, id), root},
		"noncanonical":          {signed(t, append(append([]byte(nil), manifest...), ' '), key, id), root},
		"duplicate keys":        {signed(t, []byte(`{"a":1,"a":1}`), key, id), root},
		"bad signature":         {signed(t, manifest, otherKey, id), root},
		"missing root":          {envelope, enrollmentauth.TrustRoot{}},
		"malformed envelope":    {append(append([]byte(nil), envelope...), ' '), root},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Verify(tc.data, tc.root)
			if err == nil || len(got.Manifest()) != 0 || got.Digest() != "" {
				t.Fatalf("failure exposed result: %v", err)
			}
		})
	}
}

func TestSignedUnsupportedExternalSchema(t *testing.T) {
	manifest := fixture(t)
	if _, err := enrollmentvalidator.Validate(manifest); err != nil {
		t.Fatalf("baseline record: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(manifest, &record); err != nil {
		t.Fatal(err)
	}
	schema := record["schemas"].([]any)[0].(map[string]any)
	doc := schema["document"].(map[string]any)
	doc["unsupported_keyword"] = true
	rawDoc, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	canonicalDoc, err := canonicaljson.Canonicalize(rawDoc)
	if err != nil {
		t.Fatal(err)
	}
	if err := externalschemasubset.ValidateSchema(canonicalDoc); err == nil {
		t.Fatal("unsupported schema accepted")
	}
	h := sha256.Sum256(append([]byte("ssjack-schema-v1\x00"), canonicalDoc...))
	schema["digest"] = hex.EncodeToString(h[:])
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = canonicaljson.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(pub)
	id := hex.EncodeToString(fingerprint[:])
	root, err := enrollmentauth.NewTrustRoot(pub, id)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signed(t, manifest, key, id)
	if _, err := enrollmentauth.VerifyCanonicalBytes(envelope, root); err != nil {
		t.Fatalf("signature and canonical bytes: %v", err)
	}
	got, err := Verify(envelope, root)
	if err == nil || len(got.Manifest()) != 0 || got.Digest() != "" {
		t.Fatalf("unsupported signed schema exposed result: %v", err)
	}
}

func TestAttackerSelectedRootDoesNotEstablishProvenance(t *testing.T) {
	originalKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	originalPub := originalKey.Public().(ed25519.PublicKey)
	originalFingerprint := sha256.Sum256(originalPub)
	originalRoot, err := enrollmentauth.NewTrustRoot(originalPub, hex.EncodeToString(originalFingerprint[:]))
	if err != nil {
		t.Fatal(err)
	}
	attackerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	attackerPub := attackerKey.Public().(ed25519.PublicKey)
	attackerFingerprint := sha256.Sum256(attackerPub)
	attackerID := hex.EncodeToString(attackerFingerprint[:])
	attackerRoot, err := enrollmentauth.NewTrustRoot(attackerPub, attackerID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixture(t)
	envelope := signed(t, manifest, attackerKey, attackerID)
	got, err := Verify(envelope, originalRoot)
	if err == nil || len(got.Manifest()) != 0 || got.Digest() != "" {
		t.Fatalf("original root accepted attacker: %v", err)
	}
	got, err = Verify(envelope, attackerRoot)
	if err != nil || !bytes.Equal(got.Manifest(), manifest) {
		t.Fatalf("attacker-selected root: %v", err)
	}
}
