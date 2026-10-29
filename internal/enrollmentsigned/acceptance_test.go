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
)

const acceptanceEnum = `{"$schema":"https://json-schema.org/draft/2020-12/schema","const":"ready","description":"state","enum":["ready","waiting"],"examples":["ready"],"title":"State"}`
const acceptanceObject = `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"state":{"const":"ready"}},"required":["state"]}`
const acceptanceString = `{"$schema":"https://json-schema.org/draft/2020-12/schema","enum":[null,"ready"],"maxLength":8,"minLength":1,"multipleOf":2,"type":["string","null"]}`

func acceptanceDigest(domain string, data []byte) string {
	h := sha256.Sum256(append([]byte(domain+"\x00"), data...))
	return hex.EncodeToString(h[:])
}

func acceptanceManifest(t *testing.T, schema string, pin bool, mutate func(map[string]any)) []byte {
	t.Helper()
	canonical, err := canonicaljson.Canonicalize([]byte(schema))
	if err != nil || !bytes.Equal(canonical, []byte(schema)) {
		t.Fatalf("schema literal is not canonical: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(fixture(t), &record); err != nil {
		t.Fatal(err)
	}
	entry := record["schemas"].([]any)[0].(map[string]any)
	var document map[string]any
	if err := json.Unmarshal([]byte(schema), &document); err != nil {
		t.Fatal(err)
	}
	entry["document"] = document
	if pin {
		entry["digest"] = acceptanceDigest("ssjack-schema-v1", []byte(schema))
	}
	if mutate != nil {
		mutate(record)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func acceptanceRoot(t *testing.T) (ed25519.PrivateKey, string, enrollmentauth.TrustRoot) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(pub)
	id := hex.EncodeToString(fingerprint[:])
	root, err := enrollmentauth.NewTrustRoot(pub, id)
	if err != nil {
		t.Fatal(err)
	}
	return key, id, root
}

func TestSignedDialectAcceptance(t *testing.T) {
	key, id, root := acceptanceRoot(t)
	for _, tc := range []struct{ name, schema string }{
		{"typeless_enum_const_annotations", acceptanceEnum},
		{"typeless_closed_object_nested_const", acceptanceObject},
		{"nullable_bounded_string_irrelevant_numeric", acceptanceString},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := acceptanceManifest(t, tc.schema, true, nil)
			got, err := Verify(signed(t, manifest, key, id), root)
			if err != nil || !bytes.Equal(got.Manifest(), manifest) || got.Digest() != acceptanceDigest("ssjack-enrollment-v1", manifest) {
				t.Fatalf("signed acceptance: bytes or digest mismatch: %v", err)
			}
		})
	}
}

func TestSignedDialectValidationFailures(t *testing.T) {
	key, id, root := acceptanceRoot(t)
	for _, tc := range []struct {
		name, schema string
		pin          bool
		mutate       func(map[string]any)
	}{
		{"malformed_irrelevant_multiple_of", `{"$schema":"https://json-schema.org/draft/2020-12/schema","maxLength":8,"multipleOf":0,"type":"string"}`, true, nil},
		{"unsupported_ref", `{"$ref":"other","$schema":"https://json-schema.org/draft/2020-12/schema","const":"ready"}`, true, nil},
		{"extra_schema_entry_field", acceptanceEnum, true, func(m map[string]any) { m["schemas"].([]any)[0].(map[string]any)["extra"] = true }},
		{"unresolved_desired_schema", acceptanceEnum, true, func(m map[string]any) { m["kinds"].([]any)[0].(map[string]any)["desired_schema_id"] = "missing" }},
		{"stale_schema_pin", acceptanceEnum, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := acceptanceManifest(t, tc.schema, tc.pin, tc.mutate)
			envelope := signed(t, manifest, key, id)
			authenticated, err := enrollmentauth.VerifyCanonicalBytes(envelope, root)
			if err != nil || !bytes.Equal(authenticated.Manifest(), manifest) || authenticated.Digest() != acceptanceDigest("ssjack-enrollment-v1", manifest) {
				t.Fatalf("authentication prerequisite: bytes or digest mismatch: %v", err)
			}
			got, err := Verify(envelope, root)
			if err == nil || !strings.HasPrefix(err.Error(), "validate signed enrollment: ") || len(got.Manifest()) != 0 || got.Digest() != "" {
				t.Fatalf("expected validation-stage rejection with zero result: %v", err)
			}
		})
	}
}

func TestSignedDialectExactByteSignatureBinding(t *testing.T) {
	key, id, root := acceptanceRoot(t)
	original := acceptanceManifest(t, acceptanceEnum, true, nil)
	replacement := acceptanceManifest(t, acceptanceObject, true, nil)
	if bytes.Equal(original, replacement) {
		t.Fatal("replacement must differ")
	}
	if _, err := Verify(signed(t, replacement, key, id), root); err != nil {
		t.Fatalf("replacement must itself be valid: %v", err)
	}
	envelope := signed(t, original, key, id)
	old := base64.RawURLEncoding.EncodeToString(original)
	changed := bytes.Replace(envelope, []byte(old), []byte(base64.RawURLEncoding.EncodeToString(replacement)), 1)
	if bytes.Equal(changed, envelope) {
		t.Fatal("envelope substitution failed")
	}
	got, err := Verify(changed, root)
	if err == nil || !strings.HasPrefix(err.Error(), "verify signed enrollment: signature verification failed") || len(got.Manifest()) != 0 || got.Digest() != "" {
		t.Fatalf("expected signature-stage rejection with zero result: %v", err)
	}
}
