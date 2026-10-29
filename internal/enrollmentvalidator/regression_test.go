package enrollmentvalidator

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
	"github.com/PHPCraftdream/ssjack/internal/domaindigest"
	"github.com/PHPCraftdream/ssjack/internal/enrollmentauth"
)

func noHTML(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestSharedDigestCompatibilityAndFailClosed(t *testing.T) {
	m := fixture()
	s := m["schemas"].([]any)[0].(map[string]any)
	doc := s["document"].(map[string]any)
	doc["description"] = "<&>\u2028"
	schemaDigest, err := domaindigest.Sum(domaindigest.Schema, noHTML(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	s["digest"] = schemaDigest
	raw := noHTML(t, m)
	want, err := domaindigest.Sum(domaindigest.Enrollment, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Validate(raw)
	if err != nil || got != want {
		t.Fatalf("shared enrollment digest: got %q, want %q: %v", got, want, err)
	}
	// A valid digest does not make an unsupported schema acceptable.
	doc["$ref"] = "#"
	s["digest"], err = domaindigest.Sum(domaindigest.Schema, noHTML(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Validate(noHTML(t, m)); got != "" || err != ErrInvalid {
		t.Fatalf("unsupported schema: got %q, %v", got, err)
	}
	if got, err := Validate(append(raw, bytes.Repeat([]byte(" "), canonicaljson.MaxInput)...)); got != "" || err != ErrInvalid {
		t.Fatalf("oversized input: got %q, %v", got, err)
	}
}

func TestLargeEmbeddedSchemaEncoding(t *testing.T) {
	m := fixture()
	s := m["schemas"].([]any)[0].(map[string]any)
	doc := s["document"].(map[string]any)
	// HTML characters would expand sixfold under json.Marshal; U+2028 and
	// U+2029 still expand under Encoder, but only twofold in bytes.
	doc["description"] = strings.Repeat("<&>", 17000) + "\u2028\u2029"
	raw := noHTML(t, doc)
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	escaped, err := json.Marshal(doc)
	if err != nil || len(escaped) <= canonicaljson.MaxInput {
		t.Fatalf("expected oversized HTML-escaped intermediate: %d, %v", len(escaped), err)
	}
	h := sha256.Sum256(append([]byte("ssjack-schema-v1\x00"), canonical...))
	s["digest"] = hex.EncodeToString(h[:])
	manifest := noHTML(t, m)
	if _, err := Validate(manifest); err != nil {
		t.Fatalf("bounded enrollment rejected: %v", err)
	}
	s["digest"] = strings.Repeat("b", 64)
	if _, err := Validate(noHTML(t, m)); err == nil {
		t.Fatal("accepted incorrect schema digest")
	}
}

func TestDuplicateInValidEnrollment(t *testing.T) {
	raw := noHTML(t, fixture())
	if _, err := Validate(raw); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{`"driver_id":"driver"`, `"driver_id":"driver","driver_id":"driver"`},
		{`"type":"boolean"`, `"type":"boolean","type":"boolean"`},
	} {
		mutated := bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(mutated, raw) {
			t.Fatal("fixture did not contain target")
		}
		if _, err := Validate(mutated); err == nil {
			t.Fatal("accepted duplicate decoded key")
		}
	}
}

func TestSignedManifestRequiresCanonicalBytes(t *testing.T) {
	canonical, err := canonicaljson.Canonicalize(noHTML(t, fixture()))
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
	for _, tc := range []struct {
		manifest []byte
		valid    bool
	}{{canonical, true}, {append(append([]byte(nil), canonical...), ' '), false}} {
		message := append([]byte("ssjack-enrollment-signature-v1\x00"), tc.manifest...)
		envelope, err := json.Marshal(struct {
			Format    string `json:"format"`
			KeyID     string `json:"key_id"`
			Manifest  string `json:"manifest"`
			Signature string `json:"signature"`
		}{enrollmentauth.Format, id, base64.RawURLEncoding.EncodeToString(tc.manifest), base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))})
		if err != nil {
			t.Fatal(err)
		}
		// Validate alone intentionally accepts noncanonical input.
		if _, err := Validate(tc.manifest); err != nil {
			t.Fatal(err)
		}
		verified, err := enrollmentauth.VerifyCanonicalBytes(envelope, root)
		if (err == nil) != tc.valid {
			t.Fatalf("canonical=%v: %v", tc.valid, err)
		}
		if tc.valid {
			digest, err := Validate(verified.Manifest())
			if err != nil || digest != verified.Digest() {
				t.Fatalf("verified manifest digest mismatch: %v", err)
			}
		}
	}
}
func TestArtifactDigestMapStringKeys(t *testing.T) {
	d := strings.Repeat("a", 64)
	for _, key := range []string{"", "Driver Binary", "Upper/Case", "é", strings.Repeat("x", 65)} {
		t.Run(key, func(t *testing.T) {
			m := fixture()
			m["artifact_digests"] = map[string]any{key: d}
			raw := noHTML(t, m)
			want, err := domaindigest.Sum(domaindigest.Enrollment, raw)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := Validate(raw); err != nil || got != want {
				t.Fatalf("digest %q, want %q: %v", got, want, err)
			}
		})
	}
	for name, artifacts := range map[string]map[string]any{
		"empty":             {},
		"bad digest":        {"Upper/Case": strings.Repeat("A", 64)},
		"non-string digest": {"Upper/Case": 1},
		"non-NFC key":       {"e\u0301": d},
		"control key":       {"bad\nkey": d},
	} {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			m["artifact_digests"] = artifacts
			if _, err := Validate(noHTML(t, m)); err != ErrInvalid {
				t.Fatalf("expected invalid: %v", err)
			}
		})
	}
	for _, count := range []int{128, 129} {
		m := fixture()
		artifacts := map[string]any{}
		for i := 0; i < count; i++ {
			artifacts[strings.Repeat("x", i+1)] = d
		}
		m["artifact_digests"] = artifacts
		if _, err := Validate(noHTML(t, m)); (err == nil) != (count == 128) {
			t.Fatalf("count %d: %v", count, err)
		}
	}
}

func TestArtifactDigestBinding(t *testing.T) {
	m := fixture()
	d := strings.Repeat("a", 64)
	m["artifact_digests"] = map[string]any{"Driver Binary": d}
	original, err := Validate(noHTML(t, m))
	if err != nil {
		t.Fatal(err)
	}
	for name, artifacts := range map[string]map[string]any{
		"key":    {"Driver Binary 2": d},
		"digest": {"Driver Binary": strings.Repeat("b", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			m["artifact_digests"] = artifacts
			got, err := Validate(noHTML(t, m))
			if err != nil || got == original {
				t.Fatalf("changed %s: digest %q, original %q: %v", name, got, original, err)
			}
		})
	}
}

func TestArtifactMapOrderingAndDependencyBinding(t *testing.T) {
	d := strings.Repeat("a", 64)
	m := fixture()
	m["artifact_digests"] = map[string]any{"": d, "é": d}
	m["dependency_digests"] = map[string]any{"dep": d}
	m["provenance"].(map[string]any)["dependencies"] = []any{map[string]any{"name": "dep", "path": "/dep", "sha256": d}}
	raw := noHTML(t, m)
	if _, err := Validate(raw); err != nil {
		t.Fatal(err)
	}
	ordered := `"artifact_digests":{"":"` + d + `","é":"` + d + `"}`
	for _, replacement := range []string{
		`"artifact_digests":{"é":"` + d + `","":"` + d + `"}`,
		`"artifact_digests":{"":"` + d + `","\u00e9":"` + d + `","é":"` + d + `"}`,
	} {
		other := bytes.Replace(raw, []byte(ordered), []byte(replacement), 1)
		if bytes.Equal(raw, other) {
			t.Fatal("fixture did not contain artifact map")
		}
		if _, err := Validate(other); err != ErrInvalid {
			t.Fatalf("expected invalid ordering or duplicate: %v", err)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"dependency non-Name": func(m map[string]any) {
			m["dependency_digests"] = map[string]any{"Upper/Case": d}
			m["provenance"].(map[string]any)["dependencies"].([]any)[0].(map[string]any)["name"] = "Upper/Case"
		},
		"dependency digest mismatch": func(m map[string]any) { m["dependency_digests"] = map[string]any{"dep": strings.Repeat("b", 64)} },
		"extra field":                func(m map[string]any) { m["provenance"].(map[string]any)["extra"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			copy := fixture()
			copy["artifact_digests"] = m["artifact_digests"]
			copy["dependency_digests"] = m["dependency_digests"]
			copy["provenance"] = map[string]any{"source": "source", "revision": "rev", "dependencies": []any{map[string]any{"name": "dep", "path": "/dep", "sha256": d}}}
			mutate(copy)
			if _, err := Validate(noHTML(t, copy)); err != ErrInvalid {
				t.Fatalf("expected invalid: %v", err)
			}
		})
	}
}

func TestDigestMapIncomingOrder(t *testing.T) {
	m := fixture()
	d := strings.Repeat("a", 64)
	m["artifact_digests"] = map[string]any{"a": d, "b": d}
	m["dependency_digests"] = map[string]any{"a": d, "b": d}
	m["provenance"].(map[string]any)["dependencies"] = []any{
		map[string]any{"name": "a", "path": "/a", "sha256": d},
		map[string]any{"name": "b", "path": "/b", "sha256": d},
	}
	raw := noHTML(t, m)
	digest, err := Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	if got, err := Validate(indented.Bytes()); err != nil || got != digest {
		t.Fatalf("sorted noncanonical input: %q, %v", got, err)
	}
	for _, field := range []string{"artifact_digests", "dependency_digests"} {
		t.Run(field, func(t *testing.T) {
			ordered := `"` + field + `":{"a":"` + d + `","b":"` + d + `"}`
			for _, replacement := range []string{
				`"` + field + `":{"b":"` + d + `","a":"` + d + `"}`,
				`"` + field + `":{"a":"` + d + `","\u0061":"` + d + `","b":"` + d + `"}`,
			} {
				other := bytes.Replace(raw, []byte(ordered), []byte(replacement), 1)
				if bytes.Equal(raw, other) {
					t.Fatal("fixture did not contain digest map")
				}
				if _, err := Validate(other); err == nil {
					t.Fatal("accepted reversed or duplicate decoded map keys")
				}
			}
		})
	}
}
