package enrollmentrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
)

const fixtureSchemaDigest = "89c526c00a0416cf1c19a9f502cf3a831d5b566a7defb77af96b9f4e301a95f1"

func recordFixture(t *testing.T) (enrollment.Metadata, enrollment.Policy, enrollment.Snapshot, string) {
	t.Helper()
	m, err := enrollment.Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"demo.driver","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := enrollment.ParsePolicy([]byte(`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"demo.driver","driver_protocol":1,"revision":"r1"}`), m)
	if err != nil {
		t.Fatal(err)
	}
	schema := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"x":{"type":"integer","minimum":0,"maximum":3}},"required":["x"],"additionalProperties":false}`
	canonical, err := driverprotocol.CanonicalSchemaDocument([]byte(schema))
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), canonical...))
	if hex.EncodeToString(d[:]) != fixtureSchemaDigest {
		t.Fatal("independent known schema digest mismatch")
	}
	raw := fmt.Sprintf(`{"format":%q,"enrollment_id":%q,"driver_id":%q,"driver_protocol":1,"executable":{"path":"/opt/demo","sha256":%q},"configuration_digest":%q,"principal":{"issuer":"human-process","subject":"operator-1"},"schemas":[{"id":"demo.desired","digest":"%s","document":%s},{"id":"demo.projection","digest":"%s","document":%s}],"kinds":[{"name":"cache","desired_schema_id":"demo.desired","projection_schema_id":"demo.projection"}]}`, RecordFormat, m.EnrollmentID(), m.DriverID(), strings.Repeat("a", 64), strings.Repeat("b", 64), fixtureSchemaDigest, canonical, fixtureSchemaDigest, canonical)
	snapshotRaw := fmt.Sprintf(`{"format":%q,"enrollment_id":%q,"driver_id":%q,"driver_protocol":1,"executable":{"path":"/opt/demo","sha256":%q},"artifact_digests":{"main":"%s"},"dependency_digests":{},"configuration_digest":%q,"principal":{"issuer":"human-process","subject":"operator-1"}}`, enrollment.SnapshotFormat, m.EnrollmentID(), m.DriverID(), strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("b", 64))
	snapshot, err := enrollment.ParseSnapshot([]byte(snapshotRaw), m, p)
	if err != nil {
		t.Fatal(err)
	}
	return m, p, snapshot, raw
}

func TestParseRecordRejectsSnapshotAndPolicyBindingMismatches(t *testing.T) {
	m, p, snapshot, raw := recordFixture(t)
	badPolicyRevision, err := enrollment.ParsePolicy([]byte(`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"demo.driver","driver_protocol":1,"revision":"r2"}`), m)
	if err != nil {
		t.Fatal(err)
	}
	badPolicyDigest, err := enrollment.ParsePolicy([]byte("{\"format\":\"ssjack-policy-subset-v1\",\"enrollment_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"driver_id\":\"demo.driver\",\"driver_protocol\":1,\"revision\":\"r1\"}\n"), m)
	if err != nil {
		t.Fatal(err)
	}
	if badPolicyDigest.Revision() != p.Revision() || badPolicyDigest.Digest() == p.Digest() {
		t.Fatal("policy fixture did not preserve revision and alter raw digest")
	}
	for _, tc := range []struct {
		name     string
		snapshot enrollment.Snapshot
		policy   enrollment.Policy
	}{
		{"snapshot policy revision", snapshot, badPolicyRevision},
		{"policy digest", snapshot, badPolicyDigest},
		{"snapshot executable path", mustRecordSnapshot(t, m, p, `"path":"/opt/demo"`, `"path":"/opt/other"`), p},
		{"snapshot executable digest", mustRecordSnapshot(t, m, p, `"sha256":"`+strings.Repeat("a", 64)+`"`, `"sha256":"`+strings.Repeat("a", 63)+`c"`), p},
		{"snapshot configuration digest", mustRecordSnapshot(t, m, p, `"configuration_digest":"`+strings.Repeat("b", 64)+`"`, `"configuration_digest":"`+strings.Repeat("b", 63)+`c"`), p},
		{"snapshot principal", mustRecordSnapshot(t, m, p, `"subject":"operator-1"`, `"subject":"operator-2"`), p},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRecord([]byte(raw), m, tc.snapshot, tc.policy); err == nil {
				t.Fatal("accepted snapshot or policy mismatch")
			}
		})
	}
	_ = snapshot
}

func snapshotFixtureRaw(m enrollment.Metadata, p enrollment.Policy) string {
	return fmt.Sprintf(`{"format":%q,"enrollment_id":%q,"driver_id":%q,"driver_protocol":1,"executable":{"path":"/opt/demo","sha256":%q},"artifact_digests":{"main":"%s"},"dependency_digests":{},"configuration_digest":"%s","principal":{"issuer":"human-process","subject":"operator-1"}}`, enrollment.SnapshotFormat, m.EnrollmentID(), m.DriverID(), strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("b", 64))
}

func mustRecordSnapshot(t *testing.T, m enrollment.Metadata, p enrollment.Policy, old, replacement string) enrollment.Snapshot {
	t.Helper()
	base := snapshotFixtureRaw(m, p)
	base = strings.Replace(base, old, replacement, 1)
	s, err := enrollment.ParseSnapshot([]byte(base), m, p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseRecordSyntheticBindings(t *testing.T) {
	m, p, snapshot, raw := recordFixture(t)
	r, err := ParseRecord([]byte(raw), m, snapshot, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.EnrollmentID() != m.EnrollmentID() || r.DriverID() != m.DriverID() || r.PolicyRevision() != p.Revision() || r.PolicyDigest() != p.Digest() {
		t.Fatal("binding mismatch")
	}
	if issuer, subject := r.Principal(); issuer != "human-process" || subject != "operator-1" {
		t.Fatal("principal mismatch")
	}
	if len(r.Kinds()) != 1 || r.Kinds()[0].Name() != "cache" || r.Kinds()[0].DesiredSchemaID() != "demo.desired" || r.Kinds()[0].ProjectionSchemaID() != "demo.projection" {
		t.Fatal("kind/schema binding mismatch")
	}
	copyKinds := r.Kinds()
	copyKinds[0] = KindPin{}
	if r.Kinds()[0].Name() != "cache" {
		t.Fatal("Kinds exposed mutable state")
	}
	s, ok := r.Schema("demo.desired")
	if !ok || s.Digest() != fixtureSchemaDigest {
		t.Fatal("missing expected schema pin")
	}
	copy := s.Document()
	copy[0] ^= 1
	again, _ := r.Schema("demo.desired")
	if string(copy) == string(again.Document()) {
		t.Fatal("schema accessor exposed mutable bytes")
	}

	rootCases := []struct{ name, input string }{
		{"unknown root field", strings.TrimSuffix(raw, "}") + `,"extra":0}`},
		{"null root", `null`}, {"array root", `[]`},
	}
	rootKeys := []string{"format", "enrollment_id", "driver_id", "driver_protocol", "executable", "configuration_digest", "principal", "schemas", "kinds"}
	for _, key := range rootKeys {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, key)
		missing, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if string(missing) == raw {
			t.Fatalf("missing-field mutation did not change input: %s", key)
		}
		rootCases = append(rootCases, struct{ name, input string }{"missing/" + key, string(missing)})
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			t.Fatal(err)
		}
		fields[key] = json.RawMessage("null")
		nullValue, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if string(nullValue) == raw {
			t.Fatalf("null mutation did not change input: %s", key)
		}
		rootCases = append(rootCases, struct{ name, input string }{"null/" + key, string(nullValue)})
	}
	for _, tc := range rootCases {
		t.Run("root/"+tc.name, func(t *testing.T) {
			if _, err := ParseRecord([]byte(tc.input), m, snapshot, p); err == nil {
				t.Fatal("accepted invalid root")
			}
		})
	}
	mutations := []struct{ name, old, replacement string }{
		{"changed schema", `"maximum":3`, `"maximum":4`},
		{"unsupported schema keyword", `"additionalProperties":false`, `"additionalProperties":false,"pattern":"x"`},
		{"principal issuer", `"issuer":"human-process"`, `"issuer":"other"`},
		{"principal subject", `"subject":"operator-1"`, `"subject":"other"`},
		{"non-ASCII principal", `"subject":"operator-1"`, `"subject":"opérator"`},
		{"control principal", `"subject":"operator-1"`, `"subject":"operator\u0001"`},
		{"surrogate principal", `"subject":"operator-1"`, `"subject":"operator\ud800"`},
		{"executable path", `"path":"/opt/demo"`, `"path":"/opt/other"`},
		{"executable digest", `"sha256":"` + strings.Repeat("a", 64) + `"`, `"sha256":"` + strings.Repeat("c", 64) + `"`},
		{"configuration digest", `"configuration_digest":"` + strings.Repeat("b", 64) + `"`, `"configuration_digest":"` + strings.Repeat("c", 64) + `"`},
		{"desired schema id", `"desired_schema_id":"demo.desired"`, `"desired_schema_id":"missing.desired"`},
		{"projection schema id", `"projection_schema_id":"demo.projection"`, `"projection_schema_id":"missing.projection"`},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			bad := strings.Replace(raw, tc.old, tc.replacement, 1)
			if bad == raw {
				t.Fatal("mutation did not change input")
			}
			if _, err := ParseRecord([]byte(bad), m, snapshot, p); err == nil {
				t.Fatal("accepted mismatch")
			}
		})
	}
	dup := strings.Replace(raw, `"id":"demo.projection","digest":"`+fixtureSchemaDigest+`"`, `"id":"demo.desired","digest":"`+fixtureSchemaDigest+`"`, 1)
	if dup == raw {
		t.Fatal("duplicate schema mutation had no effect")
	}
	if _, err := ParseRecord([]byte(dup), m, snapshot, p); err == nil {
		t.Fatal("accepted duplicate schema ID")
	}
	if _, err := ParseRecord([]byte(raw), m, snapshot, p); err != nil {
		t.Fatal(err)
	}
	duplicateKey := strings.Replace(raw, `"driver_id":"demo.driver"`, `"driver_id":"demo.driver","driver_id":"demo.driver"`, 1)
	if duplicateKey == raw {
		t.Fatal("duplicate-key mutation had no effect")
	}
	if _, err := ParseRecord([]byte(duplicateKey), m, snapshot, p); err == nil {
		t.Fatal("accepted duplicate JSON key")
	}
	if _, err := ParseRecord([]byte(raw+strings.Repeat(" ", MaxRecordSize-len(raw))), m, snapshot, p); err != nil {
		t.Fatalf("accepted record at size limit: %v", err)
	}
	if _, err := ParseRecord([]byte(raw+strings.Repeat(" ", MaxRecordSize-len(raw)+1)), m, snapshot, p); err == nil {
		t.Fatal("accepted record above size limit")
	}
	input := []byte(raw)
	parsed, err := ParseRecord(input, m, snapshot, p)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest := parsed.Digest()
	originalSchema, ok := parsed.Schema("demo.desired")
	if !ok {
		t.Fatal("missing schema before source mutation")
	}
	for i := range input {
		input[i] = 'x'
	}
	mutatedSchema, ok := parsed.Schema("demo.desired")
	if !ok || mutatedSchema.Digest() != originalSchema.Digest() || string(mutatedSchema.Document()) != string(originalSchema.Document()) || parsed.Digest() != originalDigest {
		t.Fatal("record changed after source bytes were overwritten")
	}

	// Bindings are checked independently: each altered identity component must fail.
	for _, altered := range []struct{ name, raw string }{
		{"enrollment", strings.Replace(raw, m.EnrollmentID(), "BBBBBBBBBBBBBBBBBBBBBB", 1)},
		{"driver", strings.Replace(raw, `"driver_id":"demo.driver"`, `"driver_id":"other.driver"`, 1)},
	} {
		t.Run("binding/"+altered.name, func(t *testing.T) {
			if _, err := ParseRecord([]byte(altered.raw), m, snapshot, p); err == nil {
				t.Fatal("accepted isolated binding mismatch")
			}
		})
	}
	for _, bad := range []string{
		strings.Replace(raw, `"$schema":"https://json-schema.org/draft/2020-12/schema"`, `"$schema":"https://example.invalid/schema"`, 1),
		strings.Replace(raw, `"maximum":3`, `"$ref":"https://example.invalid/schema"`, 1),
		strings.Replace(raw, `"name":"cache"`, `"name":"Cache"`, 1),
		strings.Replace(raw, `"name":"cache"`, `"name":"cache","name":"cache"`, 1),
	} {
		if _, err := ParseRecord([]byte(bad), m, snapshot, p); err == nil {
			t.Fatal("accepted invalid schema/kind record")
		}
	}
	for _, tc := range []struct{ name, kinds string }{
		{"sorted kinds", `[{"name":"cache","desired_schema_id":"demo.desired","projection_schema_id":"demo.projection"},{"name":"store","desired_schema_id":"demo.desired","projection_schema_id":"demo.projection"}]`},
		{"unsorted kinds", `[{"name":"store","desired_schema_id":"demo.desired","projection_schema_id":"demo.projection"},{"name":"cache","desired_schema_id":"demo.desired","projection_schema_id":"demo.projection"}]`},
	} {
		candidate := strings.Replace(raw, `[{"name":"cache","desired_schema_id":"demo.desired","projection_schema_id":"demo.projection"}]`, tc.kinds, 1)
		_, err := ParseRecord([]byte(candidate), m, snapshot, p)
		if tc.name == "sorted kinds" && err != nil {
			t.Fatalf("rejected valid multiple kinds: %v", err)
		}
		if tc.name == "unsorted kinds" && err == nil {
			t.Fatal("accepted unsorted kinds")
		}
	}
	if _, err := ParseRecord([]byte(raw+strings.Repeat(" ", MaxRecordSize)), m, snapshot, p); err == nil {
		t.Fatal("accepted oversized input")
	}
}

func TestRecordRawDigestIsNotCanonicalV1Digest(t *testing.T) {
	m, p, snapshot, raw := recordFixture(t)
	result, err := ParseRecord([]byte(raw), m, snapshot, p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(raw))
	if result.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatal("raw-input digest mismatch")
	}
	if result.Digest() == fixtureSchemaDigest {
		t.Fatal("record raw digest unexpectedly equals schema digest")
	}
}
