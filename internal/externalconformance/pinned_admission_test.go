package externalconformance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/externalschemasubset"
)

func admissionSchema(t *testing.T, schema string) string {
	t.Helper()
	digest := unifiedDigest(schema)
	if err := driverprotocol.ValidateSchemaDocument([]byte(schema), "x", digest); err != nil {
		t.Fatalf("driver schema and pin: %v", err)
	}
	if err := externalschemasubset.ValidateSchema([]byte(schema)); err != nil {
		t.Fatalf("external schema: %v", err)
	}
	return digest
}

func admissionValue(t *testing.T, schema, digest, value string, limit int, accepted bool) {
	t.Helper()
	var driverWant, externalWant error
	if !accepted {
		driverWant = driverprotocol.ErrInvalid
		externalWant = externalschemasubset.ErrValue
	}
	if err := driverprotocol.ValidatePinnedValue([]byte(schema), "x", digest, "t", "k", "t", "k", "x", []byte(value), limit); !errors.Is(err, driverWant) {
		t.Errorf("driver: %v, want %v", err, driverWant)
	}
	if err := externalschemasubset.Validate([]byte(schema), []byte(value), limit); !errors.Is(err, externalWant) {
		t.Errorf("external: %v, want %v", err, externalWant)
	}
}

func admissionArrayBytes(t *testing.T, size int) string {
	t.Helper()
	count := (size - 1 + 4098) / 4099
	remaining := size - 1 - 3*count
	parts := make([]string, count)
	for i := range parts {
		n := remaining
		if n > 4096 {
			n = 4096
		}
		parts[i] = `"` + strings.Repeat("a", n) + `"`
		remaining -= n
	}
	value := `[` + strings.Join(parts, `,`) + `]`
	if remaining != 0 || len(value) != size || len(value) >= 262144 {
		t.Fatalf("array size=%d remaining=%d, want %d", len(value), remaining, size)
	}
	return value
}

func TestPinnedAdmissionByteLimits(t *testing.T) {
	const nullSchema = prefix + `"type":"null"}`
	const arraySchema = prefix + `"items":{"maxLength":4096,"type":"string"},"maxItems":256,"type":"array"}`
	const stringSchema = prefix + `"maxLength":8,"type":"string"}`
	nullDigest := admissionSchema(t, nullSchema)
	arrayDigest := admissionSchema(t, arraySchema)
	stringDigest := admissionSchema(t, stringSchema)
	for _, tc := range []struct {
		size     int
		accepted bool
	}{{65537, true}, {262144, true}, {262145, false}} {
		t.Run(fmt.Sprintf("raw_%d", tc.size), func(t *testing.T) {
			value := `null` + strings.Repeat(" ", tc.size-4)
			if len(value) != tc.size {
				t.Fatal("raw length")
			}
			admissionValue(t, nullSchema, nullDigest, value, 4, tc.accepted)
		})
	}
	for _, tc := range []struct {
		name        string
		size, limit int
		accepted    bool
	}{
		{"canonical_exact", 65536, 65536, true}, {"canonical_over", 65537, 65536, false},
		{"desired_exact", 32768, driverprotocol.MaxDesired, true}, {"desired_over", 32769, driverprotocol.MaxDesired, false},
		{"projection_exact", 8192, driverprotocol.MaxProjection, true}, {"projection_over", 8193, driverprotocol.MaxProjection, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admissionValue(t, arraySchema, arrayDigest, admissionArrayBytes(t, tc.size), tc.limit, tc.accepted)
		})
	}
	if driverprotocol.MaxDesired != 32768 || driverprotocol.MaxProjection != 8192 {
		t.Fatal("caller limits changed")
	}
	for _, tc := range []struct {
		name, value string
		limit       int
		accepted    bool
	}{
		{"utf8_exact", `"é"`, 4, true}, {"utf8_over", `"é"`, 3, false},
		{"escaped_utf8", `"\u00e9"`, 4, true}, {"escaped_ascii", `"\u0061"`, 3, true},
		{"html_not_marshal_escaped", `"<>&"`, 5, true}, {"quote_escape_exact", `"\""`, 4, true},
		{"quote_escape_over", `"\""`, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) { admissionValue(t, stringSchema, stringDigest, tc.value, tc.limit, tc.accepted) })
	}
	for _, limit := range []int{-1, 0, 65537} {
		t.Run(fmt.Sprintf("invalid_limit_%d", limit), func(t *testing.T) { admissionValue(t, nullSchema, nullDigest, `null`, limit, false) })
	}
}

func TestPinnedAdmissionStrictAndIntegerSemantics(t *testing.T) {
	const zero = prefix + `"const":0,"type":"integer"}`
	const nested = prefix + `"additionalProperties":false,"properties":{"x":{"const":0,"type":"integer"}},"required":["x"],"type":"object"}`
	const unique = prefix + `"items":{"type":"integer"},"maxItems":2,"type":"array","uniqueItems":true}`
	const integer = prefix + `"type":"integer"}`
	const text = prefix + `"maxLength":8,"type":"string"}`
	const object = prefix + `"additionalProperties":false,"properties":{"a":{"type":"integer"}},"required":["a"],"type":"object"}`
	groups := []struct {
		name, schema string
		pass, fail   []string
	}{
		{"zero", zero, []string{`-0`, `0`}, []string{`0.0`, `0e0`, `-0E+0`}},
		{"nested_zero", nested, []string{`{"x":-0}`, `{"x":0}`}, []string{`{"x":0.0}`}},
		{"unique", unique, []string{`[-0,1]`}, []string{`[-0,0]`}},
		{"integers", integer, []string{`9007199254740991`, `-9007199254740991`}, []string{`9007199254740992`, `-9007199254740992`, `1.0`, `1e0`, `0 0`, `0x`, ``, `+0`}},
		{"text", text, []string{`"é"`, `"a"`}, []string{`"e\u0301"`, `"\u0001"`, `"\ud800"`, `"\udc00"`, "\"" + string([]byte{0xff}) + "\"", "\"a\n\"", `"unterminated`}},
		{"decoded_duplicates", object, []string{`{"a":1}`}, []string{`{"a":1,"\u0061":1}`, `{"a":1} {}`, `{"a":}`}},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			digest := admissionSchema(t, g.schema)
			for i, value := range g.pass {
				t.Run(fmt.Sprintf("accept_%d", i), func(t *testing.T) {
					admissionValue(t, g.schema, digest, value, 65536, true)
				})
			}
			for i, value := range g.fail {
				t.Run(fmt.Sprintf("reject_%d", i), func(t *testing.T) {
					admissionValue(t, g.schema, digest, value, 65536, false)
				})
			}
		})
	}
}

func admissionZeros(n int) string {
	if n == 0 {
		return `[]`
	}
	return `[` + strings.TrimSuffix(strings.Repeat(`0,`, n), `,`) + `]`
}

func TestPinnedAdmissionResourceLimits(t *testing.T) {
	const anyNonObject = prefix + `"additionalProperties":false}`
	digest := admissionSchema(t, anyNonObject)
	full := admissionZeros(256)
	atNodes := `[` + strings.TrimSuffix(strings.Repeat(full+`,`, 15), `,`) + `,` + admissionZeros(239) + `]`
	overNodes := `[` + strings.TrimSuffix(strings.Repeat(full+`,`, 15), `,`) + `,` + admissionZeros(240) + `]`
	for _, tc := range []struct {
		name, value string
		accepted    bool
	}{
		{"depth_16", strings.Repeat(`[`, 16) + `0` + strings.Repeat(`]`, 16), true},
		{"depth_17", strings.Repeat(`[`, 17) + `0` + strings.Repeat(`]`, 17), false},
		{"nodes_4096", atNodes, true}, {"nodes_4097", overNodes, false},
		{"array_256", admissionZeros(256), true}, {"array_257", admissionZeros(257), false},
	} {
		t.Run(tc.name, func(t *testing.T) { admissionValue(t, anyNonObject, digest, tc.value, 65536, tc.accepted) })
	}
	props, required, values := make([]string, 128), make([]string, 128), make([]string, 128)
	for i := 0; i < 128; i++ {
		key := fmt.Sprintf(`"p%03d"`, i)
		props[i], required[i], values[i] = key+`:{"type":"null"}`, key, key+`:null`
	}
	schema := prefix + `"additionalProperties":false,"properties":{` + strings.Join(props, `,`) + `},"required":[` + strings.Join(required, `,`) + `],"type":"object"}`
	objectDigest := admissionSchema(t, schema)
	value := `{` + strings.Join(values, `,`) + `}`
	t.Run("object_128", func(t *testing.T) { admissionValue(t, schema, objectDigest, value, 65536, true) })
	overObject := strings.TrimSuffix(value, `}`) + `,"p128":null}`
	t.Run("object_129", func(t *testing.T) { admissionValue(t, schema, objectDigest, overObject, 65536, false) })
	for _, tc := range []struct {
		raw   string
		valid bool
	}{{value, true}, {overObject, false}} {
		if _, err := canonicaljson.Canonicalize([]byte(tc.raw)); (err == nil) != tc.valid {
			t.Errorf("canonical object resource admission valid=%v: %v", tc.valid, err)
		}
		if _, err := driverprotocol.ParseJSON([]byte(tc.raw)); (err == nil) != tc.valid {
			t.Errorf("parser object resource admission valid=%v: %v", tc.valid, err)
		}
	}
}

func TestPinnedAdmissionPinPrecedence(t *testing.T) {
	const schema = prefix + `"type":"null"}`
	const changed = prefix + `"type":["boolean","null"]}`
	const malformed = prefix + `"type":"number"}`
	digest := admissionSchema(t, schema)
	admissionSchema(t, changed)
	admissionValue(t, schema, digest, `null`, 4, true)
	wrongDomain := sha256.Sum256([]byte("ssjack-other-v1\x00" + schema))
	missingNUL := sha256.Sum256([]byte("ssjack-schema-v1" + schema))
	for _, tc := range []struct {
		name, schema, digest, id, target, kind string
		want                                   error
	}{
		{"correct", schema, digest, "x", "t", "k", driverprotocol.ErrInvalid},
		{"identity", schema, digest, "other", "t", "k", driverprotocol.ErrSchema},
		{"target", schema, digest, "x", "other", "k", driverprotocol.ErrSchema},
		{"kind", schema, digest, "x", "t", "other", driverprotocol.ErrSchema},
		{"stale", changed, digest, "x", "t", "k", driverprotocol.ErrSchema},
		{"wrong_domain", schema, hex.EncodeToString(wrongDomain[:]), "x", "t", "k", driverprotocol.ErrSchema},
		{"missing_nul", schema, hex.EncodeToString(missingNUL[:]), "x", "t", "k", driverprotocol.ErrSchema},
		{"malformed_digest", schema, "not-a-digest", "x", "t", "k", driverprotocol.ErrSchema},
		{"malformed_schema", malformed, unifiedDigest(malformed), "x", "t", "k", driverprotocol.ErrSchema},
	} {
		for _, input := range []struct {
			name, value string
			limit       int
		}{
			{"malformed", `{`, 4}, {"raw_over", `null` + strings.Repeat(" ", 262141), 4}, {"invalid_limit", `null`, 0},
		} {
			t.Run(tc.name+"/"+input.name, func(t *testing.T) {
				err := driverprotocol.ValidatePinnedValue([]byte(tc.schema), "x", tc.digest, "t", "k", tc.target, tc.kind, tc.id, []byte(input.value), input.limit)
				if !errors.Is(err, tc.want) {
					t.Errorf("got %v, want %v", err, tc.want)
				}
			})
		}
	}
	for _, input := range []struct {
		value string
		limit int
	}{{`{`, 4}, {`null` + strings.Repeat(" ", 262141), 4}, {`null`, 0}} {
		if err := externalschemasubset.Validate([]byte(malformed), []byte(input.value), input.limit); !errors.Is(err, externalschemasubset.ErrSchema) {
			t.Errorf("external schema precedence: %v", err)
		}
		if err := externalschemasubset.Validate([]byte(schema), []byte(input.value), input.limit); !errors.Is(err, externalschemasubset.ErrValue) {
			t.Errorf("external value class: %v", err)
		}
	}
}
