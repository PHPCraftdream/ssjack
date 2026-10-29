package externalconformance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/externalschemasubset"
)

func unifiedDigest(schema string) string {
	h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + schema))
	return hex.EncodeToString(h[:])
}

func TestUnifiedLiteralVectors(t *testing.T) {
	cases := []struct {
		name, body string
		pass, fail []string
	}{
		{"irrelevant containers", `"additionalProperties":true,"items":{"type":"null"},"maxItems":1,"properties":{"x":{"type":"integer"}},"required":["x"],"type":"boolean"`, []string{`true`}, []string{`{}`, `null`}},
		{"irrelevant scalar", `"maxLength":2,"minimum":1,"type":"boolean"`, []string{`true`}, []string{`1`}},
		{"object reversed", `"additionalProperties":false,"maxProperties":0,"minProperties":1,"type":["object","null"]`, []string{`null`}, []string{`{}`, `{"x":1}`}},
		{"array reversed", `"items":{"type":"integer"},"maxItems":1,"minItems":2,"type":["array","null"]`, []string{`null`}, []string{`[]`, `[1]`, `[1,2]`}},
		{"string reversed", `"maxLength":1,"minLength":2,"type":["string","null"]`, []string{`null`}, []string{`"x"`, `"xx"`}},
		{"integer reversed", `"maximum":1,"minimum":2,"type":["integer","null"]`, []string{`null`}, []string{`1`, `2`}},
		{"exclusive reversed", `"exclusiveMaximum":1,"exclusiveMinimum":2,"type":["integer","null"]`, []string{`null`}, []string{`1`, `2`}},
		{"finite excludes null", `"enum":[1],"maximum":1,"minimum":2,"type":["integer","null"]`, nil, []string{`null`, `1`}},
		{"boolean unique", `"type":"boolean","uniqueItems":true`, []string{`true`, `false`}, []string{`null`, `[]`}},
		{"boolean multiple", `"multipleOf":2,"type":"boolean"`, []string{`true`, `false`}, []string{`2`}},
		{"boolean exclusive minimum", `"exclusiveMinimum":2,"type":"boolean"`, []string{`true`, `false`}, []string{`2`}},
		{"boolean exclusive maximum", `"exclusiveMaximum":2,"type":"boolean"`, []string{`true`, `false`}, []string{`2`}},
		{"nullable boolean unique", `"type":["boolean","null"],"uniqueItems":true`, []string{`true`, `null`}, []string{`[]`}},
		{"nullable boolean multiple", `"multipleOf":2,"type":["boolean","null"]`, []string{`false`, `null`}, []string{`2`}},
		{"nullable boolean exclusive minimum", `"exclusiveMinimum":2,"type":["boolean","null"]`, []string{`true`, `null`}, []string{`2`}},
		{"nullable boolean exclusive maximum", `"exclusiveMaximum":2,"type":["boolean","null"]`, []string{`false`, `null`}, []string{`2`}},
		{"nullable boolean finite", `"enum":[true],"exclusiveMaximum":2,"exclusiveMinimum":-2,"multipleOf":2,"type":["boolean","null"],"uniqueItems":true`, []string{`true`}, []string{`null`, `false`}},
		{"applicable unique", `"items":{"type":"integer"},"maxItems":2,"type":"array","uniqueItems":true`, []string{`[1,2]`}, []string{`[1,1]`}},
		{"applicable numeric", `"exclusiveMaximum":6,"exclusiveMinimum":-2,"multipleOf":2,"type":"integer"`, []string{`0`, `2`, `4`}, []string{`-2`, `3`, `6`}},
		{"finite intersection", `"const":2,"enum":[1,2,3]`, []string{`2`}, []string{`1`, `3`, `null`}},
		{"mixed finite", `"enum":[null,true,1,"x",[],{"x":1}]`, []string{`null`, `true`, `1`, `"x"`, `[]`, `{"x":1}`}, []string{`false`, `2`, `"xx"`, `[1]`, `{}`}},
		{"closed finite", `"additionalProperties":false,"enum":[null,{"x":1},{"x":2}],"properties":{"x":{"const":1}},"required":["x"]`, []string{`null`, `{"x":1}`}, []string{`{"x":2}`, `{}`}},
		{"nested nullable applicability", `"additionalProperties":false,"properties":{"x":{"items":{"maxLength":1,"minimum":2,"type":["integer","null"]},"maxItems":2,"type":["array","null"]}},"required":["x"],"type":["object","null"]`, []string{`null`, `{"x":null}`, `{"x":[null,2]}`}, []string{`{"x":[1]}`, `{"x":["x"]}`, `{"x":[2,2,2]}`}},
		{"nested irrelevant container", `"items":{"items":{"type":"null"},"minimum":2,"type":["integer","null"]},"maxItems":2,"type":"array"`, []string{`[null,2]`}, []string{`[1]`, `[[null]]`}},
		{"nested boolean keywords", `"items":{"exclusiveMaximum":2,"exclusiveMinimum":-2,"multipleOf":2,"type":"boolean","uniqueItems":true},"maxItems":2,"type":"array"`, []string{`[true,false]`, `[]`}, []string{`[null]`, `[2]`}},
		{"nested nullable boolean keywords", `"items":{"exclusiveMaximum":2,"exclusiveMinimum":-2,"multipleOf":2,"type":["boolean","null"],"uniqueItems":true},"maxItems":2,"type":"array"`, []string{`[true,null]`, `[false]`}, []string{`[2]`, `[[]]`}},
		{"ordinary typeless closed", `"additionalProperties":false,"properties":{"x":{"type":"integer"}},"required":["x"]`, []string{`{"x":1}`, `null`, `[]`}, []string{`{}`, `{"x":true}`, `{"x":1,"y":2}`}},
		{"empty omitted", `"additionalProperties":false,"type":"object"`, []string{`{}`}, []string{`{"x":1}`, `null`}},
		{"empty properties", `"additionalProperties":false,"properties":{},"type":"object"`, []string{`{}`}, []string{`{"x":1}`}},
		{"empty required", `"additionalProperties":false,"required":[],"type":"object"`, []string{`{}`}, []string{`{"x":1}`}},
		{"extra required typed", `"additionalProperties":false,"required":["x"],"type":["object","null"]`, []string{`null`}, []string{`{}`, `{"x":1}`}},
		{"extra required typeless", `"additionalProperties":false,"required":["x"]`, []string{`null`, `1`, `[]`}, []string{`{}`, `{"x":1}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schema := prefix + tc.body + `}`
			digest := unifiedDigest(schema)
			if err := driverprotocol.ValidateSchemaDocument([]byte(schema), "x", digest); err != nil {
				t.Fatalf("driver schema: %v", err)
			}
			if err := externalschemasubset.ValidateSchema([]byte(schema)); err != nil {
				t.Fatalf("external schema: %v", err)
			}
			for _, group := range []struct {
				values           []string
				driver, external error
			}{{tc.pass, nil, nil}, {tc.fail, driverprotocol.ErrInvalid, externalschemasubset.ErrValue}} {
				for _, value := range group.values {
					if err := driverprotocol.ValidatePinnedValue([]byte(schema), "x", digest, "t", "k", "t", "k", "x", []byte(value), 65536); !errors.Is(err, group.driver) {
						t.Errorf("driver %s: %v want %v", value, err, group.driver)
					}
					if err := externalschemasubset.Validate([]byte(schema), []byte(value), 65536); !errors.Is(err, group.external) {
						t.Errorf("external %s: %v want %v", value, err, group.external)
					}
				}
			}
		})
	}
}

func TestUnifiedMalformedLiteralVectors(t *testing.T) {
	bases := []struct{ body, value string }{
		{`"type":"boolean"`, `true`},
		{`"type":["boolean","null"]`, `null`},
		{`"type":"null"`, `null`},
		{`"const":null`, `null`},
	}
	badKeywords := []string{
		`"properties":null`, `"properties":{"x":false}`, `"required":["x","x"]`, `"additionalProperties":{}`,
		`"minProperties":-1`, `"maxProperties":129`, `"items":false`, `"items":{"type":"string"}`,
		`"minItems":-1`, `"maxItems":257`, `"uniqueItems":1`, `"minLength":-1`, `"maxLength":0`,
		`"minimum":false`, `"maximum":null`, `"exclusiveMinimum":true`, `"exclusiveMaximum":1.0`, `"multipleOf":0`,
		`"title":null`, `"description":false`, `"examples":{}`, `"enum":[]`, `"$ref":"x"`,
	}
	for _, base := range bases {
		for _, bad := range badKeywords {
			parts := []string{base.body, bad}
			sort.Strings(parts)
			schema := prefix + parts[0] + `,` + parts[1] + `}`
			if bad == `"$ref":"x"` {
				schema = `{"$ref":"x","$schema":"https://json-schema.org/draft/2020-12/schema",` + base.body + `}`
			}
			checkUnifiedMalformed(t, schema, base.value)
		}
	}
	for _, tc := range []struct{ body, value string }{
		{`"additionalProperties":false,"items":{"type":"integer"},"maxItems":1`, `[1]`},
		{`"additionalProperties":false,"maxLength":1`, `"x"`},
		{`"additionalProperties":false,"minimum":2,"multipleOf":2`, `2`},
		{`"const":2,"enum":[1,2,3],"minimum":2,"multipleOf":2`, `2`},
		{`"enum":[null,true,1,2,"x","xx",[],[1,2]],"maxItems":1,"maxLength":1,"minimum":2`, `true`},
		{`"enum":[null,true,1,2,"x","xx",[],[1]],"maxItems":0,"maxLength":1,"maximum":1,"minItems":1,"minLength":2,"minimum":2`, `null`},
		{`"enum":[1],"minProperties":0`, `1`},
		{`"additionalProperties":false,"enum":[null],"uniqueItems":true`, `null`},
		{`"items":{"const":1,"multipleOf":2},"maxItems":1,"type":"array"`, `[1]`},
		{`"type":"string"`, `"x"`},
		{`"maxItems":1,"type":"array"`, `[]`},
		{`"items":{"type":"null"},"type":"array"`, `[]`},
		{`"additionalProperties":true,"type":"object"`, `{}`},
		{`"additionalProperties":false,"properties":{"x":{"type":"null"}},"type":"object"`, `{"x":null}`},
		{`"items":{"type":"boolean","uniqueItems":1},"maxItems":1,"type":"array"`, `[true]`},
		{`"items":{"multipleOf":0,"type":["boolean","null"]},"maxItems":1,"type":"array"`, `[null]`},
		{`"items":{"exclusiveMinimum":true,"type":"boolean"},"maxItems":1,"type":"array"`, `[true]`},
		{`"items":{"exclusiveMaximum":1.0,"type":["boolean","null"]},"maxItems":1,"type":"array"`, `[null]`},
		{`"type":"number"`, `1`},
	} {
		checkUnifiedMalformed(t, prefix+tc.body+`}`, tc.value)
	}
}

func TestUnifiedTypelessForbiddenKeywords(t *testing.T) {
	bases := [][]string{
		{`"const":null`},
		{`"additionalProperties":false`, `"const":null`, `"enum":[null]`},
	}
	keywords := []string{
		`"items":{"type":"null"}`, `"minItems":0`, `"maxItems":1`, `"uniqueItems":true`,
		`"minLength":0`, `"maxLength":1`, `"minimum":0`, `"maximum":1`,
		`"exclusiveMinimum":0`, `"exclusiveMaximum":1`, `"multipleOf":1`,
	}
	for _, base := range bases {
		for _, keyword := range keywords {
			parts := append(append([]string{}, base...), keyword)
			sort.Strings(parts)
			schema := prefix
			for i, part := range parts {
				if i > 0 {
					schema += `,`
				}
				schema += part
			}
			checkUnifiedMalformed(t, schema+`}`, `null`)
		}
	}
}

func checkUnifiedMalformed(t *testing.T, schema, value string) {
	t.Helper()
	digest := unifiedDigest(schema)
	if _, err := driverprotocol.CanonicalSchemaDocument([]byte(schema)); !errors.Is(err, driverprotocol.ErrSchema) {
		t.Errorf("driver canonical %s: %v", schema, err)
	}
	if err := driverprotocol.ValidateSchemaDocument([]byte(schema), "x", digest); !errors.Is(err, driverprotocol.ErrSchema) {
		t.Errorf("driver schema %s: %v", schema, err)
	}
	if err := driverprotocol.ValidatePinnedValue([]byte(schema), "x", digest, "t", "k", "t", "k", "x", []byte(value), 65536); !errors.Is(err, driverprotocol.ErrSchema) {
		t.Errorf("driver value %s: %v", schema, err)
	}
	if err := externalschemasubset.ValidateSchema([]byte(schema)); !errors.Is(err, externalschemasubset.ErrSchema) {
		t.Errorf("external schema %s: %v", schema, err)
	}
	if err := externalschemasubset.Validate([]byte(schema), []byte(value), 65536); !errors.Is(err, externalschemasubset.ErrSchema) {
		t.Errorf("external value %s: %v", schema, err)
	}
}

func TestUnifiedIndependentPinsAndErrorClasses(t *testing.T) {
	const schema = prefix + `"type":"boolean"}`
	const changed = prefix + `"type":["boolean","null"]}`
	digest := unifiedDigest(schema)
	wrongDomain := sha256.Sum256([]byte("ssjack-other-v1\x00" + schema))
	missingNUL := sha256.Sum256([]byte("ssjack-schema-v1" + schema))
	for _, tc := range []struct {
		name, schema, digest, id, target, kind, actualTarget, actualKind, actualID, value string
		want                                                                              error
	}{
		{"valid", schema, digest, "x", "t", "k", "t", "k", "x", `true`, nil},
		{"wrong domain", schema, hex.EncodeToString(wrongDomain[:]), "x", "t", "k", "t", "k", "x", `true`, driverprotocol.ErrSchema},
		{"missing NUL", schema, hex.EncodeToString(missingNUL[:]), "x", "t", "k", "t", "k", "x", `true`, driverprotocol.ErrSchema},
		{"stale schema", changed, digest, "x", "t", "k", "t", "k", "x", `true`, driverprotocol.ErrSchema},
		{"id", schema, digest, "x", "t", "k", "t", "k", "other", `true`, driverprotocol.ErrSchema},
		{"target", schema, digest, "x", "t", "k", "other", "k", "x", `true`, driverprotocol.ErrSchema},
		{"kind", schema, digest, "x", "t", "k", "t", "other", "x", `true`, driverprotocol.ErrSchema},
		{"value class", schema, digest, "x", "t", "k", "t", "k", "x", `null`, driverprotocol.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := driverprotocol.ValidatePinnedValue([]byte(tc.schema), tc.id, tc.digest, tc.target, tc.kind, tc.actualTarget, tc.actualKind, tc.actualID, []byte(tc.value), 65536); !errors.Is(err, tc.want) {
				t.Errorf("pinned value: %v, want %v", err, tc.want)
			}
		})
	}
	for _, tc := range []struct{ name, schema, digest, id string }{
		{"wrong domain", schema, hex.EncodeToString(wrongDomain[:]), "x"},
		{"missing NUL", schema, hex.EncodeToString(missingNUL[:]), "x"},
		{"stale", changed, digest, "x"},
		{"invalid id", schema, digest, "INVALID"},
	} {
		if err := driverprotocol.ValidateSchemaDocument([]byte(tc.schema), tc.id, tc.digest); !errors.Is(err, driverprotocol.ErrSchema) {
			t.Errorf("%s schema pin: %v", tc.name, err)
		}
	}
	if err := driverprotocol.ValidateSchemaDocument([]byte(schema), "x", digest); err != nil {
		t.Errorf("valid schema pin: %v", err)
	}
}

func TestUnifiedPinnedRequestAndProjection(t *testing.T) {
	const schema = prefix + `"additionalProperties":false,"properties":{"ok":{"items":{"type":"null"},"maxItems":1,"type":"boolean"}},"required":["ok"],"type":"object"}`
	const changed = prefix + `"additionalProperties":false,"properties":{"ok":{"items":{"type":"null"},"maxItems":2,"type":"boolean"}},"required":["ok"],"type":"object"}`
	const malformed = prefix + `"additionalProperties":false,"properties":{"ok":{"items":false,"maxItems":1,"type":"boolean"}},"required":["ok"],"type":"object"}`
	const observe = `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":1000,"operation_id":null}`
	q, err := driverprotocol.ValidateStructuralRequest([]byte(observe))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, schema, digest, value string
		want                        error
	}{
		{"valid", schema, unifiedDigest(schema), `true`, nil},
		{"boolean violation", schema, unifiedDigest(schema), `1`, driverprotocol.ErrInvalid},
		{"malformed inapplicable child", malformed, unifiedDigest(malformed), `true`, driverprotocol.ErrSchema},
		{"stale pin", changed, unifiedDigest(schema), `true`, driverprotocol.ErrSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"plan","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":{"ok":` + tc.value + `},"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":1000,"operation_id":null}`
			if _, err := driverprotocol.ValidatePinnedRequest([]byte(plan), []byte(tc.schema), "cache.desired", tc.digest, "target", "kind"); !errors.Is(err, tc.want) {
				t.Errorf("request: %v, want %v", err, tc.want)
			}
			response := `{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":null,"projection":{"ok":` + tc.value + `}}}`
			if _, err := driverprotocol.ValidatePinnedProjection(q, []byte(response), []byte(tc.schema), "cache.desired", "cache.projection", tc.digest, "target", "kind", "cache.projection"); !errors.Is(err, tc.want) {
				t.Errorf("projection: %v, want %v", err, tc.want)
			}
		})
	}
}
