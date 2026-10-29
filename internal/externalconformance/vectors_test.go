// Package externalconformance exercises the documented isolated external dialect.
// Expectations are literal contract vectors, not derived from validator internals.
package externalconformance

import (
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/externalschemasubset"
)

const prefix = `{"$schema":"https://json-schema.org/draft/2020-12/schema",`

// Contract: docs/declarative/schemas.md, external dialect and clarifications;
// internal/externalschemasubset/README.md, shape, equality and canonical bounds.
func TestSchemaVectors(t *testing.T) {
	cases := []struct {
		name, document string
		accepted       bool
	}{
		{"closed", prefix + `"type":"object","properties":{"x":{"type":"boolean"}},"required":["x"],"additionalProperties":false}`, true},
		{"nullable empty array", prefix + `"type":["null","array"],"maxItems":0}`, true},
		{"finite object", prefix + `"const":{"nested":{"x":1}}}`, true},
		{"untyped closed", prefix + `"properties":{"x":{"type":"null"}},"required":["x"],"additionalProperties":false}`, true},
		{"boolean schema", `true`, false},
		{"wrong dialect", `{"$schema":"other","type":"null"}`, false},
		{"nested dialect", prefix + `"type":"array","maxItems":1,"items":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}}`, false},
		{"open object", prefix + `"type":"object","additionalProperties":true}`, false},
		{"unrequired property", prefix + `"type":"object","properties":{"x":{"type":"null"}},"required":[],"additionalProperties":false}`, false},
		{"unbounded string", prefix + `"type":"string"}`, false},
		{"unbounded array", prefix + `"type":"array","items":{"type":"null"}}`, false},
		{"nonempty array without items", prefix + `"type":"array","maxItems":1}`, false},
		{"invalid zero array item", prefix + `"type":"array","maxItems":0,"items":false}`, false},
		{"unknown type", prefix + `"type":"number"}`, false},
		{"invalid union", prefix + `"type":["string","boolean"],"maxLength":1}`, false},
		{"reference", prefix + `"type":"null","$ref":"https://example.invalid/schema"}`, false},
		{"definitions", prefix + `"type":"null","$defs":{}}`, false},
		{"pattern", prefix + `"type":"string","maxLength":2,"pattern":"x"}`, false},
		{"composition", prefix + `"type":"null","anyOf":[]}`, false},
		{"duplicate enum", prefix + `"enum":[{"a":1,"b":2},{"b":2,"a":1}]}`, false},
		{"unsafe number", prefix + `"type":"integer","maximum":9007199254740992}`, false},
		{"decimal", prefix + `"type":"integer","minimum":1.0}`, false},
		{"max length zero", prefix + `"type":"string","maxLength":0}`, false},
		{"max array over", prefix + `"type":"array","maxItems":257,"items":{"type":"null"}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := externalschemasubset.ValidateSchema([]byte(tc.document))
			if tc.accepted && err != nil || !tc.accepted && !errors.Is(err, externalschemasubset.ErrSchema) {
				t.Fatalf("schema acceptance=%t, error=%v", tc.accepted, err)
			}
			if !tc.accepted && !errors.Is(externalschemasubset.Validate([]byte(tc.document), []byte(`null`), 65536), externalschemasubset.ErrSchema) {
				t.Fatal("invalid schema did not fail closed before value validation")
			}
		})
	}
}

func TestValueVectors(t *testing.T) {
	const nested = prefix + `"type":"object","properties":{"data":{"type":["object","null"],"properties":{"ids":{"type":"array","items":{"type":"integer","minimum":-4,"exclusiveMaximum":5,"multipleOf":2},"minItems":1,"maxItems":2,"uniqueItems":true}},"required":["ids"],"additionalProperties":false}},"required":["data"],"additionalProperties":false}`
	const unique = prefix + `"type":"array","items":{"const":{"a":1,"b":2}},"maxItems":2,"uniqueItems":true}`
	cases := []struct {
		name, schema, value string
		accepted            bool
	}{
		{"nullable", nested, `{"data":null}`, true},
		{"nested bounds", nested, `{"data":{"ids":[-4,4]}}`, true},
		{"missing nested", nested, `{"data":{}}`, false},
		{"extra nested", nested, `{"data":{"ids":[2],"other":null}}`, false},
		{"extra root", nested, `{"data":null,"other":null}`, false},
		{"exclusive bound below", prefix + `"type":"integer","exclusiveMaximum":5}`, `4`, true},
		{"exclusive bound equal", prefix + `"type":"integer","exclusiveMaximum":5}`, `5`, false},
		{"minimum equal", prefix + `"type":"integer","minimum":-4}`, `-4`, true},
		{"minimum below", prefix + `"type":"integer","minimum":-4}`, `-5`, false},
		{"multiple", nested, `{"data":{"ids":[3]}}`, false},
		{"empty array", nested, `{"data":{"ids":[]}}`, false},
		{"duplicate number", nested, `{"data":{"ids":[2,2]}}`, false},
		{"canonical object duplicate", unique, `[{"a":1,"b":2},{"b":2,"a":1}]`, false},
		{"canonical object equal", unique, `[{"b":2,"a":1}]`, true},
		{"const array order", prefix + `"const":[1,2]}`, `[2,1]`, false},
		{"enum and const intersection", prefix + `"enum":[1,2],"const":2}`, `1`, false},
		{"nullable enum excludes null", prefix + `"type":["string","null"],"maxLength":2,"enum":["ok"]}`, `null`, false},
		{"unicode scalar length", prefix + `"type":"string","maxLength":1}`, `"é"`, true},
		{"too many scalars", prefix + `"type":"string","maxLength":1}`, `"éx"`, false},
		{"safe integer", prefix + `"type":"integer"}`, `-9007199254740991`, true},
		{"unsafe integer", prefix + `"type":"integer"}`, `-9007199254740992`, false},
		{"exponent token", prefix + `"type":"integer"}`, `1e0`, false},
		{"duplicate decoded key", prefix + `"const":{"a":1}}`, `{"a":1,"\u0061":1}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := externalschemasubset.ValidateSchema([]byte(tc.schema)); err != nil {
				t.Fatalf("vector schema rejected: %v", err)
			}
			err := externalschemasubset.Validate([]byte(tc.schema), []byte(tc.value), 65536)
			if tc.accepted && err != nil || !tc.accepted && !errors.Is(err, externalschemasubset.ErrValue) {
				t.Fatalf("value acceptance=%t, error=%v", tc.accepted, err)
			}
		})
	}
}

func TestResourceVectors(t *testing.T) {
	const schema = prefix + `"type":"string","maxLength":4096}`
	cases := []struct {
		name, value string
		limit       int
		accepted    bool
	}{
		{"canonical byte limit exact", `"é"`, 4, true},
		{"canonical byte limit exceeded", `"é"`, 3, false},
		{"raw cap exact", `"x"` + strings.Repeat(" ", 262141), 3, true},
		{"raw cap exceeded", `"x"` + strings.Repeat(" ", 262142), 3, false},
		{"string max exact", `"` + strings.Repeat("x", 4096) + `"`, 65536, true},
		{"string max exceeded", `"` + strings.Repeat("x", 4097) + `"`, 65536, false},
		{"invalid caller limit", `"x"`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := externalschemasubset.Validate([]byte(schema), []byte(tc.value), tc.limit)
			if tc.accepted && err != nil || !tc.accepted && !errors.Is(err, externalschemasubset.ErrValue) {
				t.Fatalf("value acceptance=%t, error=%v", tc.accepted, err)
			}
		})
	}
}
