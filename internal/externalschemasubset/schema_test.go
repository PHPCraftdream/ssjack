package externalschemasubset

import (
	"errors"
	"strings"
	"testing"
)

const root = `{"$schema":"https://json-schema.org/draft/2020-12/schema",`

func TestSchemaRejections(t *testing.T) {
	cases := []string{
		`true`, `{}`, `{"$schema":[],"type":"null"}`, root + `"type":["string"],"maxLength":5}`,
		root + `"type":"object","properties":{},"required":[],"additionalProperties":[]}`,
		root + `"type":"string","maxLength":5,"pattern":"x"}`,
		root + `"type":"integer","minimum":false}`,
		root + `"type":"string","maxLength":0}`,
		root + `"type":"array","items":true,"maxItems":1}`,
		root + `"type":"array","items":{"type":"null"},"maxItems":257}`,
		root + `"type":"array","items":{"type":"null"},"maxItems":1,"uniqueItems":1}`,
		root + `"type":"object","properties":{"a":{"type":"null"}},"required":[],"additionalProperties":false}`,
		root + `"type":"object","properties":{"a":{"type":"null"}},"required":["a","a"],"additionalProperties":false}`,
		root + `"type":"object","properties":{},"required":[],"additionalProperties":{}}`,
		root + `"type":"array","items":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"},"maxItems":1}`,
		root + `"type":"integer","enum":[1,1]}`,
		root + `"type":"integer","enum":null}`,
		root + `"type":"integer","type":"boolean"}`,
		root + `"type":"integer","minimum":1.0}`,
	}
	for _, s := range cases {
		if !errors.Is(ValidateSchema([]byte(s)), ErrSchema) {
			t.Errorf("accepted schema %s", s)
		}
	}
}

func TestReversedBoundPairs(t *testing.T) {
	cases := []struct {
		name, shape, below, above, accepted string
	}{
		{"object", `"type":"object","properties":{"x":{"type":"null"}},"required":["x"],"additionalProperties":false,"minProperties":1,"maxProperties":0`, `{}`, `{"x":null}`, ``},
		{"array", `"type":"array","items":{"type":"null"},"minItems":1,"maxItems":0`, `[]`, `[null]`, ``},
		{"string", `"type":"string","minLength":2,"maxLength":1`, `"a"`, `"ab"`, ``},
		{"integer", `"type":"integer","minimum":3,"maximum":2`, `2`, `3`, ``},
		{"nullable", `"type":["integer","null"],"minimum":3,"maximum":2`, `2`, `3`, `null`},
		{"untyped object", `"properties":{"x":{"type":"null"}},"required":["x"],"additionalProperties":false,"minProperties":1,"maxProperties":0`, `{}`, `{"x":null}`, `true`},
		{"nested nullable", `"type":"array","items":{"type":["string","null"],"minLength":2,"maxLength":1},"maxItems":1`, `["a"]`, `["ab"]`, `[null]`},
		{"equal bounds", `"type":"integer","minimum":2,"maximum":2`, `1`, `3`, `2`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := []byte(root + tc.shape + `}`)
			if err := ValidateSchema(s); err != nil {
				t.Fatalf("schema rejected: %v", err)
			}
			for _, value := range []string{tc.below, tc.above} {
				if err := Validate(s, []byte(value), 65536); !errors.Is(err, ErrValue) {
					t.Errorf("expected rejection of %s: %v", value, err)
				}
			}
			if tc.accepted != "" {
				if err := Validate(s, []byte(tc.accepted), 65536); err != nil {
					t.Fatalf("valid value rejected: %v", err)
				}
			}
		})
	}
}

func TestReversedPairsStillEnforceIndividualBounds(t *testing.T) {
	for _, shape := range []string{
		`"type":"object","additionalProperties":false,"minProperties":129,"maxProperties":0`,
		`"type":"array","items":{"type":"null"},"minItems":257,"maxItems":0`,
		`"type":"string","minLength":2,"maxLength":0`,
		`"type":"integer","minimum":9007199254740992,"maximum":0`,
		`"type":"integer","minimum":3,"maximum":2,"multipleOf":0`,
	} {
		s := []byte(root + shape + `}`)
		if err := ValidateSchema(s); !errors.Is(err, ErrSchema) {
			t.Errorf("accepted invalid schema %s: %v", s, err)
		}
		if err := Validate(s, []byte(`null`), 65536); !errors.Is(err, ErrSchema) {
			t.Errorf("Validate accepted invalid schema %s: %v", s, err)
		}
	}
}

func TestValues(t *testing.T) {
	s := root + `"type":"object","properties":{"name":{"type":"string","minLength":1,"maxLength":2},"numbers":{"type":"array","items":{"type":"integer","minimum":0,"maximum":3},"minItems":1,"maxItems":2,"uniqueItems":true}},"required":["name","numbers"],"additionalProperties":false}`
	if err := ValidateSchema([]byte(s)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		v     string
		valid bool
	}{
		{`{"name":"é","numbers":[0,3]}`, true},
		{`{"name":"abc","numbers":[1]}`, false},
		{`{"name":"","numbers":[1]}`, false},
		{`{"name":"a","numbers":[1,1]}`, false},
		{`{"name":"a","numbers":[4]}`, false},
		{`{"name":"a","numbers":[]}`, false},
		{`{"name":"a","numbers":[1],"extra":true}`, false},
		{`{"name":"a"}`, false},
		{`{"name":"a","name":"b","numbers":[1]}`, false},
		{`{"name":"a","numbers":[1.0]}`, false},
		{`{"name":"\u0065\u0301","numbers":[1]}`, false},
	}
	for _, tc := range cases {
		err := Validate([]byte(s), []byte(tc.v), 32768)
		if (err == nil) != tc.valid {
			t.Errorf("value %s: %v", tc.v, err)
		}
	}
	if !errors.Is(Validate([]byte(s), []byte(`{}`), 0), ErrValue) {
		t.Error("invalid limit accepted")
	}
	if !errors.Is(Validate([]byte(s), []byte(`{"name":"a","numbers":[1]}`), 5), ErrValue) {
		t.Error("byte limit ignored")
	}
	if !errors.Is(Validate([]byte(`{}`), []byte(`null`), 100), ErrSchema) {
		t.Error("invalid schema accepted")
	}
}

func TestZeroMaxItemsWithoutItems(t *testing.T) {
	cases := []struct {
		name, shape    string
		valid, invalid []string
	}{
		{"array", `"type":"array","maxItems":0`, []string{`[]`}, []string{`[null]`, `null`, `{}`}},
		{"nullable", `"type":["null","array"],"maxItems":0`, []string{`[]`, `null`}, []string{`[1]`}},
		{"nested closed object", `"type":"object","properties":{"a":{"type":"array","maxItems":0}},"required":["a"],"additionalProperties":false`, []string{`{"a":[]}`}, []string{`{"a":[1]}`, `{"a":[],"extra":true}`, `{}`}},
		{"nested array", `"type":"array","items":{"type":["array","null"],"maxItems":0},"maxItems":2`, []string{`[[],null]`}, []string{`[[1]]`}},
		{"contradictory minimum", `"type":"array","minItems":1,"maxItems":0`, nil, []string{`[]`, `[1]`}},
		{"present valid items", `"type":"array","items":{"type":"null"},"maxItems":0`, []string{`[]`}, []string{`[null]`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := []byte(root + tc.shape + `}`)
			if err := ValidateSchema(s); err != nil {
				t.Fatalf("schema rejected: %v", err)
			}
			for _, value := range tc.valid {
				if err := Validate(s, []byte(value), 65536); err != nil {
					t.Errorf("%s: %v", value, err)
				}
			}
			for _, value := range tc.invalid {
				if err := Validate(s, []byte(value), 65536); !errors.Is(err, ErrValue) {
					t.Errorf("%s: expected ErrValue, got %v", value, err)
				}
			}
		})
	}
}

func TestZeroMaxItemsSchemaRejections(t *testing.T) {
	for _, shape := range []string{
		`"type":"array"`, `"type":"array","maxItems":1`,
		`"type":["array","null"],"maxItems":1`,
		`"type":"array","maxItems":null`, `"type":"array","maxItems":false`,
		`"type":"array","maxItems":-1`, `"type":"array","maxItems":257`,
		`"type":"array","maxItems":0.0`, `"type":"array","maxItems":0,"minItems":257`,
		`"type":"array","maxItems":0,"items":null`, `"type":"array","maxItems":0,"items":true`,
		`"type":"array","maxItems":0,"items":[]`, `"type":"array","maxItems":0,"items":{}`,
		`"type":"array","maxItems":0,"items":{"type":"object","additionalProperties":true}`,
		`"type":"object","properties":{"a":{"type":"array","maxItems":0,"items":false}},"required":["a"],"additionalProperties":false`,
	} {
		s := []byte(root + shape + `}`)
		if err := ValidateSchema(s); !errors.Is(err, ErrSchema) {
			t.Errorf("accepted %s: %v", s, err)
		}
		if err := Validate(s, []byte(`[]`), 65536); !errors.Is(err, ErrSchema) {
			t.Errorf("Validate accepted %s: %v", s, err)
		}
	}
}

func TestEqualityAndBounds(t *testing.T) {
	s := root + `"type":"object","properties":{"x":{"type":"integer"}},"required":["x"],"additionalProperties":false,"enum":[{"x":1}],"const":{"x":1}}`
	if err := Validate([]byte(s), []byte(`{"x":1}`), 100); err != nil {
		t.Fatal(err)
	}
	if Validate([]byte(s), []byte(`{"x":2}`), 100) == nil {
		t.Fatal("enum/const ignored")
	}
	dup := root + `"type":"integer","enum":[{"a":1,"b":2},{"b":2,"a":1}]}`
	if ValidateSchema([]byte(dup)) == nil {
		t.Fatal("structurally duplicate enum accepted")
	}
	if Validate([]byte(root+`"type":"string","maxLength":4096}`), []byte(`"`+strings.Repeat("a", 4097)+`"`), 65536) == nil {
		t.Fatal("length ignored")
	}
	if Validate([]byte(root+`"type":"integer"}`), []byte(`9007199254740992`), 100) == nil {
		t.Fatal("unsafe integer accepted")
	}
}
