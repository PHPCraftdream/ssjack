package externalschemasubset

import (
	"errors"
	"strings"
	"testing"
)

const root = `{"$schema":"https://json-schema.org/draft/2020-12/schema",`

func TestSchemaRejections(t *testing.T) {
	cases := []string{
		`true`, `{}`, `{"$schema":[],"type":"null"}`, root + `"type":["string","null"],"maxLength":5}`,
		root + `"type":"object","properties":{},"required":[],"additionalProperties":[]}`,
		root + `"type":"string","maxLength":5,"pattern":"x"}`,
		root + `"type":"integer","multipleOf":2}`,
		root + `"type":"integer","minimum":false}`,
		root + `"type":"integer","minimum":3,"maximum":2}`,
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
		root + `"type":"integer","title":"ignored"}`,
		root + `"type":"integer","type":"boolean"}`,
		root + `"type":"integer","minimum":1.0}`,
	}
	for _, s := range cases {
		if !errors.Is(ValidateSchema([]byte(s)), ErrSchema) {
			t.Errorf("accepted schema %s", s)
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
