package externalschemasubset

import (
	"errors"
	"testing"
)

func TestUntypedClosedShape(t *testing.T) {
	s := root + `"properties":{"x":{"type":"integer"}},"required":["x"],"additionalProperties":false,"minProperties":1,"maxProperties":1}`
	if err := ValidateSchema([]byte(s)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`{"x":1}`, true}, {`null`, true}, {`false`, true}, {`42`, true}, {`"text"`, true}, {`[{}]`, true},
		{`{}`, false}, {`{"x":true}`, false}, {`{"x":1,"extra":2}`, false},
	} {
		err := Validate([]byte(s), []byte(tc.value), 65536)
		if (err == nil) != tc.valid {
			t.Errorf("%s: %v", tc.value, err)
		}
	}
}

func TestUntypedClosedFiniteAndNested(t *testing.T) {
	s := root + `"type":"array","items":{"additionalProperties":false,"properties":{"v":{"additionalProperties":false}},"required":["v"],"enum":[{"v":{}},null,3],"const":{"v":{}}},"maxItems":2}`
	if err := ValidateSchema([]byte(s)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`[{"v":{}}]`, true}, {`[]`, true}, {`[null]`, false}, {`[3]`, false},
		{`[{"v":{"extra":1}}]`, false}, {`[{"v":{},"extra":1}]`, false}, {`[{}]`, false},
	} {
		err := Validate([]byte(s), []byte(tc.value), 65536)
		if (err == nil) != tc.valid {
			t.Errorf("%s: %v", tc.value, err)
		}
	}
	unrestricted := root + `"type":"object","properties":{"v":{"additionalProperties":false}},"required":["v"],"additionalProperties":false}`
	for _, value := range []string{`{"v":null}`, `{"v":[1]}`, `{"v":{}}`} {
		if err := Validate([]byte(unrestricted), []byte(value), 65536); err != nil {
			t.Errorf("%s: %v", value, err)
		}
	}
}

func TestExtraRequiredNames(t *testing.T) {
	cases := []struct {
		shape string
		pass  []string
		fail  []string
	}{
		{`"type":"object","properties":{},"required":["x"],"additionalProperties":false`, nil, []string{`{}`, `{"x":1}`, `null`}},
		{`"type":"object","properties":{"a":{"type":"integer"}},"required":["x","a"],"additionalProperties":false`, nil, []string{`{"a":1}`, `{"a":1,"x":2}`}},
		{`"additionalProperties":false,"required":["x"]`, []string{`null`, `1`, `[]`, `"x"`}, []string{`{}`, `{"x":1}`}},
		{`"type":["object","null"],"required":["x"],"additionalProperties":false`, []string{`null`}, []string{`{}`, `{"x":1}`, `1`}},
		{`"additionalProperties":false,"required":["x"],"enum":[null,1]`, []string{`null`, `1`}, []string{`false`, `{}`, `{"x":1}`}},
		{`"type":"array","items":{"additionalProperties":false,"required":["x"]},"maxItems":2`, []string{`[null,1]`}, []string{`[{}]`, `[{"x":1}]`}},
	}
	for _, tc := range cases {
		s := root + tc.shape + `}`
		if err := ValidateSchema([]byte(s)); err != nil {
			t.Errorf("schema %s: %v", s, err)
			continue
		}
		for _, value := range tc.pass {
			if err := Validate([]byte(s), []byte(value), 65536); err != nil {
				t.Errorf("schema %s value %s: %v", s, value, err)
			}
		}
		for _, value := range tc.fail {
			if err := Validate([]byte(s), []byte(value), 65536); !errors.Is(err, ErrValue) {
				t.Errorf("schema %s value %s: got %v, want ErrValue", s, value, err)
			}
		}
	}
}

func TestExtraRequiredInvalidShapes(t *testing.T) {
	for _, shape := range []string{
		`"type":"object","properties":{"a":{"type":"null"}},"required":["x"],"additionalProperties":false`,
		`"additionalProperties":false,"properties":{"a":{"type":"null"}},"required":["x","x"]`,
		`"additionalProperties":false,"required":["x","\u0078"]`,
		`"additionalProperties":false,"required":["x",1]`,
		`"additionalProperties":false,"required":["x"],"unknown":true`,
	} {
		s := root + shape + `}`
		if err := ValidateSchema([]byte(s)); !errors.Is(err, ErrSchema) {
			t.Errorf("schema %s: got %v, want ErrSchema", s, err)
		}
		if err := Validate([]byte(s), []byte(`null`), 65536); !errors.Is(err, ErrSchema) {
			t.Errorf("Validate %s: got %v, want ErrSchema", s, err)
		}
	}
}

func TestUntypedClosedReversedBounds(t *testing.T) {
	s := []byte(root + `"additionalProperties":false,"minProperties":2,"maxProperties":1}`)
	if err := ValidateSchema(s); err != nil {
		t.Fatalf("schema rejected: %v", err)
	}
	if err := Validate(s, []byte(`{}`), 65536); !errors.Is(err, ErrValue) {
		t.Errorf("object: got %v, want ErrValue", err)
	}
	for _, value := range []string{`null`, `true`, `[]`} {
		if err := Validate(s, []byte(value), 65536); err != nil {
			t.Errorf("non-object %s rejected: %v", value, err)
		}
	}
}

func TestUntypedClosedRejections(t *testing.T) {
	for _, shape := range []string{
		`"properties":{}`, `"additionalProperties":true`, `"additionalProperties":{}`,
		`"additionalProperties":false,"type":null`, `"additionalProperties":false,"type":""`,
		`"additionalProperties":false,"properties":null`, `"additionalProperties":false,"required":null`,
		`"additionalProperties":false,"properties":{"x":{"type":"null"}}`,
		`"additionalProperties":false,"minProperties":129`,
		`"additionalProperties":false,"items":false,"maxItems":1`,
		`"additionalProperties":false,"items":{"type":"null"}`, `"additionalProperties":false,"maxItems":1`,
		`"additionalProperties":false,"uniqueItems":true`, `"additionalProperties":false,"multipleOf":2`,
		`"enum":[1],"minimum":0`, `"const":1,"properties":{}`, `"enum":[null],"additionalProperties":true`,
		`"additionalProperties":false,"maxLength":0`, `"additionalProperties":false,"minimum":null`,
		`"additionalProperties":false,"$ref":"x"`, `"additionalProperties":false,"enum":[]`,
		`"additionalProperties":false,"properties":{"x":{}},"required":["x"]`,
	} {
		s := root + shape + `}`
		if err := ValidateSchema([]byte(s)); !errors.Is(err, ErrSchema) {
			t.Errorf("accepted %s: %v", s, err)
		}
		if err := Validate([]byte(s), []byte(`null`), 100); !errors.Is(err, ErrSchema) {
			t.Errorf("Validate accepted %s: %v", s, err)
		}
	}
}

func TestTypedMismatchedContainerKeywords(t *testing.T) {
	cases := []struct {
		shape, value string
		valid        bool
	}{
		{`"type":"boolean","properties":{"x":{"type":"integer"}},"required":["x"],"additionalProperties":true,"items":{"type":"null"},"maxItems":1`, `true`, true},
		{`"type":"boolean","properties":{"x":{"type":"integer"}},"additionalProperties":false`, `{}`, false},
		{`"type":["null","array"],"maxItems":1,"items":{"type":"integer"},"properties":{"x":{"type":"null"}},"required":["x"],"additionalProperties":true`, `null`, true},
		{`"type":"array","maxItems":1,"items":{"type":"integer"},"minProperties":2`, `[1]`, true},
		{`"type":"array","maxItems":1,"items":{"type":"integer"},"minProperties":2`, `[1,2]`, false},
		{`"type":"object","additionalProperties":false,"items":{"type":"null"},"maxItems":0`, `{}`, true},
		{`"type":"object","additionalProperties":false,"items":{"type":"null"},"maxItems":0`, `{"x":1}`, false},
		{`"type":["boolean","null"],"enum":[true],"items":{"type":"null"}`, `null`, false},
		{`"type":"array","maxItems":1,"items":{"type":"boolean","properties":{"x":{"type":"null"}}}`, `[true]`, true},
	}
	for _, tc := range cases {
		s := []byte(root + tc.shape + `}`)
		if err := ValidateSchema(s); err != nil {
			t.Errorf("schema %s: %v", tc.shape, err)
			continue
		}
		err := Validate(s, []byte(tc.value), 65536)
		if tc.valid && err != nil || !tc.valid && !errors.Is(err, ErrValue) {
			t.Errorf("schema %s value %s: %v", tc.shape, tc.value, err)
		}
	}
}

func TestMismatchedContainerRejections(t *testing.T) {
	for _, shape := range []string{
		`"type":"boolean","properties":null`,
		`"type":"boolean","properties":{"x":true}`,
		`"type":"boolean","properties":{"x":{"type":"null","$ref":"x"}}`,
		`"type":"boolean","properties":{"x":{"type":"array","maxItems":1}}`,
		`"type":"boolean","required":["x","\u0078"]`,
		`"type":"boolean","required":[1]`,
		`"type":"boolean","additionalProperties":{}`,
		`"type":"boolean","minProperties":129`,
		`"type":"boolean","items":false`,
		`"type":"boolean","items":{"type":"null","allOf":[]}`,
		`"type":"boolean","items":{"type":"object","additionalProperties":true}`,
		`"type":"boolean","maxItems":257`,
		`"type":"boolean","uniqueItems":1`,
		`"type":"object","additionalProperties":true,"items":{"type":"null"}`,
		`"type":"array","items":{"type":"null"},"properties":{}`,
		`"type":"array","maxItems":1,"items":{"type":"boolean","items":{}}`,
	} {
		s := []byte(root + shape + `}`)
		if !errors.Is(ValidateSchema(s), ErrSchema) || !errors.Is(Validate(s, []byte(`true`), 65536), ErrSchema) {
			t.Errorf("invalid schema accepted: %s", shape)
		}
	}
}
