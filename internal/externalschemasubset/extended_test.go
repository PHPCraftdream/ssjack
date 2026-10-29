package externalschemasubset

import (
	"errors"
	"testing"
)

func TestTypelessEnum(t *testing.T) {
	s := root + `"type":"object","properties":{"mode":{"enum":["ephemeral","persistent",null]},"n":{"enum":[1,2],"const":2}},"required":["mode","n"],"additionalProperties":false}`
	if err := ValidateSchema([]byte(s)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`{"mode":"ephemeral","n":2}`, true},
		{`{"mode":null,"n":2}`, true},
		{`{"mode":"other","n":2}`, false},
		{`{"mode":"persistent","n":1}`, false},
		{`{"mode":"persistent","n":2,"extra":true}`, false},
		{`{"mode":"persistent"}`, false},
	} {
		err := Validate([]byte(s), []byte(tc.value), 65536)
		if (err == nil) != tc.valid {
			t.Errorf("%s: %v", tc.value, err)
		}
	}
	for _, x := range []string{
		`"enum":[]`, `"enum":[1,1]`, `"enum":[1],"type":null`,
		`"enum":[1],"type":""`, `"enum":[1],"minimum":0`,
		`"enum":[1],"$ref":"x"`,
		`"enum":[1],"examples":{}`, `"enum":[1],"properties":{}`,
	} {
		if err := ValidateSchema([]byte(root + x + `}`)); !errors.Is(err, ErrSchema) {
			t.Errorf("accepted %s: %v", x, err)
		}
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`{"a":1,"b":2}`, true}, {`{"b":2,"a":1}`, true}, {`{"a":1}`, false},
	} {
		schema := root + `"enum":[{"b":2,"a":1}],"title":"annotation"}`
		err := Validate([]byte(schema), []byte(tc.value), 65536)
		if (err == nil) != tc.valid {
			t.Errorf("root enum %s: %v", tc.value, err)
		}
	}
}

func TestTypelessConst(t *testing.T) {
	for _, tc := range []struct {
		constant, equal, different string
	}{
		{`null`, `null`, `false`},
		{`false`, `false`, `0`},
		{`1`, `1`, `true`},
		{`"x"`, `"\u0078"`, `"y"`},
		{`[1,2]`, `[1,2]`, `[2,1]`},
		{`{"a":1,"b":[null]}`, `{"b":[null],"a":1}`, `{"a":1,"b":[]}`},
	} {
		s := root + `"const":` + tc.constant + `,"title":"t","default":null,"examples":[]}`
		if err := ValidateSchema([]byte(s)); err != nil {
			t.Errorf("const %s: %v", tc.constant, err)
		}
		if err := Validate([]byte(s), []byte(tc.equal), 65536); err != nil {
			t.Errorf("equal %s: %v", tc.equal, err)
		}
		if err := Validate([]byte(s), []byte(tc.different), 65536); !errors.Is(err, ErrValue) {
			t.Errorf("different %s: %v", tc.different, err)
		}
	}
	for _, x := range []string{
		`"const":null,"type":null`, `"const":1,"type":""`,
		`"const":1,"type":"unknown"`, `"const":1,"minimum":0`,
		`"const":[],"items":{"type":"null"}`, `"const":{},"properties":{}`,
		`"const":1,"$ref":"x"`, `"const":1,"allOf":[]`,
		`"const":1,"examples":{}`, `"const":1,"enum":[]`,
		`"const":1.0`, `"const":{"x":1,"x":1}`,
	} {
		s := root + x + `}`
		if !errors.Is(ValidateSchema([]byte(s)), ErrSchema) || !errors.Is(Validate([]byte(s), []byte(`1`), 100), ErrSchema) {
			t.Errorf("accepted schema %s", s)
		}
	}
	s := root + `"type":"array","items":{"const":{"x":null}},"maxItems":1}`
	if err := Validate([]byte(s), []byte(`[{"x":null}]`), 100); err != nil {
		t.Errorf("nested const: %v", err)
	}
	if !errors.Is(Validate([]byte(s), []byte(`[{"x":false}]`), 100), ErrValue) {
		t.Error("nested mismatch accepted")
	}
	for _, tc := range []struct {
		schema, value string
		limit         int
	}{
		{root + `"const":1,"enum":[2]}`, `1`, 100},
		{root + `"const":1}`, `1.0`, 100},
		{root + `"const":1}`, `1`, 0},
		{root + `"const":"abc"}`, `"abc"`, 4},
	} {
		if !errors.Is(Validate([]byte(tc.schema), []byte(tc.value), tc.limit), ErrValue) {
			t.Errorf("accepted value %s for %s", tc.value, tc.schema)
		}
	}
}

func TestTypelessFiniteObjectValues(t *testing.T) {
	for _, tc := range []struct {
		name, schema, equal, extra string
	}{
		{"root enum", root + `"enum":[{"a":{"x":1}}]}`, `{"a":{"x":1}}`, `{"a":{"x":1},"extra":true}`},
		{"root const", root + `"const":{"a":{"x":1}}}`, `{"a":{"x":1}}`, `{"a":{"x":1,"extra":true}}`},
		{"nested enum", root + `"type":"object","properties":{"v":{"enum":[{"x":1}]}},"required":["v"],"additionalProperties":false}`, `{"v":{"x":1}}`, `{"v":{"x":1,"extra":true}}`},
		{"nested const", root + `"type":"array","items":{"const":{"x":1}},"maxItems":1}`, `[{"x":1}]`, `[{"x":1,"extra":true}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSchema([]byte(tc.schema)); err != nil {
				t.Fatal(err)
			}
			if err := Validate([]byte(tc.schema), []byte(tc.equal), 65536); err != nil {
				t.Fatalf("exact value rejected: %v", err)
			}
			if err := Validate([]byte(tc.schema), []byte(tc.extra), 65536); !errors.Is(err, ErrValue) {
				t.Fatalf("extra property accepted: %v", err)
			}
		})
	}
}

func TestUntypedUnconstrainedRejected(t *testing.T) {
	for _, s := range []string{
		root + `"title":"open"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema"}`,
		root + `"type":"object","properties":{"v":{}},"required":["v"],"additionalProperties":false}`,
		root + `"type":"array","items":{"description":"open"},"maxItems":1}`,
	} {
		if err := ValidateSchema([]byte(s)); !errors.Is(err, ErrSchema) {
			t.Errorf("accepted unconstrained schema %s: %v", s, err)
		}
		if err := Validate([]byte(s), []byte(`{}`), 65536); !errors.Is(err, ErrSchema) {
			t.Errorf("Validate accepted unconstrained schema %s: %v", s, err)
		}
	}
}

func TestOmittedEmptyObjectKeywords(t *testing.T) {
	for _, shape := range []string{
		`"type":"object","additionalProperties":false`,
		`"type":"object","properties":{},"additionalProperties":false`,
		`"type":"object","required":[],"additionalProperties":false`,
		`"type":["object","null"],"additionalProperties":false`,
	} {
		s := root + shape + `}`
		if err := ValidateSchema([]byte(s)); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if err := Validate([]byte(s), []byte(`{}`), 100); err != nil {
			t.Fatalf("empty object rejected: %v", err)
		}
		if err := Validate([]byte(s), []byte(`{"extra":1}`), 100); !errors.Is(err, ErrValue) {
			t.Fatalf("extra property accepted: %v", err)
		}
	}
	nested := root + `"type":"object","properties":{"v":{"type":"object","additionalProperties":false}},"required":["v"],"additionalProperties":false}`
	if err := Validate([]byte(nested), []byte(`{"v":{}}`), 100); err != nil {
		t.Fatal(err)
	}
	if err := Validate([]byte(nested), []byte(`{"v":{"extra":true}}`), 100); !errors.Is(err, ErrValue) {
		t.Fatalf("nested extra accepted: %v", err)
	}
	for _, shape := range []string{
		`"type":"object"`,
		`"type":"object","properties":null,"additionalProperties":false`,
		`"type":"object","required":null,"additionalProperties":false`,
		`"type":"object","properties":{"x":{"type":"null"}},"additionalProperties":false`,
		`"type":"object","additionalProperties":true`,
	} {
		s := root + shape + `}`
		if err := ValidateSchema([]byte(s)); !errors.Is(err, ErrSchema) {
			t.Errorf("accepted %s: %v", s, err)
		}
	}
}

func TestExtendedShapes(t *testing.T) {
	bad := []string{
		`"type":["null","null"]`, `"type":["integer","boolean"]`, `"type":["integer","null","boolean"]`, `"type":["null",1]`, `"type":[]`,
		`"type":"integer","title":null`, `"type":"integer","description":3`, `"type":"integer","examples":{}`,
		`"type":"integer","multipleOf":0`, `"type":"integer","multipleOf":-2`, `"type":"integer","multipleOf":true`, `"type":"integer","exclusiveMinimum":false`, `"type":"integer","exclusiveMaximum":1.0`,
		`"type":"boolean","multipleOf":2`, `"type":["string","null"],"maxLength":4,"maximum":1`,
		`"type":["object","null"],"properties":{},"required":[],"additionalProperties":true`,
	}
	for _, x := range bad {
		s := root + x + `}`
		if !errors.Is(ValidateSchema([]byte(s)), ErrSchema) {
			t.Errorf("accepted %s", s)
		}
		if !errors.Is(Validate([]byte(s), []byte(`null`), 100), ErrSchema) {
			t.Errorf("Validate accepted schema %s", s)
		}
	}
}

func TestNullableAnnotationsAndNumbers(t *testing.T) {
	cases := []struct {
		schema, value string
		valid         bool
	}{
		{`"type":["null","integer"],"minimum":-4,"maximum":4,"exclusiveMinimum":-4,"exclusiveMaximum":4,"multipleOf":2`, `null`, true},
		{`"type":["integer","null"],"minimum":-4,"maximum":4,"exclusiveMinimum":-4,"exclusiveMaximum":4,"multipleOf":2`, `-2`, true},
		{`"type":["integer","null"],"exclusiveMinimum":-4,"exclusiveMaximum":4,"multipleOf":2`, `-4`, false},
		{`"type":["integer","null"],"exclusiveMinimum":-4,"exclusiveMaximum":4,"multipleOf":2`, `4`, false},
		{`"type":["integer","null"],"multipleOf":2`, `-3`, false},
		{`"type":"integer","multipleOf":9007199254740991`, `-9007199254740991`, true},
		{`"type":["string","null"],"maxLength":2,"enum":["x"],"const":"x","title":"t","description":"d","default":null,"examples":[123]`, `null`, false},
		{`"type":["string","null"],"maxLength":2,"enum":["x"],"const":"x","title":"t","description":"d","default":null,"examples":[123]`, `"x"`, true},
		{`"type":["object","null"],"properties":{"a":{"type":["array","null"],"items":{"type":"boolean"},"maxItems":1}},"required":["a"],"additionalProperties":false`, `{"a":[true]}`, true},
		{`"type":["object","null"],"properties":{"a":{"type":["array","null"],"items":{"type":"boolean"},"maxItems":1}},"required":["a"],"additionalProperties":false`, `{"a":[1]}`, false},
		{`"type":["object","null"],"properties":{},"required":[],"additionalProperties":false`, `null`, true},
		{`"type":["boolean","null"]`, `false`, true},
		{`"type":"integer","minimum":1,"exclusiveMaximum":1`, `1`, false},
	}
	for _, tc := range cases {
		s := root + tc.schema + `}`
		if err := ValidateSchema([]byte(s)); err != nil {
			t.Errorf("invalid schema %s: %v", s, err)
			continue
		}
		err := Validate([]byte(s), []byte(tc.value), 65536)
		if (err == nil) != tc.valid {
			t.Errorf("schema %s value %s: %v", s, tc.value, err)
		}
	}
}
