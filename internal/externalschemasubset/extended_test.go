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
		`"enum":[1],"$ref":"x"`, `"const":1`,
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
