package driverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func pinned(schema string) ([]byte, string) {
	b := []byte(schema)
	v, e := ParseJSON(b)
	if e != nil {
		panic(e)
	}
	c, e := canonicalBytes(v)
	if e != nil {
		panic(e)
	}
	h := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), c...))
	return b, hex.EncodeToString(h[:])
}
func TestPinnedSemanticValidation(t *testing.T) {
	b, d := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"n":{"type":"integer","minimum":0,"maximum":4}},"required":["n"],"additionalProperties":false}`)
	if e := ValidatePinnedValue(b, "cache.desired", d, "target", "kind", "target", "kind", "cache.desired", []byte(`{"n":2}`), 32768); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ id, digest, value string }{{"other", d, `{"n":2}`}, {"cache.desired", "00", `{"n":2}`}, {"cache.desired", d, `{"n":5}`}, {"cache.desired", d, `{"n":2,"extra":0}`}} {
		if ValidatePinnedValue(b, "cache.desired", tc.digest, "target", "kind", "target", "kind", tc.id, []byte(tc.value), 32768) == nil {
			t.Fatal("accepted invalid identity/digest/value")
		}
	}
}
func TestSchemaRejectsIgnoredAndNestedKeywords(t *testing.T) {
	cases := []struct{ schema, value string }{{`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","pattern":"x","maxLength":10}`, `"x"`}, {`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"x":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":10}},"required":["x"],"additionalProperties":false}`, `{"x":"ok"}`}}
	for _, tc := range cases {
		b, d := pinned(tc.schema)
		if ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(tc.value), 32768) == nil {
			t.Fatal("accepted invalid schema")
		}
	}
}
func TestPinnedRequestAndCorrelatedProjection(t *testing.T) {
	b, d := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}`)
	observe := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":1000,"operation_id":null}`)
	q, e := ValidateStructuralRequest(observe)
	if e != nil {
		t.Fatal(e)
	}
	response := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":null,"projection":{"ok":true}}}`)
	if _, e = ValidatePinnedProjection(q, response, b, "cache.desired", "cache.projection", d, "other", "kind", "cache.projection"); e == nil {
		t.Fatal("accepted target correlation mismatch")
	}
	if _, e = ValidatePinnedProjection(q, response, b, "cache.desired", "cache.projection", d, "target", "kind", "cache.projection"); e != nil {
		t.Fatal(e)
	}
	mismatchedResponse := []byte(strings.Replace(string(response), "AAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBB", 1))
	if _, e = ValidatePinnedProjection(q, mismatchedResponse, b, "cache.desired", "cache.projection", d, "target", "kind", "cache.projection"); e == nil {
		t.Fatal("accepted response correlation mismatch")
	}
	bad := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":null,"projection":{"ok":true,"leak":"x"}}}`)
	if _, e = ValidatePinnedProjection(q, bad, b, "cache.desired", "cache.projection", d, "target", "kind", "cache.projection"); e == nil {
		t.Fatal("accepted invalid projection")
	}
	plan := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"plan","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":{"ok":true},"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":1000,"operation_id":null}`)
	if _, e = ValidatePinnedRequest(plan, b, "cache.desired", d, "target", "kind"); e != nil {
		t.Fatal(e)
	}
}

func TestSchemaMaxLengthZero(t *testing.T) {
	b, d := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":0}`)
	if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(`""`), 32768); err != ErrSchema {
		t.Fatalf("maxLength zero: got %v, want ErrSchema", err)
	}
}

func TestSchemaBoundAdversaries(t *testing.T) {
	cases := []struct {
		name       string
		valid      string
		contradict string
	}{
		{name: "array item bounds", valid: `{"type":"array","items":{"type":"integer"},"minItems":1,"maxItems":3}`, contradict: `{"type":"array","items":{"type":"integer"},"minItems":3,"maxItems":1}`},
		{name: "string length bounds", valid: `{"type":"string","minLength":1,"maxLength":3}`, contradict: `{"type":"string","minLength":3,"maxLength":1}`},
		{name: "integer bounds", valid: `{"type":"integer","minimum":1,"maximum":3}`, contradict: `{"type":"integer","minimum":3,"maximum":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := ParseJSON([]byte(tc.valid))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSchema(valid, false, 0); err != nil {
				t.Fatalf("valid baseline rejected: %v", err)
			}
			invalid, err := ParseJSON([]byte(tc.contradict))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSchema(invalid, false, 0); err != ErrSchema {
				t.Fatalf("contradictory bounds: got %v, want ErrSchema", err)
			}
		})
	}
}

func TestSchemaKeywordShapesAndTypes(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	cases := []struct{ good, bad string }{
		{`"type":"object","properties":{},"required":[],"additionalProperties":false`, `"type":"object","properties":{},"required":[],"additionalProperties":null`},
		{`"type":"array","items":{"type":"null"},"maxItems":2`, `"type":"array","items":null,"maxItems":2`},
		{`"type":"string","maxLength":2`, `"type":"string","maxLength":"2"`},
		{`"type":"integer","minimum":0`, `"type":"integer","minimum":null`},
		{`"type":"boolean"`, `"type":"boolean","items":{"type":"null"}`},
		{`"type":"null"`, `"type":"null","properties":{}`},
	}
	for _, tc := range cases {
		for _, item := range []struct {
			raw  string
			want error
		}{{root + tc.good + `}`, nil}, {root + tc.bad + `}`, ErrSchema}} {
			v, err := ParseJSON([]byte(item.raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := validateSchema(v, true, 0); got != item.want {
				t.Errorf("%s: got %v want %v", item.raw, got, item.want)
			}
		}
	}
	for _, raw := range []string{`{"type":"string","maxLength":1,"$ref":"#"}`, `{"type":"string","maxLength":1,"$vocabulary":{}}`, `{"type":"array","items":{"type":"integer"},"maxItems":2,"uniqueItems":true}`, `{"type":["null","string"]}`, `{"type":"number"}`, `{"type":"object","properties":{},"required":null,"additionalProperties":false}`} {
		v, err := ParseJSON([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if validateSchema(v, false, 0) != ErrSchema {
			t.Errorf("accepted unsupported/malformed schema %s", raw)
		}
	}
}

func TestSchemaEnumConstTypedEquality(t *testing.T) {
	for _, raw := range []string{`{"type":"integer","enum":[1,1]}`, `{"type":"boolean","enum":[true,true]}`, `{"type":"null","enum":[null,null]}`} {
		v, _ := ParseJSON([]byte(raw))
		if validateSchema(v, false, 0) != ErrSchema {
			t.Errorf("accepted duplicate enum: %s", raw)
		}
	}
	v, _ := ParseJSON([]byte(`{"type":"string","const":"x","maxLength":1}`))
	if !matches(v, "x", 0) || matches(v, "y", 0) {
		t.Fatal("const mismatch")
	}
}

func TestSchemaValueBoundsAndTextAdversaries(t *testing.T) {
	for _, raw := range []string{`"a\u0080"`, `"\n"`, `"\u0001"`, `"\ud800"`, `"\udc00"`} {
		if _, err := ParseJSON([]byte(raw)); err == nil {
			t.Errorf("accepted invalid text %s", raw)
		}
	}
	v, _ := ParseJSON([]byte(`{"type":"string","maxLength":1}`))
	for _, raw := range []string{`"é"`, `"\ud83d\ude00"`} {
		x, err := ParseJSON([]byte(raw))
		if err != nil || !matches(v, x, 0) {
			t.Errorf("valid scalar rejected %s: %v", raw, err)
		}
	}
	deepSchema := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":1,"const":"x"}`
	for i := 0; i < 18; i++ {
		deepSchema = strings.Replace(deepSchema, `"const":"x"`, `"const":{"type":"string","maxLength":1,"const":"x"}`, 1)
	}
	if _, err := ParseJSON([]byte(deepSchema)); err == nil {
		t.Fatal("accepted excessive schema depth")
	}
	manyNodes := `[` + strings.TrimSuffix(strings.Repeat(`[`+strings.TrimSuffix(strings.Repeat(`0,`, 256), ",")+`],`, 17), ",") + `]`
	if _, err := ParseJSON([]byte(manyNodes)); err == nil {
		t.Fatal("accepted excessive JSON nodes")
	}
	if _, err := ParseJSON([]byte(`{"a":[0,1]}`)); err != nil {
		t.Fatalf("valid node-count baseline rejected: %v", err)
	}
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}`
	spaced := []byte(strings.Replace(canonical, `,`, ", "+strings.Repeat(" ", maxSchemaBytes/2), 1))
	_, digest := pinned(canonical)
	if err := ValidatePinnedValue(spaced, "x", digest, "t", "k", "t", "k", "x", []byte(`null`), 100); err != nil {
		t.Fatalf("valid whitespace-expanded schema rejected: %v", err)
	}
	if bounded([]any{int64(1), int64(2)}, 1) {
		t.Fatal("accepted excessive value nodes/bytes")
	}
	if !bounded([]any{int64(1)}, 3) {
		t.Fatal("rejected valid bounded baseline")
	}
}

func TestPinnedIdentityAndChangedSchemaDigest(t *testing.T) {
	b, d := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":3}`)
	htmlSchema, htmlDigest := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":3,"const":"<>&"}`)
	if err := ValidatePinnedValue(htmlSchema, "x", htmlDigest, "t", "k", "t", "k", "x", []byte(`"<>&"`), 100); err != ErrSchema {
		t.Fatalf("HTML-sensitive schema: got %v, want ErrSchema", err)
	}
	if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(`"ok"`), 100); err != nil {
		t.Fatalf("valid baseline rejected: %v", err)
	}
	changed := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":4}`)
	if !jsonEqual("<>&", "<>&") || string(mustCanonical(t, "<>&")) != `"\u003c\u003e\u0026"` {
		t.Fatal("HTML-sensitive canonical schema serialization changed")
	}
	for _, tc := range []struct {
		schema                                             []byte
		digest, target, kind, actualTarget, actualKind, id string
	}{
		{changed, d, "t", "k", "t", "k", "x"}, {b, d, "t", "k", "other", "k", "x"}, {b, d, "t", "k", "t", "other", "x"}, {b, d, "t", "k", "t", "k", "other"},
	} {
		if ValidatePinnedValue(tc.schema, "x", tc.digest, tc.target, tc.kind, tc.actualTarget, tc.actualKind, tc.id, []byte(`"ok"`), 100) == nil {
			t.Error("accepted changed digest or identity mismatch")
		}
	}
}

func mustCanonical(t *testing.T, v any) []byte {
	t.Helper()
	b, err := canonicalBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSchemaMaxLengthMustBePositive(t *testing.T) {
	for _, tc := range []struct {
		name, schema string
		want         error
	}{
		{name: "positive baseline", schema: `{"type":"string","maxLength":1}`},
		{name: "zero maximum", schema: `{"type":"string","maxLength":0}`, want: ErrSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseJSON([]byte(tc.schema))
			if err != nil {
				t.Fatal(err)
			}
			if got := validateSchema(v, false, 0); got != tc.want {
				t.Fatalf("validateSchema: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSchemaSevenArrayItemsAndValueTypes(t *testing.T) {
	array, ad := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array","items":{"type":"integer"},"maxItems":7}`)
	check := func(b []byte, d, value string, want bool) {
		t.Helper()
		err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(value), MaxDesired)
		if (err == nil) != want {
			t.Errorf("%s: got %v", value, err)
		}
	}
	check(array, ad, `[1,2,3,4,5,6,7]`, true)
	check(array, ad, `null`, false)
	check(array, ad, `[1,2,3,4,5,6,"7"]`, false)
	obj, od := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"items":{"type":"array","items":{"type":"integer"},"maxItems":7}},"required":["items"],"additionalProperties":false}`)
	check(obj, od, `{"items":[1,2,3,4,5,6,7]}`, true)
	bad, bd := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"required":[],"additionalProperties":false,"items":7}`)
	if err := ValidatePinnedValue(bad, "x", bd, "t", "k", "t", "k", "x", []byte(`{}`), MaxDesired); err != ErrSchema {
		t.Fatalf("numeric object items keyword: got %v, want ErrSchema", err)
	}
}

func TestSchemaEnumEqualityAndLimit(t *testing.T) {
	v, _ := ParseJSON([]byte(`{"type":"integer","enum":[1,true]}`))
	if !jsonEqual(int64(1), int64(1)) || jsonEqual(int64(1), true) || !matches(v, int64(1), 0) || matches(v, false, 0) {
		t.Fatal("enum equality lost JSON type distinctions")
	}
	a := make([]any, 257)
	for i := range a {
		a[i] = int64(i)
	}
	if validateSchema(map[string]any{"type": "integer", "enum": a}, false, 0) != ErrSchema {
		t.Fatal("accepted enum above bound")
	}
}

func TestPinnedNullableEmptyArrayIndependentDigest(t *testing.T) {
	schema := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":["null","array"],"maxItems":0}`)
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","maxItems":0,"type":["null","array"]}`
	hash := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
	digest := hex.EncodeToString(hash[:])
	if err := ValidateSchemaDocument(schema, "x", digest); err != nil {
		t.Fatalf("schema and independent digest: %v", err)
	}
	for _, tc := range []struct {
		value string
		want  error
	}{{`null`, nil}, {`[]`, nil}, {`[null]`, ErrInvalid}} {
		if err := ValidatePinnedValue(schema, "x", digest, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
			t.Errorf("value %s: got %v, want %v", tc.value, err, tc.want)
		}
	}
	wrongHash := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical + " "))
	wrongDigest := hex.EncodeToString(wrongHash[:])
	if err := ValidateSchemaDocument(schema, "x", wrongDigest); err != ErrSchema {
		t.Errorf("wrong schema digest: got %v, want ErrSchema", err)
	}
	for _, tc := range []struct{ digest, actualID string }{{wrongDigest, "x"}, {digest, "other"}} {
		if err := ValidatePinnedValue(schema, "x", tc.digest, "t", "k", "t", "k", tc.actualID, []byte(`[]`), MaxDesired); err != ErrSchema {
			t.Errorf("digest %s, actual ID %s: got %v, want ErrSchema", tc.digest, tc.actualID, err)
		}
	}
}

func TestPinnedNullableSchemas(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	cases := []struct {
		name, schema   string
		accept, reject []string
	}{
		{"empty array", `"type":["null","array"],"maxItems":0`, []string{`null`, `[]`}, []string{`[null]`, `{}`}},
		{"array reversed", `"type":["array","null"],"items":{"type":"integer"},"maxItems":2`, []string{`null`, `[]`, `[1,2]`}, []string{`[null]`, `[1,2,3]`}},
		{"string", `"type":["string","null"],"maxLength":2`, []string{`null`, `"é"`}, []string{`"abc"`, `1`}},
		{"integer", `"type":["null","integer"],"minimum":1,"maximum":2`, []string{`null`, `1`}, []string{`0`, `true`}},
		{"boolean", `"type":["boolean","null"]`, []string{`null`, `true`}, []string{`0`}},
		{"nested object", `"type":["object","null"],"properties":{"a":{"type":["null","array"],"maxItems":1,"items":{"type":["string","null"],"maxLength":1}}},"required":["a"],"additionalProperties":false`, []string{`null`, `{"a":null}`, `{"a":[null]}`, `{"a":["x"]}`}, []string{`{}`, `{"a":["xx"]}`, `{"a":[],"b":1}`}},
		{"enum null", `"type":["null","integer"],"enum":[1]`, []string{`1`}, []string{`null`, `2`}},
		{"const null", `"type":["integer","null"],"const":null`, []string{`null`}, []string{`1`}},
		{"enum const intersection", `"type":["null","integer"],"enum":[null,1],"const":1`, []string{`1`}, []string{`null`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, d := pinned(root + tc.schema + `}`)
			if err := ValidateSchemaDocument(b, "x", d); err != nil {
				t.Fatalf("schema rejected: %v", err)
			}
			for _, values := range []struct {
				list []string
				want bool
			}{{tc.accept, true}, {tc.reject, false}} {
				for _, value := range values.list {
					err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(value), MaxDesired)
					if (err == nil) != values.want {
						t.Errorf("value %s: %v", value, err)
					}
				}
			}
		})
	}
}

func TestPinnedNullableInvalidSchemas(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	for _, schema := range []string{
		`"type":[]`, `"type":["null"]`, `"type":["null","null"]`,
		`"type":["string","integer"]`, `"type":["null","number"]`,
		`"type":["null","boolean","integer"]`, `"type":["null",1]`,
		`"type":["null","string"]`, `"type":["null","array"]`,
		`"type":"array","maxItems":1`, `"type":["null","array"],"maxItems":1`,
		`"type":"array","maxItems":null`, `"type":"array","maxItems":"0"`,
		`"type":"array","maxItems":-1`, `"type":"array","maxItems":0,"items":null`,
		`"type":["null","array"],"maxItems":0,"items":{"type":"string"}`,
		`"type":["null","array"],"minItems":1,"maxItems":0`,
		`"type":["null","boolean"],"maxItems":0`,
	} {
		b, d := pinned(root + schema + `}`)
		if err := ValidateSchemaDocument(b, "x", d); err != ErrSchema {
			t.Errorf("schema %s: got %v, want ErrSchema", schema, err)
		}
	}
}
