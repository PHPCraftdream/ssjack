package driverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
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
func TestPinnedPropertyCounts(t *testing.T) {
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"maxProperties":1,"minProperties":1,"properties":{"a":{"type":"boolean"}},"required":["a"],"type":["object","null"]}`
	h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
	digest := hex.EncodeToString(h[:])
	if err := ValidateSchemaDocument([]byte(canonical), "x", digest); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		want  error
	}{{`null`, nil}, {`{"a":true}`, nil}, {`{}`, ErrInvalid}, {`{"a":true,"b":false}`, ErrInvalid}} {
		if err := ValidatePinnedValue([]byte(canonical), "x", digest, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
			t.Errorf("%s: %v, want %v", tc.value, err, tc.want)
		}
	}
	for _, key := range []string{"minProperties", "maxProperties"} {
		changed := []byte(strings.Replace(canonical, `"`+key+`":1`, `"`+key+`":0`, 1))
		if err := ValidateSchemaDocument(changed, "x", digest); err != ErrSchema {
			t.Errorf("stale %s schema pin: %v", key, err)
		}
		if err := ValidatePinnedValue(changed, "x", digest, "t", "k", "t", "k", "x", []byte(`null`), MaxDesired); err != ErrSchema {
			t.Errorf("stale %s value pin: %v", key, err)
		}
	}
}

func TestPinnedPropertyCountsKeywordShapesAndApplicability(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	shape := `"type":"object","properties":{},"required":[],"additionalProperties":false,`
	for _, key := range []string{"minProperties", "maxProperties"} {
		for _, value := range []string{`null`, `true`, `"1"`, `[]`, `{}`, `-1`, `129`, `1.0`, `9007199254740992`} {
			if _, err := CanonicalSchemaDocument([]byte(root + shape + `"` + key + `":` + value + `}`)); err != ErrSchema {
				t.Errorf("%s=%s: %v", key, value, err)
			}
		}
		for _, body := range []string{`"type":"boolean"`, `"type":["null","string"],"maxLength":1`, `"type":"array","maxItems":0`, `"type":"integer"`, `"type":"null"`, `"properties":{},"additionalProperties":false`, `"type":"object","required":[],"additionalProperties":false`} {
			if _, err := CanonicalSchemaDocument([]byte(root + body + `,"` + key + `":0}`)); err != nil {
				t.Errorf("%s on %s: %v", key, body, err)
			}
		}
	}
}

func TestPinnedPropertyCountEdges(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	makeObject := func(n int, bounds string) (string, string) {
		props, required, values := make([]string, n), make([]string, n), make([]string, n)
		for i := 0; i < n; i++ {
			key := strconv.Quote("k" + strconv.Itoa(i))
			props[i], required[i], values[i] = key+`:{"type":"null"}`, key, key+`:null`
		}
		return `"type":"object","properties":{` + strings.Join(props, ",") + `},"required":[` + strings.Join(required, ",") + `],"additionalProperties":false,` + bounds, `{` + strings.Join(values, ",") + `}`
	}
	for _, tc := range []struct {
		n      int
		bounds string
		want   error
	}{
		{0, `"minProperties":0,"maxProperties":0`, nil}, {0, `"minProperties":1`, ErrInvalid},
		{0, `"maxProperties":1`, nil}, {1, `"minProperties":0,"maxProperties":2`, nil},
		{127, `"minProperties":126,"maxProperties":128`, nil}, {128, `"minProperties":127`, nil},
		{127, `"minProperties":128`, ErrInvalid}, {128, `"minProperties":128,"maxProperties":128`, nil},
		{128, `"maxProperties":127`, ErrInvalid}, {1, `"minProperties":2,"maxProperties":0`, ErrInvalid},
	} {
		body, value := makeObject(tc.n, tc.bounds)
		b, d := pinned(root + body + `}`)
		if err := ValidateSchemaDocument(b, "x", d); err != nil {
			t.Errorf("%d %s schema: %v", tc.n, tc.bounds, err)
		}
		if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(value), MaxDesired); err != tc.want {
			t.Errorf("%d %s: %v, want %v", tc.n, tc.bounds, err, tc.want)
		}
	}
	inner, _ := makeObject(0, `"minProperties":1`)
	b, d := pinned(root + `"type":"object","properties":{"x":{` + inner + `}},"required":["x"],"additionalProperties":false}`)
	if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(`{"x":{}}`), MaxDesired); err != ErrInvalid {
		t.Errorf("nested count: %v", err)
	}
}

func TestPinnedUniqueItems(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	cases := []struct {
		name, schema   string
		accept, reject []string
	}{
		{"strings", `"type":"array","items":{"type":"string","maxLength":4},"minItems":1,"maxItems":3,"uniqueItems":true`, []string{`["a","b"]`}, []string{`[]`, `["a","\u0061"]`, `["a","b","c","d"]`, `[1]`}},
		{"false", `"type":"array","items":{"type":"integer"},"maxItems":2,"uniqueItems":false`, []string{`[1,1]`, `[]`}, []string{`[1,1,1]`, `[true]`}},
		{"omitted", `"type":"array","items":{"type":"integer"},"maxItems":2`, []string{`[1,1]`}, []string{`[1,true]`}},
		{"nullable", `"type":["null","array"],"items":{"type":["null","integer"]},"maxItems":3,"uniqueItems":true`, []string{`null`, `[]`, `[null,1]`}, []string{`[null,null]`, `[1,1]`, `[true,1]`}},
		{"empty", `"type":"array","maxItems":0,"uniqueItems":true`, []string{`[]`}, []string{`[null]`, `null`}},
		{"objects", `"type":"array","items":{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"string","maxLength":2}},"required":["a","b"],"additionalProperties":false},"maxItems":2,"uniqueItems":true`, []string{`[{"a":1,"b":"x"},{"a":2,"b":"x"}]`}, []string{`[{"a":1,"b":"x"},{"b":"\u0078","a":1}]`, `[{"a":1}]`}},
		{"nested", `"type":"array","items":{"type":"array","items":{"type":"integer"},"maxItems":2,"uniqueItems":true},"maxItems":2,"uniqueItems":true`, []string{`[[1,2],[2,1]]`, `[[],[1]]`}, []string{`[[1,2],[1,2]]`, `[[1,1]]`, `[[],[]]`}},
		{"enum const", `"type":"array","items":{"type":"integer"},"maxItems":2,"uniqueItems":true,"enum":[[1,2],[1,1]],"const":[1,2]`, []string{`[1,2]`}, []string{`[1,1]`, `[2,1]`}},
		{"enum independent", `"type":"array","items":{"type":"integer"},"maxItems":2,"uniqueItems":true,"enum":[[1,2],[1,1]]`, []string{`[1,2]`}, []string{`[2,1]`, `[1,1]`}},
		{"const independent", `"type":"array","items":{"type":"integer"},"maxItems":2,"uniqueItems":true,"const":[1,2]`, []string{`[1,2]`}, []string{`[2,1]`, `[1,1]`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, d := pinned(root + tc.schema + `}`)
			if err := ValidateSchemaDocument(b, "x", d); err != nil {
				t.Fatal(err)
			}
			for _, group := range []struct {
				values []string
				want   error
			}{{tc.accept, nil}, {tc.reject, ErrInvalid}} {
				for _, value := range group.values {
					if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(value), MaxDesired); err != group.want {
						t.Errorf("%s: got %v, want %v", value, err, group.want)
					}
				}
			}
			if err := ValidatePinnedValue(b, "x", strings.Repeat("0", 64), "t", "k", "t", "k", "x", []byte(`[]`), MaxDesired); err != ErrSchema {
				t.Errorf("wrong digest: %v", err)
			}
		})
	}
}

func TestPinnedUniqueItemsDistinctTypes(t *testing.T) {
	b, d := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array","items":{"type":["integer","null"],"enum":[1,null]},"maxItems":3,"uniqueItems":true}`)
	if err := ValidateSchemaDocument(b, "x", d); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		want  error
	}{{`[1,null]`, nil}, {`[1,1]`, ErrInvalid}, {`[null,null]`, ErrInvalid}, {`[1,"1"]`, ErrInvalid}, {`[1,true]`, ErrInvalid}} {
		if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.value, err, tc.want)
		}
	}
}

func TestPinnedUniqueItemsMalformed(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	for _, schema := range []string{
		`"type":"array","maxItems":0,"uniqueItems":null`, `"type":"array","maxItems":0,"uniqueItems":0`,
		`"type":"array","maxItems":0,"uniqueItems":"true"`, `"type":"array","maxItems":0,"uniqueItems":[]`,
		`"type":"array","maxItems":0,"uniqueItems":{}`,
		`"type":"array","maxItems":1,"items":{"type":"array","maxItems":0,"uniqueItems":null}`,
	} {
		b, d := pinned(root + schema + `}`)
		if err := ValidateSchemaDocument(b, "x", d); err != ErrSchema {
			t.Errorf("%s: got %v", schema, err)
		}
		if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(`[]`), MaxDesired); err != ErrSchema {
			t.Errorf("%s value: got %v", schema, err)
		}
	}
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
			if err := validateSchema(invalid, false, 0); err != nil {
				t.Fatalf("contradictory bounds rejected: %v", err)
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
		{`"type":"boolean"`, `"type":"boolean","items":false`},
		{`"type":"null"`, `"type":"null","properties":null`},
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
	for _, raw := range []string{`{"type":"string","maxLength":1,"$ref":"#"}`, `{"type":"string","maxLength":1,"$vocabulary":{}}`, `{"type":["null","string"]}`, `{"type":"number"}`, `{"type":"object","properties":{},"required":null,"additionalProperties":false}`} {
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
	htmlSchema := []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string","maxLength":3,"const":"<>&"}`)
	htmlCanonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","const":"<>&","maxLength":3,"type":"string"}`
	htmlHash := sha256.Sum256([]byte("ssjack-schema-v1\x00" + htmlCanonical))
	htmlDigest := hex.EncodeToString(htmlHash[:])
	if err := ValidatePinnedValue(htmlSchema, "x", htmlDigest, "t", "k", "t", "k", "x", []byte(`"<>&"`), 100); err != nil {
		t.Fatalf("HTML-sensitive schema: %v", err)
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
	} {
		b, d := pinned(root + schema + `}`)
		if err := ValidateSchemaDocument(b, "x", d); err != ErrSchema {
			t.Errorf("schema %s: got %v, want ErrSchema", schema, err)
		}
	}
}

func TestPinnedNumericConstraintsIndependentDigest(t *testing.T) {
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMaximum":5,"exclusiveMinimum":-5,"maximum":4,"minimum":-4,"multipleOf":2,"type":["null","integer"]}`
	h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
	digest := hex.EncodeToString(h[:])
	schema := []byte(`{"type":["null","integer"],"multipleOf":2,"minimum":-4,"maximum":4,"exclusiveMinimum":-5,"exclusiveMaximum":5,"$schema":"https://json-schema.org/draft/2020-12/schema"}`)
	if err := ValidateSchemaDocument(schema, "x", digest); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		want  error
	}{
		{`null`, nil}, {`-4`, nil}, {`0`, nil}, {`4`, nil},
		{`-5`, ErrInvalid}, {`5`, ErrInvalid}, {`-3`, ErrInvalid}, {`3`, ErrInvalid}, {`true`, ErrInvalid},
	} {
		if err := ValidatePinnedValue(schema, "x", digest, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.value, err, tc.want)
		}
	}
	changed := []byte(strings.Replace(string(schema), `"multipleOf":2`, `"multipleOf":1`, 1))
	if err := ValidatePinnedValue(changed, "x", digest, "t", "k", "t", "k", "x", []byte(`0`), MaxDesired); err != ErrSchema {
		t.Errorf("changed schema pin: %v", err)
	}
}

func TestPinnedNumericNestedAndSafeEdges(t *testing.T) {
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"n":{"items":{"exclusiveMaximum":9007199254740991,"exclusiveMinimum":-9007199254740991,"multipleOf":9007199254740991,"type":["integer","null"]},"maxItems":3,"type":"array"}},"required":["n"],"type":"object"}`
	h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
	digest := hex.EncodeToString(h[:])
	for _, tc := range []struct {
		value string
		want  error
	}{
		{`{"n":[null,0]}`, nil}, {`{"n":[9007199254740991]}`, ErrInvalid},
		{`{"n":[-9007199254740991]}`, ErrInvalid}, {`{"n":[1]}`, ErrInvalid},
	} {
		if err := ValidatePinnedValue([]byte(canonical), "x", digest, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.value, err, tc.want)
		}
	}
	canonical = `{"$schema":"https://json-schema.org/draft/2020-12/schema","multipleOf":9007199254740991,"type":"integer"}`
	h = sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
	digest = hex.EncodeToString(h[:])
	for _, tc := range []struct {
		value string
		want  error
	}{{`-9007199254740991`, nil}, {`9007199254740991`, nil}, {`9007199254740990`, ErrInvalid}} {
		if err := ValidatePinnedValue([]byte(canonical), "x", digest, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.value, err, tc.want)
		}
	}
}

func TestPinnedNumericIndependentKeywords(t *testing.T) {
	cases := []struct {
		name, canonical string
		accept, reject  []string
	}{
		{"minimum", `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMinimum":-2,"type":"integer"}`, []string{`-1`, `9007199254740991`}, []string{`-2`, `-3`}},
		{"maximum", `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMaximum":2,"type":"integer"}`, []string{`1`, `-9007199254740991`}, []string{`2`, `3`}},
		{"minimum safe low", `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMinimum":-9007199254740991,"type":["integer","null"]}`, []string{`null`, `-9007199254740990`}, []string{`-9007199254740991`}},
		{"minimum safe high", `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMinimum":9007199254740991,"type":"integer"}`, nil, []string{`9007199254740990`, `9007199254740991`}},
		{"maximum safe high", `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMaximum":9007199254740991,"type":["null","integer"]}`, []string{`null`, `9007199254740990`}, []string{`9007199254740991`}},
		{"maximum safe low", `{"$schema":"https://json-schema.org/draft/2020-12/schema","exclusiveMaximum":-9007199254740991,"type":"integer"}`, nil, []string{`-9007199254740990`, `-9007199254740991`}},
		{"multiple", `{"$schema":"https://json-schema.org/draft/2020-12/schema","multipleOf":2,"type":"integer"}`, []string{`-4`, `0`, `4`, `-9007199254740990`, `9007199254740990`}, []string{`-3`, `3`, `-9007199254740991`, `9007199254740991`}},
		{"enum intersection", `{"$schema":"https://json-schema.org/draft/2020-12/schema","enum":[null,-2,-1,0,2],"exclusiveMinimum":-2,"multipleOf":2,"type":["null","integer"]}`, []string{`null`, `0`, `2`}, []string{`-2`, `-1`, `4`}},
		{"const intersection", `{"$schema":"https://json-schema.org/draft/2020-12/schema","const":2,"exclusiveMaximum":2,"type":"integer"}`, nil, []string{`1`, `2`, `3`}},
		{"const accepted", `{"$schema":"https://json-schema.org/draft/2020-12/schema","const":2,"exclusiveMaximum":3,"type":"integer"}`, []string{`2`}, []string{`1`, `3`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + tc.canonical))
			digest := hex.EncodeToString(h[:])
			schema := []byte(tc.canonical)
			if err := ValidateSchemaDocument(schema, "x", digest); err != nil {
				t.Fatalf("schema: %v", err)
			}
			for _, group := range []struct {
				values []string
				want   error
			}{{tc.accept, nil}, {tc.reject, ErrInvalid}} {
				for _, value := range group.values {
					if err := ValidatePinnedValue(schema, "x", digest, "t", "k", "t", "k", "x", []byte(value), MaxDesired); err != group.want {
						t.Errorf("%s: got %v, want %v", value, err, group.want)
					}
				}
			}
		})
	}
}

func TestPinnedAnnotations(t *testing.T) {
	plain := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":["null","object"],"properties":{"v":{"type":"array","maxItems":1,"items":{"type":["string","null"],"maxLength":1}}},"required":["v"],"additionalProperties":false}`
	annotated := `{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"root","description":"text","default":{"arbitrary":[true,null,1]},"examples":[null,{},[1]],"type":["null","object"],"properties":{"v":{"title":"array","default":false,"type":"array","maxItems":1,"items":{"description":"item","examples":[42],"type":["string","null"],"maxLength":1}}},"required":["v"],"additionalProperties":false}`
	for _, schema := range []string{plain, annotated} {
		b, d := pinned(schema)
		if err := ValidateSchemaDocument(b, "x", d); err != nil {
			t.Fatalf("schema: %v", err)
		}
		for _, tc := range []struct {
			value string
			want  error
		}{
			{`null`, nil}, {`{"v":[null]}`, nil}, {`{"v":["x"]}`, nil},
			{`{"v":["xx"]}`, ErrInvalid}, {`{}`, ErrInvalid}, {`{"v":[42]}`, ErrInvalid},
		} {
			if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
				t.Errorf("%s: got %v, want %v", tc.value, err, tc.want)
			}
		}
	}
	_, digest := pinned(plain)
	if err := ValidateSchemaDocument([]byte(annotated), "x", digest); err != ErrSchema {
		t.Errorf("annotations must change digest: %v", err)
	}
	b, d := pinned(annotated)
	reordered := strings.Replace(annotated, `"title":"root","description":"text"`, `"description":"text","title":"root"`, 1)
	if err := ValidateSchemaDocument([]byte(reordered), "x", d); err != nil {
		t.Errorf("canonical key order: %v", err)
	}
	changed := strings.Replace(string(b), `"title":"root"`, `"title":"other"`, 1)
	if err := ValidateSchemaDocument([]byte(changed), "x", d); err != ErrSchema {
		t.Errorf("changed annotation pin: %v", err)
	}
}

func TestPinnedAnnotationConstraintIntersection(t *testing.T) {
	plain := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"n":{"type":"integer","enum":[1,2],"const":2}},"required":["n"],"additionalProperties":false}`
	annotated := `{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"root","type":"object","properties":{"n":{"description":"number","examples":[1,2],"type":"integer","enum":[1,2],"const":2}},"required":["n"],"additionalProperties":false}`
	for _, schema := range []struct{ name, raw string }{{"plain", plain}, {"annotated", annotated}} {
		t.Run(schema.name, func(t *testing.T) {
			b, d := pinned(schema.raw)
			for _, tc := range []struct {
				name, value string
				want        error
			}{
				{"intersection", `{"n":2}`, nil},
				{"enum only", `{"n":1}`, ErrInvalid},
				{"outside enum", `{"n":3}`, ErrInvalid},
				{"wrong type", `{"n":"2"}`, ErrInvalid},
				{"extra property", `{"n":2,"extra":true}`, ErrInvalid},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
						t.Errorf("got %v, want %v", err, tc.want)
					}
				})
			}
		})
	}
}

func TestPinnedAnnotationEnumIndependence(t *testing.T) {
	for _, annotation := range []string{"", `"default":3,"examples":[3],`} {
		schema := `{"$schema":"https://json-schema.org/draft/2020-12/schema",` + annotation + `"type":"integer","enum":[1,2]}`
		b, d := pinned(schema)
		for _, tc := range []struct {
			value string
			want  error
		}{{`1`, nil}, {`2`, nil}, {`3`, ErrInvalid}} {
			if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != tc.want {
				t.Errorf("annotation %q value %s: got %v, want %v", annotation, tc.value, err, tc.want)
			}
		}
	}
}

func TestPinnedMalformedAnnotationsWithMatchingValues(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	for _, tc := range []struct{ name, schema, value string }{
		{"title", `"type":"null","title":null`, `null`},
		{"description", `"type":"boolean","description":1`, `true`},
		{"examples", `"type":"integer","examples":{}`, `1`},
		{"nested", `"type":"object","properties":{"x":{"type":"boolean","examples":"bad"}},"required":["x"],"additionalProperties":false`, `{"x":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, d := pinned(root + tc.schema + `}`)
			if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(tc.value), MaxDesired); err != ErrSchema {
				t.Errorf("got %v, want ErrSchema", err)
			}
		})
	}
}

func TestPinnedAnnotationInvalidShapesAndBounds(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	for _, fragment := range []string{
		`"type":"null","title":null`, `"type":"boolean","description":1`,
		`"type":["null","integer"],"examples":null`, `"type":"integer","examples":{}`,
		`"type":"array","maxItems":0,"items":{"type":"null","title":false}`,
		`"type":["null","object"],"properties":{"x":{"type":"boolean","examples":"bad"}},"required":["x"],"additionalProperties":false`,
	} {
		b, d := pinned(root + fragment + `}`)
		if err := ValidateSchemaDocument(b, "x", d); err != ErrSchema {
			t.Errorf("%s: got %v", fragment, err)
		}
		if err := ValidatePinnedValue(b, "x", d, "t", "k", "t", "k", "x", []byte(`null`), MaxDesired); err != ErrSchema {
			t.Errorf("matching-independent rejection %s: %v", fragment, err)
		}
	}
	for _, fragment := range []string{
		`"default":` + `[` + strings.Repeat(`0,`, 256) + `0]`,
		`"examples":` + `[` + strings.Repeat(`null,`, 256) + `null]`,
		`"default":"` + strings.Repeat("x", 65536) + `"`,
		`"default":1.5`, `"examples":["\u0001"]`,
	} {
		if _, err := CanonicalSchemaDocument([]byte(root + `"type":"null",` + fragment + `}`)); err != ErrSchema {
			t.Errorf("unbounded or invalid annotation: %v", err)
		}
	}
}

func TestPinnedNumericInvalidSchemas(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	for _, fragment := range []string{
		`"type":"integer","multipleOf":0`, `"type":"integer","multipleOf":-1`,
		`"type":"integer","multipleOf":9007199254740992`, `"type":"integer","multipleOf":1.0`,
		`"type":"integer","multipleOf":null`, `"type":"integer","exclusiveMinimum":true`,
		`"type":"integer","exclusiveMaximum":-9007199254740992`, `"type":"integer","exclusiveMinimum":1.0`,
		`"type":"array","maxItems":1,"items":{"type":"integer","multipleOf":0}`,
		`"type":"array","maxItems":1,"items":{"type":"integer","multipleOf":9007199254740992}`,
		`"type":"object","properties":{"n":{"type":"integer","exclusiveMinimum":-9007199254740992}},"required":["n"],"additionalProperties":false`,
		`"type":"object","properties":{"n":{"type":"integer","exclusiveMaximum":9007199254740992}},"required":["n"],"additionalProperties":false`,
		`"type":"object","properties":{"n":{"type":"integer","exclusiveMaximum":false}},"required":["n"],"additionalProperties":false`,
	} {
		if _, err := CanonicalSchemaDocument([]byte(root + fragment + `}`)); err != ErrSchema {
			t.Errorf("%s: got %v, want ErrSchema", fragment, err)
		}
	}
}
