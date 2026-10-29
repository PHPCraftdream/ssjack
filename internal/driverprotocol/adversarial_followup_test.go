package driverprotocol

import (
	"strconv"
	"strings"
	"testing"
)

func TestRequestedStructuralAdversaries(t *testing.T) {
	validEffect := `[{"class":"file.write","summary_id":"written","destructive":false}]`
	for _, action := range []string{"apply"} {
		base := validStructuralRequest(action)
		withEffect := strings.Replace(string(base), `"allowed_effects":[]`, `"allowed_effects":`+validEffect, 1)
		if _, err := ValidateStructuralRequest([]byte(withEffect)); err != nil {
			t.Errorf("%s valid effect: %v", action, err)
		}
		for name, effects := range map[string]string{
			"missing field":   `[{"class":"file.write","summary_id":"written"}]`,
			"bad class":       `[{"class":"Bad","summary_id":"written","destructive":false}]`,
			"bad summary":     `[{"class":"file.write","summary_id":"Bad","destructive":false}]`,
			"bad destructive": `[{"class":"file.write","summary_id":"written","destructive":0}]`,
			"duplicate":       validEffect[:len(validEffect)-1] + `,{"class":"file.write","summary_id":"written","destructive":false}]`,
		} {
			input := strings.Replace(string(base), `"allowed_effects":[]`, `"allowed_effects":`+effects, 1)
			if _, err := ValidateStructuralRequest([]byte(input)); err == nil {
				t.Errorf("%s accepted %s", action, name)
			}
		}
	}
	for _, raw := range []string{`"é"`, `"\udc00"`} {
		_, err := ParseJSON([]byte(raw))
		if err == nil {
			t.Errorf("accepted invalid Unicode adversary %s", raw)
		}
	}
	makeProps := func(n int) string {
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Quote("k" + strconv.Itoa(i)))
			b.WriteString(":0")
		}
		b.WriteByte('}')
		return b.String()
	}
	for _, tc := range []struct {
		n  int
		ok bool
	}{{128, true}, {129, false}} {
		_, err := ParseJSON([]byte(makeProps(tc.n)))
		if (err == nil) != tc.ok {
			t.Errorf("%d object properties: %v", tc.n, err)
		}
	}
	for _, tc := range []struct {
		n  int64
		ok bool
	}{{-9007199254740991, true}, {9007199254740991, true}, {-9007199254740992, false}, {9007199254740992, false}} {
		_, err := ParseJSON([]byte(`{"n":` + strconv.FormatInt(tc.n, 10) + `}`))
		if (err == nil) != tc.ok {
			t.Errorf("integer %d: %v", tc.n, err)
		}
	}
	v, err := ParseJSON([]byte(`{"x":"<>&"}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"x":"\u003c\u003e\u0026"}` {
		t.Fatalf("HTML escaping not reflected in canonical byte count: %q", encoded)
	}
}

func TestSchemaInputWhitespaceAndAdjacentParserBounds(t *testing.T) {
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}`
	_, digest := pinned(canonical)
	oversized := []byte(strings.Replace(canonical, `,`, ", "+strings.Repeat(" ", maxSchemaBytes), 1))
	if len(oversized) <= maxSchemaBytes {
		t.Fatal("fixture does not cross raw schema limit")
	}
	if err := ValidatePinnedValue(oversized, "x", digest, "t", "k", "t", "k", "x", []byte(`null`), 100); err != ErrSchema {
		t.Fatalf("oversized whitespace schema: got %v, want ErrSchema", err)
	}
	depth := strings.Repeat("[", MaxDepth) + "0" + strings.Repeat("]", MaxDepth)
	if _, err := ParseJSON([]byte(depth)); err != nil {
		t.Fatalf("exact depth rejected: %v", err)
	}
	if _, err := ParseJSON([]byte("[" + depth + "]")); err == nil {
		t.Fatal("accepted depth above limit")
	}
	makeNodes := func(last int) []byte {
		parts := make([]string, 16)
		for i := range parts {
			n := 255
			if i == len(parts)-1 {
				n = last
			}
			parts[i] = "[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]"
		}
		return []byte("[" + strings.Join(parts, ",") + "]")
	}
	if _, err := ParseJSON(makeNodes(254)); err != nil {
		t.Fatalf("4096-node boundary rejected: %v", err)
	}
	if _, err := ParseJSON(makeNodes(255)); err == nil {
		t.Fatal("accepted 4097 nodes")
	}
}

func TestPinnedDesiredProjectionByteBoundaries(t *testing.T) {
	desiredSchema, desiredDigest := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"a":{"type":"string","maxLength":4096},"b":{"type":"string","maxLength":4096},"c":{"type":"string","maxLength":4096},"d":{"type":"string","maxLength":4096},"e":{"type":"string","maxLength":4096},"f":{"type":"string","maxLength":4096},"g":{"type":"string","maxLength":4096},"h":{"type":"string","maxLength":4096}},"required":["a","b","c","d","e","f","g","h"],"additionalProperties":false}`)
	requestFor := func(last int) []byte {
		values := []int{4089, 4089, 4089, 4089, 4089, 4089, 4089, last}
		keys := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
		var desired strings.Builder
		desired.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				desired.WriteByte(',')
			}
			desired.WriteString(`"` + key + `":"` + strings.Repeat("a", values[i]) + `"`)
		}
		desired.WriteByte('}')
		return []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"plan","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":` + desired.String() + `,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":65536,"operation_id":null}`)
	}
	exact, err := ParseJSON(requestFor(4088))
	if err != nil {
		t.Fatal(err)
	}
	requestObject, _ := object(exact)
	encoded, err := canonicalBytes(requestObject["desired"])
	if err != nil || len(encoded) != MaxDesired {
		t.Fatalf("desired canonical size %d, err %v", len(encoded), err)
	}
	if _, err := ValidatePinnedRequest(requestFor(4088), desiredSchema, "cache.desired", desiredDigest, "target", "kind"); err != nil {
		t.Fatalf("desired exact boundary rejected: %v", err)
	}
	if _, err := ValidatePinnedRequest(requestFor(4089), desiredSchema, "cache.desired", desiredDigest, "target", "kind"); err == nil {
		t.Fatal("oversize desired accepted")
	}

	projectionSchema, projectionDigest := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"a":{"type":"string","maxLength":1018},"b":{"type":"string","maxLength":1018},"c":{"type":"string","maxLength":1018},"d":{"type":"string","maxLength":1018},"e":{"type":"string","maxLength":1018},"f":{"type":"string","maxLength":1018},"g":{"type":"string","maxLength":1018},"h":{"type":"string","maxLength":1018}},"required":["a","b","c","d","e","f","g","h"],"additionalProperties":false}`)
	observe := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":65536,"operation_id":null}`)
	q, err := ValidateStructuralRequest(observe)
	if err != nil {
		t.Fatal(err)
	}
	responseFor := func(last int) []byte {
		values := []int{1017, 1017, 1017, 1017, 1017, 1017, 1017, last}
		keys := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
		var projection strings.Builder
		projection.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				projection.WriteByte(',')
			}
			projection.WriteString(`"` + key + `":"` + strings.Repeat("a", values[i]) + `"`)
		}
		projection.WriteByte('}')
		return []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":null,"projection":` + projection.String() + `}}`)
	}
	validate := func(last int) error {
		_, e := ValidatePinnedProjection(q, responseFor(last), projectionSchema, "cache.desired", "cache.projection", projectionDigest, "target", "kind", "cache.projection")
		return e
	}
	exactResponse, err := ParseJSON(responseFor(1016))
	if err != nil {
		t.Fatal(err)
	}
	responseObject, _ := object(exactResponse)
	dataObject, _ := object(responseObject["data"])
	projectionObject, _ := object(dataObject["projection"])
	encodedProjection, err := canonicalBytes(projectionObject)
	if err != nil || len(encodedProjection) != MaxProjection {
		t.Fatalf("projection canonical size %d, err %v", len(encodedProjection), err)
	}
	if err := validate(1016); err != nil {
		t.Fatalf("projection exact boundary rejected: %v", err)
	}
	if err := validate(1017); err == nil {
		t.Fatal("oversize projection accepted")
	}
}

func TestCanonicalValueSpelling(t *testing.T) {
	for _, raw := range []string{`{"<":"<&>\u2028\u2029\"\\"}`, `{"\u003c":"\u003c\u0026\u003e\u2028\u2029\u0022\u005c"}`} {
		v, err := ParseJSON([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		b, err := canonicalValueBytes(v)
		want := "{\"<\":\"<&>\u2028\u2029\\\"\\\\\"}"
		if err != nil || string(b) != want {
			t.Fatalf("canonical value %q: %v", b, err)
		}
		if !bounded(v, len(want)) || bounded(v, len(want)-1) {
			t.Fatal("incorrect canonical bound")
		}
	}
}

func TestSensitiveValueByteBoundaries(t *testing.T) {
	schema, digest := pinned(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"a":{"type":"string","maxLength":4096},"b":{"type":"string","maxLength":4096},"c":{"type":"string","maxLength":4096},"d":{"type":"string","maxLength":4096},"e":{"type":"string","maxLength":4096},"f":{"type":"string","maxLength":4096},"g":{"type":"string","maxLength":4096},"h":{"type":"string","maxLength":4096}},"required":["a","b","c","d","e","f","g","h"],"additionalProperties":false}`)
	value := func(total int) string {
		parts := make([]string, 8)
		for i := range parts {
			n := (total - 57) / 8
			if i == 7 {
				n += (total - 57) % 8
			}
			parts[i] = `"` + string(rune('a'+i)) + `":"<>&` + "\u2028\u2029" + strings.Repeat("x", n-9) + `"`
		}
		return `{` + strings.Join(parts, ",") + `}`
	}
	request := func(v string) []byte {
		return []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"plan","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":` + v + `,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":65536,"operation_id":null}`)
	}
	observe := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"target","kind":"kind","schema_id":"cache.desired","resource_id":"r","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":1,"max_response_bytes":65536,"operation_id":null}`)
	q, err := ValidateStructuralRequest(observe)
	if err != nil {
		t.Fatal(err)
	}
	response := func(v string) []byte {
		return []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":null,"projection":` + v + `}}`)
	}
	for _, tc := range []struct {
		limit      int
		projection bool
	}{{MaxDesired, false}, {MaxProjection, true}} {
		for _, extra := range []int{0, 1} {
			v := value(tc.limit + extra)
			if len(v) != tc.limit+extra {
				t.Fatalf("fixture size %d, want %d", len(v), tc.limit+extra)
			}
			if tc.projection {
				_, err = ValidateStructuralResponse(q, response(v))
				if (err == nil) != (extra == 0) {
					t.Errorf("structural projection extra %d: %v", extra, err)
				}
				_, err = ValidatePinnedProjection(q, response(v), schema, "cache.desired", "cache.projection", digest, "target", "kind", "cache.projection")
			} else {
				_, err = ValidateStructuralRequest(request(v))
				if (err == nil) != (extra == 0) {
					t.Errorf("structural desired extra %d: %v", extra, err)
				}
				_, err = ValidatePinnedRequest(request(v), schema, "cache.desired", digest, "target", "kind")
			}
			if (err == nil) != (extra == 0) {
				t.Errorf("pinned projection=%v extra %d: %v", tc.projection, extra, err)
			}
		}
	}
}

func TestPinnedSchemaRejectsJSONSeparatorEscaping(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"required":[],"additionalProperties":false,"const":`
	baseline, baselineDigest := pinned(root + `{"x":"y"}}`)
	if err := ValidateSchemaDocument(baseline, "x", baselineDigest); err != nil {
		t.Fatalf("baseline schema rejected: %v", err)
	}
	for _, sep := range []struct{ name, literal, escaped string }{
		{"U+2028", "\u2028", `\u2028`},
		{"U+2029", "\u2029", `\u2029`},
	} {
		for _, position := range []string{"key", "value"} {
			for _, spelling := range []string{sep.literal, sep.escaped} {
				t.Run(sep.name+"/"+position+"/"+spelling, func(t *testing.T) {
					value := `{"` + spelling + `":0}`
					if position == "value" {
						value = `{"x":"` + spelling + `"}`
					}
					schema, digest := pinned(root + value + `}`)
					if _, err := CanonicalSchemaDocument(schema); err != ErrSchema {
						t.Fatalf("canonical schema: got %v, want ErrSchema", err)
					}
					if err := ValidateSchemaDocument(schema, "x", digest); err != ErrSchema {
						t.Fatalf("schema pin: got %v, want ErrSchema", err)
					}
					if err := ValidatePinnedValue(schema, "x", digest, "t", "k", "t", "k", "x", []byte(`{}`), MaxDesired); err != ErrSchema {
						t.Fatalf("pinned value: got %v, want ErrSchema", err)
					}
				})
			}
		}
	}
}
