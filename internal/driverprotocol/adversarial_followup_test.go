package driverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
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
	oversized := []byte(strings.Replace(canonical, `,`, ", "+strings.Repeat(" ", 262144), 1))
	if len(oversized) <= 262144 {
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

func TestPinnedSchemaCanonicalContract(t *testing.T) {
	root := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{},"required":[],"additionalProperties":false,"const":`
	for _, pair := range []struct{ literal, escaped string }{
		{"<", `\u003c`}, {">", `\u003e`}, {"&", `\u0026`},
		{"\u2028", `\u2028`}, {"\u2029", `\u2029`},
	} {
		valueSchema := `{"$schema":"https://json-schema.org/draft/2020-12/schema","const":"` + pair.literal + `","maxLength":1,"type":"string"}`
		valueHash := sha256.Sum256([]byte("ssjack-schema-v1\x00" + valueSchema))
		if err := ValidatePinnedValue([]byte(valueSchema), "x", hex.EncodeToString(valueHash[:]), "t", "k", "t", "k", "x", []byte(`"`+pair.escaped+`"`), 100); err != nil {
			t.Errorf("sensitive matching value: %v", err)
		}
		for _, position := range []string{"key", "value"} {
			value := func(s string) string {
				if position == "key" {
					return `{"` + s + `":0}`
				}
				return `{"x":"` + s + `"}`
			}
			canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"const":` + value(pair.literal) + `,"properties":{},"required":[],"type":"object"}`
			h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
			digest := hex.EncodeToString(h[:])
			wrong := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical + " "))
			for _, spelling := range []string{pair.literal, pair.escaped} {
				schema := []byte(root + value(spelling) + `}`)
				got, err := CanonicalSchemaDocument(schema)
				if err != nil || string(got) != canonical {
					t.Errorf("%s canonical %q: %v", position, got, err)
				}
				if err := ValidateSchemaDocument(schema, "x", digest); err != nil {
					t.Errorf("schema: %v", err)
				}
				if err := ValidateSchemaDocument(schema, "x", hex.EncodeToString(wrong[:])); err != ErrSchema {
					t.Errorf("wrong digest: %v", err)
				}
				if err := ValidatePinnedValue(schema, "x", digest, "t", "k", "t", "k", "x", []byte(value(pair.literal)), MaxDesired); err != ErrInvalid {
					t.Errorf("closed object mismatch: %v", err)
				}
				if err := ValidatePinnedValue(schema, "x", hex.EncodeToString(wrong[:]), "t", "k", "t", "k", "x", []byte(value(pair.literal)), MaxDesired); err != ErrSchema {
					t.Errorf("wrong value digest: %v", err)
				}
			}
		}
	}
}

func TestPinnedSchemaSizeBoundaries(t *testing.T) {
	base := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}`
	canonical := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}`
	h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
	digest := hex.EncodeToString(h[:])
	for _, extra := range []int{0, 1} {
		raw := []byte(base + strings.Repeat(" ", 262144-len(base)+extra))
		_, err := CanonicalSchemaDocument(raw)
		if (err == nil) != (extra == 0) {
			t.Errorf("raw boundary %d: %v", extra, err)
		}
		if err := ValidateSchemaDocument(raw, "x", digest); (err == nil) != (extra == 0) {
			t.Errorf("raw pin %d: %v", extra, err)
		}
		if err := ValidatePinnedValue(raw, "x", digest, "t", "k", "t", "k", "x", []byte(`null`), 100); (err == nil) != (extra == 0) {
			t.Errorf("raw value %d: %v", extra, err)
		}
	}
	makeSchema := func(n int, suffix string) string {
		key := strings.Repeat("a", n)
		return `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"` + key + `":{"const":"` + suffix + `","type":"boolean"}},"required":["` + key + `"],"type":"object"}`
	}
	baseLen := len(makeSchema(0, ""))
	for _, extra := range []int{0, 1} {
		remaining := 65536 + extra - baseLen
		schema := makeSchema(remaining/2, strings.Repeat("x", remaining%2))
		h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + schema))
		digest := hex.EncodeToString(h[:])
		got, err := CanonicalSchemaDocument([]byte(schema))
		if (err == nil) != (extra == 0) || (err == nil && string(got) != schema) {
			t.Errorf("canonical boundary %d: %v", extra, err)
		}
		if err := ValidateSchemaDocument([]byte(schema), "x", digest); (err == nil) != (extra == 0) {
			t.Errorf("canonical pin %d: %v", extra, err)
		}
		if err := ValidatePinnedValue([]byte(schema), "x", digest, "t", "k", "t", "k", "x", []byte(`{}`), 100); extra == 0 && err != ErrInvalid || extra == 1 && err != ErrSchema {
			t.Errorf("canonical value %d: %v", extra, err)
		}
	}
}

func TestPinnedLargeFiniteValues(t *testing.T) {
	text := strings.Repeat("x", 3000) + "<>&\u2028\u2029"
	quoted := `"` + text + `"`
	value := `{"a":[` + quoted + `,` + quoted + `],"b":true}`
	alternate := `{"b":true,"a":["` + strings.Repeat("x", 3000) + `\u003c\u003e\u0026\u2028\u2029",` + quoted + `]}`
	other := strings.Replace(value, `"b":true`, `"b":false`, 1)
	shape := `"additionalProperties":false,"properties":{"a":{"items":{"maxLength":4096,"type":"string"},"maxItems":2,"type":"array"},"b":{"type":"boolean"}},"required":["a","b"],"type":"object"`
	prefix := `{"$schema":"https://json-schema.org/draft/2020-12/schema",`
	for _, finite := range []string{`"enum":[` + value + `],`, `"const":` + value + `,`, `"const":` + value + `,"enum":[` + other + `,` + value + `],`} {
		canonical := prefix + `"additionalProperties":false,` + finite + strings.TrimPrefix(shape, `"additionalProperties":false,`) + `}`
		rawSchema := strings.NewReplacer("<", `\u003c`, ">", `\u003e`, "&", `\u0026`, "\u2028", `\u2028`, "\u2029", `\u2029`).Replace(canonical)
		h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + canonical))
		digest := hex.EncodeToString(h[:])
		for _, schema := range []string{canonical, rawSchema} {
			if err := ValidateSchemaDocument([]byte(schema), "x", digest); err != nil {
				t.Errorf("large finite schema: %v", err)
			}
		}
		for _, tc := range []struct {
			input string
			limit int
			want  error
		}{
			{value, MaxDesired, nil}, {alternate, MaxDesired, nil}, {other, MaxDesired, ErrInvalid},
			{value, len(value) - 1, ErrInvalid},
		} {
			if err := ValidatePinnedValue([]byte(canonical), "x", digest, "t", "k", "t", "k", "x", []byte(tc.input), tc.limit); err != tc.want {
				t.Errorf("large finite value: got %v, want %v", err, tc.want)
			}
		}
		changed := strings.Replace(canonical, `"b":true`, `"b":false`, 1)
		if err := ValidatePinnedValue([]byte(changed), "x", digest, "t", "k", "t", "k", "x", []byte(value), MaxDesired); err != ErrSchema {
			t.Errorf("stale finite pin: %v", err)
		}
	}
	duplicate := prefix + shape + `,"enum":[` + value + `,` + alternate + `]}`
	if _, err := CanonicalSchemaDocument([]byte(duplicate)); err != ErrSchema {
		t.Errorf("duplicate large values: %v", err)
	}
	oversized := prefix + `"const":"` + strings.Repeat("x", 65536) + `","type":"boolean"}`
	if _, err := CanonicalSchemaDocument([]byte(oversized)); err != ErrSchema {
		t.Errorf("oversized finite schema: %v", err)
	}
	tooMany := prefix + `"const":[` + strings.TrimSuffix(strings.Repeat("0,", 257), ",") + `],"type":"boolean"}`
	if _, err := CanonicalSchemaDocument([]byte(tooMany)); err != ErrSchema {
		t.Errorf("oversized finite array: %v", err)
	}
	tooManyEnum := prefix + `"enum":[` + strings.TrimSuffix(strings.Repeat("0,", 257), ",") + `],"type":"boolean"}`
	if _, err := CanonicalSchemaDocument([]byte(tooManyEnum)); err != ErrSchema {
		t.Errorf("oversized enum: %v", err)
	}
	deep := prefix + `"const":` + strings.Repeat("[", MaxDepth) + `0` + strings.Repeat("]", MaxDepth) + `,"type":"boolean"}`
	if _, err := CanonicalSchemaDocument([]byte(deep)); err != ErrSchema {
		t.Errorf("over-depth finite value: %v", err)
	}
	rawOversized := prefix + `"const":true,"type":"boolean"}` + strings.Repeat(" ", 262144)
	if _, err := CanonicalSchemaDocument([]byte(rawOversized)); err != ErrSchema {
		t.Errorf("oversized raw finite schema: %v", err)
	}
}
