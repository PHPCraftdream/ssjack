package externalschemasubset

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func TestExpandedEquality(t *testing.T) {
	// Each array is below the canonical output cap, but default JSON marshaling
	// expands the HTML characters past the canonical input cap.
	makeValue := func(last string) string {
		items := make([]string, 12)
		for i := range items {
			items[i] = `"` + strings.Repeat("<", 4000) + `"`
		}
		items[11] = `"` + strings.Repeat("<", 3999) + last + `"`
		return `[` + strings.Join(items, ",") + `]`
	}
	a, b := makeValue("<"), makeValue(">")
	base := root + `"type":"array","items":{"type":"string","maxLength":4096},"maxItems":12,`
	for _, keyword := range []string{"const", "enum"} {
		constraint := a
		if keyword == "enum" {
			constraint = `[` + a + `]`
		}
		s := base + `"` + keyword + `":` + constraint + `}`
		if err := Validate([]byte(s), []byte(a), canonicaljson.MaxOutput); err != nil {
			t.Fatalf("%s rejected equal value: %v", keyword, err)
		}
		if err := Validate([]byte(s), []byte(b), canonicaljson.MaxOutput); !errors.Is(err, ErrValue) {
			t.Fatalf("%s accepted distinct value: %v", keyword, err)
		}
	}
}

func TestCanonicalEqualityNestedAndEscapes(t *testing.T) {
	large := strings.Repeat("<>&\u2028\u2029", 2000)
	v := []any{map[string]any{"b": []any{json.Number("1"), large}, "a": true}}
	w := []any{map[string]any{"a": true, "b": []any{json.Number("1"), large}}}
	k, err := key(v)
	if err != nil {
		t.Fatal(err)
	}
	other, err := key(w)
	if err != nil || k != other {
		t.Fatalf("nested equal values differ: %v", err)
	}
	if _, err := key(make(chan int)); err == nil {
		t.Fatal("marshal error ignored")
	}
	if _, err := key(json.Number("1.5")); err == nil {
		t.Fatal("canonicalization error ignored")
	}

	dup := root + `"type":"null","enum":[{"a":[1,{"x":true,"y":null}]},{"a":[1,{"y":null,"x":true}]}]}`
	if !errors.Is(ValidateSchema([]byte(dup)), ErrSchema) {
		t.Fatal("nested duplicate enum accepted")
	}
	s := root + `"type":"array","items":{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"],"additionalProperties":false},"maxItems":2,"uniqueItems":true}`
	if !errors.Is(Validate([]byte(s), []byte(`[{"a":1,"b":2},{"b":2,"a":1}]`), canonicaljson.MaxOutput), ErrValue) {
		t.Fatal("nested duplicate items accepted")
	}
	if err := Validate([]byte(s), []byte(`[{"a":1,"b":2},{"b":3,"a":1}]`), canonicaljson.MaxOutput); err != nil {
		t.Fatalf("distinct items rejected: %v", err)
	}
}
