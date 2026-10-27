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
	for _, raw := range []string{`"é"`, `"\udc00"`, `"\ud83d\ude00"`} {
		_, err := ParseJSON([]byte(raw))
		if err == nil {
			t.Errorf("accepted non-ASCII Unicode adversary %s", raw)
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
