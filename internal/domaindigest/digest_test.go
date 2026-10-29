package domaindigest

import (
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func TestDomainVectors(t *testing.T) {
	// SHA-256 vectors independently generated over ASCII label + NUL + {"a":1}.
	cases := []struct {
		domain Domain
		want   string
	}{
		{Schema, "dc7445c18574905097fc5b978a1ede7b916e320b77e7e040a24c6308a287948d"},
		{ToolSchema, "baef9501d0225ecddd1772002b7f6c557dedfa0059999e271f59e46f7789c470"},
		{Plan, "6b266c5ae024fb603d2b9670f8d5fe29f225bc24fe2b636a325974bab8d59cbc"},
		{Enrollment, "168369327e5d35adf00ce4762d211161ae6f8cad1074b69b4c9a977d9c8cbbd3"},
		{Desired, "1ff318a0b93a777bd23893bc5e4f49fad9686690d5b33f12dc1a3d9de54f62ef"},
		{Effects, "740ee47e63232257f4b86ed319fdefab5e49dcc682b93cb0d744eb722541a366"},
	}
	seen := make(map[string]Domain)
	for _, tc := range cases {
		for _, input := range []string{`{"a":1}`, ` { "\u0061" : 1 } `} {
			got, err := Sum(tc.domain, []byte(input))
			if err != nil || got != tc.want {
				t.Errorf("domain %d input %q: got %q, %v; want %q", tc.domain, input, got, err, tc.want)
			}
		}
		got, err := Sum(tc.domain, []byte(`{"a":1}`))
		if err != nil {
			t.Fatalf("domain %d: %v", tc.domain, err)
		}
		if previous, ok := seen[got]; ok {
			t.Errorf("domains %d and %d produced the same digest", previous, tc.domain)
		}
		seen[got] = tc.domain
	}
}

func TestRejectInvalidDomainAndJSON(t *testing.T) {
	for _, domain := range []Domain{0, 7, 255} {
		if got, err := Sum(domain, []byte(`null`)); got != "" || !errors.Is(err, ErrDomain) {
			t.Errorf("domain %d: got %q, %v", domain, got, err)
		}
	}
	for _, input := range []string{
		``, `{"a":1,"\u0061":2}`, `1.0`, `true false`, `"\ud800"`,
		`"e\u0301"`, `{"e\u0301":1}`, string([]byte{'"', 0xff, '"'}),
	} {
		if got, err := Sum(Desired, []byte(input)); got != "" || !errors.Is(err, canonicaljson.ErrInvalid) {
			t.Errorf("invalid input length %d: got %q, %v", len(input), got, err)
		}
	}
}

func TestUnicodeEquivalence(t *testing.T) {
	literal := []byte(`{"é":"😀"}`)
	escaped := []byte(`{"\u00e9":"\ud83d\ude00"}`)
	a, errA := Sum(Schema, literal)
	b, errB := Sum(Schema, escaped)
	if errA != nil || errB != nil || a != b || a == "" {
		t.Fatalf("Unicode equivalence: %q, %v; %q, %v", a, errA, b, errB)
	}
}

func TestCanonicalSizeBoundaries(t *testing.T) {
	cases := []struct {
		input string
		valid bool
	}{
		{strings.Repeat(" ", canonicaljson.MaxInput-1) + "0", true},
		{strings.Repeat(" ", canonicaljson.MaxInput) + "0", false},
		{`"` + strings.Repeat("a", canonicaljson.MaxOutput-2) + `"`, true},
		{`"` + strings.Repeat("a", canonicaljson.MaxOutput-1) + `"`, false},
	}
	for i, tc := range cases {
		got, err := Sum(Desired, []byte(tc.input))
		if tc.valid && (err != nil || len(got) != 64) {
			t.Errorf("case %d: got %q, %v; want digest", i, got, err)
		}
		if !tc.valid && (got != "" || !errors.Is(err, canonicaljson.ErrInvalid)) {
			t.Errorf("case %d: got %q, %v; want invalid", i, got, err)
		}
	}
}

func TestDifferentValuesHaveDifferentDigests(t *testing.T) {
	a, errA := Sum(Desired, []byte(`{"a":1}`))
	b, errB := Sum(Desired, []byte(`{"a":2}`))
	if errA != nil || errB != nil || a == b {
		t.Fatalf("changed value: %q, %v; %q, %v", a, errA, b, errB)
	}
}
