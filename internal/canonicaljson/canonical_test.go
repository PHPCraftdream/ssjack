package canonicaljson

import (
	"fmt"
	"strings"
	"testing"
)

func TestCanonicalVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{` { "z": [true,null,-0], "a": 1 } `, `{"a":1,"z":[true,null,0]}`},
		{`"a\u0022b\u005cc\/\u003c\u003e \u0026"`, `"a\"b\\c/<> &"`},
		{`"\u00e9"`, `"é"`},
		{`"\u2028\u2029"`, "\"\u2028\u2029\""},
		{`"\ud83d\ude00"`, `"😀"`},
		{`{"😀":1,"":2,"a":3}`, `{"a":3,"":2,"😀":1}`},
		{`[-9007199254740991,9007199254740991]`, `[-9007199254740991,9007199254740991]`},
	}
	for _, tc := range cases {
		got, err := Canonicalize([]byte(tc.in))
		if err != nil || string(got) != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.in, got, err, tc.want)
			continue
		}
		again, err := Canonicalize(got)
		if err != nil || string(again) != tc.want {
			t.Errorf("idempotence: %q, %v", again, err)
		}
	}
}

func TestRejectInvalid(t *testing.T) {
	cases := []string{
		`{"a":1,"\u0061":2}`, `"e\u0301"`, `{"e\u0301":0}`, `"\n"`, `"\u0085"`, `"\ud800"`, `"\udc00"`, `"\ud800x"`,
		`1.0`, `1e0`, `9007199254740992`, `-9007199254740992`, `01`, `true false`, `{"a":}`, `"\x20"`, string([]byte{'"', 0xff, '"'}),
	}
	for _, input := range cases {
		if got, err := Canonicalize([]byte(input)); err == nil {
			t.Errorf("accepted %q as %q", input, got)
		}
	}
}

func TestBounds(t *testing.T) {
	nested := func(n int) string { return strings.Repeat("[", n) + "0" + strings.Repeat("]", n) }
	array := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]" }
	object := func(n int) string {
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "\"k%d\":0", i)
		}
		b.WriteByte('}')
		return b.String()
	}
	// 1 root + 15 arrays + 15*256 values = 3856 nodes; a sixteenth exceeds 4096.
	nodes := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat(array(256)+",", n), ",") + "]" }
	cases := []struct {
		input string
		ok    bool
	}{
		{nested(MaxDepth), true}, {nested(MaxDepth + 1), false},
		{array(MaxArray), true}, {array(MaxArray + 1), false},
		{object(MaxProperties), true}, {object(MaxProperties + 1), false},
		{nodes(15), true}, {nodes(16), false},
		{`"` + strings.Repeat("a", MaxOutput-2) + `"`, true}, {`"` + strings.Repeat("a", MaxOutput-1) + `"`, false},
		{strings.Repeat(" ", MaxInput-1) + "0", true}, {strings.Repeat(" ", MaxInput) + "0", false},
	}
	for i, tc := range cases {
		_, err := Canonicalize([]byte(tc.input))
		if (err == nil) != tc.ok {
			t.Errorf("case %d: got error %v, want success %v", i, err, tc.ok)
		}
	}
}
