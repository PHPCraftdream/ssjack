package declarativedescriptor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func reject(t *testing.T, b []byte) {
	t.Helper()
	if _, err := Validate(b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func tool(m map[string]any, i int) map[string]any {
	return m["tools"].([]any)[i].(map[string]any)
}

func TestIndependentFixture(t *testing.T) {
	m := fixture()
	m["session_id"] = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	raw := encode(m)
	d, err := Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID() != DescriptorID || d.SessionID() != m["session_id"] || len(d.Tools()) != 6 {
		t.Fatal("result identity")
	}
	tools := d.Tools()
	tools[0].Name = "changed"
	if d.Tools()[0].Name != "driver_list" {
		t.Fatal("tools alias")
	}
	canonical := d.CanonicalJSON()
	equivalent := bytes.Replace(raw, []byte(`"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false`),
		[]byte(`"additionalProperties":false,"\u0024schema":"https://json-schema.org/draft/2020-12/\u0073chema"`), 1)
	if bytes.Equal(equivalent, raw) {
		t.Fatal("nested replacement did not apply")
	}
	equivalent = append([]byte(" \n"), equivalent...)
	d2, err := Validate(equivalent)
	if err != nil || canonical != d2.CanonicalJSON() {
		t.Fatalf("nested equivalence: %v", err)
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if d.CanonicalJSON() != canonical || d.SessionID() != m["session_id"] || d.Tools()[0].Name != "driver_list" {
		t.Fatal("result aliases caller input")
	}
	raw = encode(m)
	padded := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), canonicaljson.MaxInput-len(raw))...)
	if _, err = Validate(padded); err != nil {
		t.Fatalf("exact raw boundary: %v", err)
	}
	reject(t, append(padded, ' '))
}

func TestFieldMutations(t *testing.T) {
	rootFields := []string{"protocol", "min_protocol", "max_protocol", "min_request_bytes", "max_request_bytes", "mode", "session_id", "tools"}
	toolFields := []string{"name", "input_schema", "output_schema", "schema_id", "schema_digest"}
	for _, field := range rootFields {
		t.Run("root-"+field, func(t *testing.T) {
			for _, v := range []any{nil, true, "wrong", []any{}} {
				m := fixture()
				m[field] = v
				reject(t, encode(m))
			}
			m := fixture()
			delete(m, field)
			reject(t, encode(m))
			m = fixture()
			m["unknown"] = 1
			reject(t, encode(m))
		})
	}
	for _, field := range toolFields {
		t.Run("tool-"+field, func(t *testing.T) {
			for _, v := range []any{nil, true, 1, []any{}} {
				m := fixture()
				tool(m, 0)[field] = v
				reject(t, encode(m))
			}
			m := fixture()
			delete(tool(m, 0), field)
			reject(t, encode(m))
			m = fixture()
			tool(m, 0)["unknown"] = 1
			reject(t, encode(m))
		})
	}
	for _, field := range []string{"protocol", "min_protocol", "max_protocol", "min_request_bytes", "max_request_bytes"} {
		want := 1
		if field == "max_request_bytes" {
			want = 262144
		}
		for _, value := range []any{want - 1, want + 1, json.Number(fmt.Sprintf("%d.0", want)), json.Number(fmt.Sprintf("%de0", want))} {
			m := fixture()
			m[field] = value
			reject(t, encode(m))
		}
	}
	for _, raw := range []string{"null", "{}", "[]"} {
		reject(t, []byte(raw))
	}
	for _, value := range []any{nil, map[string]any{}} {
		m := fixture()
		m["tools"].([]any)[0] = value
		reject(t, encode(m))
	}
	for _, change := range []func(map[string]any){
		func(m map[string]any) { m["Protocol"] = 1 },
		func(m map[string]any) { tool(m, 0)["Name"] = "driver_list" },
		func(m map[string]any) { m["tools"] = []any{} },
		func(m map[string]any) { m["tools"] = m["tools"].([]any)[:5] },
		func(m map[string]any) { a := m["tools"].([]any); m["tools"] = append(a, a[0]) },
		func(m map[string]any) { a := m["tools"].([]any); a[1] = a[0] },
		func(m map[string]any) { m["mode"] = "full" },
		func(m map[string]any) { a := m["tools"].([]any); a[0], a[1] = a[1], a[0] },
		func(m map[string]any) { tool(m, 0)["name"] = "other" },
		func(m map[string]any) { tool(m, 0)["schema_id"] = "wrong" },
		func(m map[string]any) { tool(m, 0)["schema_digest"] = strings.Repeat("0", 64) },
		func(m map[string]any) { tool(m, 0)["input_schema"].(map[string]any)["title"] = "substitution" },
		func(m map[string]any) { tool(m, 1)["output_schema"].(map[string]any)["title"] = "substitution" },
		func(m map[string]any) {
			output := tool(m, 1)["output_schema"].(map[string]any)
			required := output["required"].([]string)
			required[0], required[1] = required[1], required[0]
		},
		func(m map[string]any) {
			output := tool(m, 1)["output_schema"].(map[string]any)
			props := output["properties"].(map[string]any)
			values := props["state"].(map[string]any)["enum"].([]string)
			values[0], values[1] = values[1], values[0]
		},
		func(m map[string]any) {
			x := tool(m, 0)
			x["input_schema"].(map[string]any)["title"] = "substitution"
			x["schema_digest"] = pairDigest(x["input_schema"], x["output_schema"])
		},
		func(m map[string]any) {
			x := tool(m, 1)
			x["output_schema"].(map[string]any)["title"] = "substitution"
			x["schema_digest"] = pairDigest(x["input_schema"], x["output_schema"])
		},
		func(m map[string]any) {
			x := tool(m, 1)
			required := x["output_schema"].(map[string]any)["required"].([]string)
			required[0], required[1] = required[1], required[0]
			x["schema_digest"] = pairDigest(x["input_schema"], x["output_schema"])
		},
		func(m map[string]any) {
			x := tool(m, 1)
			props := x["output_schema"].(map[string]any)["properties"].(map[string]any)
			values := props["state"].(map[string]any)["enum"].([]string)
			values[0], values[1] = values[1], values[0]
			x["schema_digest"] = pairDigest(x["input_schema"], x["output_schema"])
		},
		func(m map[string]any) {
			x := tool(m, 1)
			props := x["output_schema"].(map[string]any)["properties"].(map[string]any)
			props["projection"].(map[string]any)["title"] = "extra"
			x["schema_digest"] = pairDigest(x["input_schema"], x["output_schema"])
		},
	} {
		m := fixture()
		change(m)
		reject(t, encode(m))
	}
	for _, s := range []string{"", "AAAA", "AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAA+", "AAAAAAAAAAAAAAAAAAAAAAA"} {
		m := fixture()
		m["session_id"] = s
		reject(t, encode(m))
	}
}

func TestStrictJSONAndBounds(t *testing.T) {
	raw := encode(fixture())
	for _, pair := range [][2]string{
		{`"protocol":1`, `"protocol":1,"\u0070rotocol":1`},
		{`"name":"driver_list"`, `"name":"driver_list","\u006eame":"driver_list"`},
		{`"$schema":`, `"$schema":"x","\u0024schema":`},
		{`"protocol":1`, `"protocol":1.0`},
		{`"protocol":1`, `"protocol":9007199254740992`},
		{`"mode":"declarative"`, `"mode":"declarative\u0000"`},
		{`"mode":"declarative"`, `"mode":"\ud800"`},
	} {
		mutated := bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(mutated, raw) {
			t.Fatalf("replacement did not apply: %s", pair[0])
		}
		reject(t, mutated)
	}
	reject(t, append(append([]byte(nil), raw...), 0xff))
	cases := []any{strings.Repeat("x", canonicaljson.MaxOutput+1)}
	var deep any
	for i := 0; i < canonicaljson.MaxDepth+1; i++ {
		deep = []any{deep}
	}
	cases = append(cases, deep, make([]any, canonicaljson.MaxArray+1))
	props := map[string]any{}
	for i := 0; i < canonicaljson.MaxProperties+1; i++ {
		props[fmt.Sprint(i)] = nil
	}
	cases = append(cases, props)
	nodes := make([]any, 17)
	for i := range nodes {
		nodes[i] = make([]any, 256)
	}
	cases = append(cases, nodes)
	for _, v := range cases {
		m := fixture()
		m["extra"] = v
		b := encode(m)
		if _, err := canonicaljson.Canonicalize(b); err == nil {
			t.Fatal("expected shared bound rejection")
		}
		reject(t, b)
	}
}
