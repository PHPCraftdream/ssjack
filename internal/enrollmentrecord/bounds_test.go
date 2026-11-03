package enrollmentrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func TestRecordCountBounds(t *testing.T) {
	m, p, snapshot, raw := recordFixture(t)
	withCounts := func(schemas, kinds string) string {
		a := strings.Index(raw, `"schemas":[`)
		b := strings.Index(raw, `],"kinds":[`)
		if a < 0 || b < 0 {
			t.Fatal("fixture shape changed")
		}
		return raw[:a] + `"schemas":[` + schemas + `],"kinds":[` + kinds + `]}`
	}
	doc := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}`
	canonical, err := driverprotocol.CanonicalSchemaDocument([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), canonical...))
	digest := hex.EncodeToString(sum[:])
	entry := func(id string) string {
		return fmt.Sprintf(`{"id":%q,"digest":%q,"document":%s}`, id, digest, canonical)
	}
	kind := func(name, id string) string {
		return fmt.Sprintf(`{"name":%q,"desired_schema_id":%q,"projection_schema_id":%q}`, name, id, id)
	}
	check := func(label, schemas, kinds string, ok bool) {
		t.Helper()
		_, err := ParseRecord([]byte(withCounts(schemas, kinds)), m, snapshot, p)
		if (err == nil) != ok {
			t.Fatalf("%s: err=%v", label, err)
		}
	}
	oneschema := entry("s000")
	check("zero schemas", "", kind("cache", "s000"), false)
	check("one schema", oneschema, kind("cache", "s000"), true)
	many := make([]string, 256)
	for i := range many {
		many[i] = entry(fmt.Sprintf("s%03d", i))
	}
	check("256 schemas", strings.Join(many, ","), kind("cache", "s000"), true)
	check("257 schemas", strings.Join(append(many, entry("s256")), ","), kind("cache", "s000"), false) // rejected by the 256-entry schema-list limit.
	check("zero kinds", oneschema, "", false)
	check("one kind", oneschema, kind("cache", "s000"), true)
	kinds := make([]string, 128)
	for i := range kinds {
		kinds[i] = kind(fmt.Sprintf("k%03d", i), "s000")
	}
	check("128 kinds", oneschema, strings.Join(kinds, ","), true)
	check("129 kinds", oneschema, strings.Join(append(kinds, kind("k128", "s000")), ","), false)
	check("duplicate kind", oneschema, kind("cache", "s000")+","+kind("cache", "s000"), false)
}

func TestRecordSchemaBounds(t *testing.T) {
	good := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null"}`
	deep := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"array","maxItems":1,"items":`
	for i := 0; i < 15; i++ {
		deep += `{"type":"array","maxItems":1,"items":`
	}
	deep += `{"type":"null"}` + strings.Repeat("}", 16)
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"valid", good, true}, {"malformed", `{"type":`, false}, {"deep", deep, false},
		{"whitespace above former raw cap", good + strings.Repeat(" ", 65536), true},
		{"raw limit exact", good + strings.Repeat(" ", 262144-len(good)), true},
		{"raw limit exceeded", good + strings.Repeat(" ", 262145-len(good)), false},
		{"unsupported ref", `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"null","$ref":"x"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := driverprotocol.CanonicalSchemaDocument([]byte(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.name == "unsupported ref" && err != driverprotocol.ErrSchema {
				t.Fatalf("err=%v, want ErrSchema", err)
			}
		})
	}
}

func TestParseJSONDirectBounds(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"unicode NFC", `"é"`, true}, {"unicode non-NFC", `"e\u0301"`, false},
		{"control", `"\u0001"`, false}, {"surrogate", `"\ud800"`, false},
		{"depth 16", strings.Repeat("[", 16) + `0` + strings.Repeat("]", 16), true},
		{"depth 17", strings.Repeat("[", 17) + `0` + strings.Repeat("]", 17), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := driverprotocol.ParseJSON([]byte(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

// ParseJSON enforces aggregate nodes before record identity validation.
func TestParseJSONAggregateNodes(t *testing.T) {
	// Fifteen 257-node arrays plus a 240-node final array and outer root total 4096.
	full := "[" + strings.TrimSuffix(strings.Repeat("0,", 256), ",") + "]"
	final239 := "[" + strings.TrimSuffix(strings.Repeat("0,", 239), ",") + "]"
	final240 := "[" + strings.TrimSuffix(strings.Repeat("0,", 240), ",") + "]"
	atLimit := "[" + strings.TrimSuffix(strings.Repeat(full+",", 15), ",") + "," + final239 + "]"
	above := "[" + strings.TrimSuffix(strings.Repeat(full+",", 15), ",") + "," + final240 + "]"
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{{"4096", atLimit, true}, {"4097", above, false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := driverprotocol.ParseJSON([]byte(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
