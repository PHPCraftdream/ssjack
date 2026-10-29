package enrollmentvalidator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/externalschemasubset"
)

func fixture() map[string]any {
	d := strings.Repeat("a", 64)
	doc := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "boolean"}
	b, _ := json.Marshal(doc)
	h := sha256.Sum256(append([]byte("ssjack-schema-v1\x00"), b...))
	return map[string]any{
		"artifact_digests": map[string]any{"artifact": d}, "dependency_digests": map[string]any{}, "aliases": []any{}, "capabilities": []any{"observe"}, "configuration_digest": d, "driver_id": "driver", "driver_protocol": 1, "enrollment_id": "AAAAAAAAAAAAAAAAAAAAAA", "effects": []any{map[string]any{"class": "read", "summary_id": "read", "decision": "delegated", "destructive": false}}, "environment": map[string]any{}, "resource_sinks": []any{},
		"executable": map[string]any{"path": "/driver", "sha256": d, "interpreter": map[string]any{"path": "/interp", "sha256": d}, "argv": []any{}}, "working_directory": map[string]any{"path": "/private", "device": "1", "file_id": "2"}, "os_identity": map[string]any{"platform": "posix", "uid": 1, "gid": 1, "groups": []any{}}, "principal": map[string]any{"issuer": "issuer", "subject": "subject"}, "provenance": map[string]any{"source": "source", "revision": "rev", "dependencies": []any{}},
		"limits": map[string]any{"process_slots": 1, "session_operations": 1, "global_operations": 1, "emergency_cancellations": 1, "storage_bytes": 1, "records": 1, "cancellation_reserve_bytes": 4096}, "network": map[string]any{"policy": "deny_all", "targets": []any{}, "policy_digest": d}, "schemas": []any{map[string]any{"id": "schema", "digest": hex.EncodeToString(h[:]), "document": doc}}, "kinds": []any{map[string]any{"name": "kind", "desired_schema_id": "schema", "projection_schema_id": "schema"}}, "targets": []any{map[string]any{"name": "target", "canonical_target": "remote"}},
	}
}
func validateFixture(m map[string]any) error {
	b, _ := json.Marshal(m)
	_, err := Validate(b)
	return err
}
func TestClosedAndBindings(t *testing.T) {
	if err := validateFixture(fixture()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"unknown":          func(m map[string]any) { m["extra"] = true },
		"missing":          func(m map[string]any) { delete(m, "environment") },
		"capabilities":     func(m map[string]any) { m["capabilities"] = []any{"plan"} },
		"schema digest":    func(m map[string]any) { m["schemas"].([]any)[0].(map[string]any)["digest"] = strings.Repeat("b", 64) },
		"schema reference": func(m map[string]any) { m["kinds"].([]any)[0].(map[string]any)["desired_schema_id"] = "missing" },
		"alias target": func(m map[string]any) {
			m["aliases"] = []any{map[string]any{"target": "target", "kind": "kind", "resource_id": "r", "canonical_target": "wrong", "canonical_resource": "r"}}
		},
		"network":      func(m map[string]any) { m["network"].(map[string]any)["policy"] = "allow_list" },
		"dependencies": func(m map[string]any) { m["dependency_digests"] = map[string]any{"dep": strings.Repeat("a", 64)} },
	}
	for n, mutate := range cases {
		t.Run(n, func(t *testing.T) {
			m := fixture()
			mutate(m)
			if validateFixture(m) == nil {
				t.Fatal("accepted invalid record")
			}
		})
	}
}
func TestRejectDuplicateJSON(t *testing.T) {
	if _, err := Validate([]byte(`{"x":1,"x":2}`)); err == nil {
		t.Fatal("accepted duplicate")
	}
}

func TestFixtureSchemaAndDigest(t *testing.T) {
	m := fixture()
	s := m["schemas"].([]any)[0].(map[string]any)
	raw, _ := json.Marshal(s["document"])
	if err := externalschemasubset.ValidateSchema(raw); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte("ssjack-schema-v1\x00"), canonical...))
	if s["digest"] != hex.EncodeToString(h[:]) {
		t.Fatal("schema digest mismatch")
	}
	raw, _ = json.Marshal(m)
	canonical, err = canonicaljson.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256(append([]byte("ssjack-enrollment-v1\x00"), canonical...))
	got, err := Validate(raw)
	if err != nil || got != hex.EncodeToString(h[:]) {
		t.Fatalf("digest %q: %v", got, err)
	}
	indented, _ := json.MarshalIndent(m, "", "  ")
	got2, err := Validate(indented)
	if err != nil || got2 != got {
		t.Fatalf("noncanonical input digest %q: %v", got2, err)
	}
}

func TestIdentityAndClosedObjects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"empty device", func(m map[string]any) { m["working_directory"].(map[string]any)["device"] = "" }, false},
		{"empty file id", func(m map[string]any) { m["working_directory"].(map[string]any)["file_id"] = "" }, false},
		{"relative path", func(m map[string]any) { m["working_directory"].(map[string]any)["path"] = "private" }, false},
		{"windows path", func(m map[string]any) { m["working_directory"].(map[string]any)["path"] = `C:\private` }, true},
		{"windows sid", func(m map[string]any) { m["os_identity"] = map[string]any{"platform": "windows", "sid": "S-1-5-18"} }, true},
		{"empty sid", func(m map[string]any) { m["os_identity"] = map[string]any{"platform": "windows", "sid": ""} }, false},
		{"posix max", func(m map[string]any) {
			m["os_identity"] = map[string]any{"platform": "posix", "uid": uint64(4294967295), "gid": 0, "groups": []any{uint64(4294967295)}}
		}, true},
		{"posix overflow", func(m map[string]any) { m["os_identity"].(map[string]any)["uid"] = uint64(4294967296) }, false},
		{"posix negative group", func(m map[string]any) { m["os_identity"].(map[string]any)["groups"] = []any{-1} }, false},
		{"identity extra", func(m map[string]any) { m["os_identity"].(map[string]any)["sid"] = "x" }, false},
		{"identity missing", func(m map[string]any) { delete(m["os_identity"].(map[string]any), "gid") }, false},
		{"interpreter extra", func(m map[string]any) {
			m["executable"].(map[string]any)["interpreter"].(map[string]any)["extra"] = true
		}, false},
		{"interpreter missing", func(m map[string]any) {
			delete(m["executable"].(map[string]any)["interpreter"].(map[string]any), "path")
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := fixture()
			c.mutate(m)
			err := validateFixture(m)
			if (err == nil) != c.valid {
				t.Fatalf("valid=%v: %v", c.valid, err)
			}
		})
	}
}

func TestLimitBoundaries(t *testing.T) {
	for k, max := range map[string]int{"process_slots": 4, "session_operations": 32, "global_operations": 64, "emergency_cancellations": 16, "storage_bytes": 16777216, "records": 256, "cancellation_reserve_bytes": 4096} {
		min := 1
		if k == "cancellation_reserve_bytes" {
			min = 4096
		}
		for _, c := range []struct {
			value int
			valid bool
		}{{min, true}, {max, true}, {min - 1, false}, {max + 1, false}} {
			m := fixture()
			m["limits"].(map[string]any)[k] = c.value
			if err := validateFixture(m); (err == nil) != c.valid {
				t.Errorf("%s=%d valid=%v: %v", k, c.value, c.valid, err)
			}
		}
	}
}

func TestReferencesOrderingAndAliases(t *testing.T) {
	alias := func(id string) any {
		return map[string]any{"target": "target", "kind": "kind", "resource_id": id, "canonical_target": "remote", "canonical_resource": "shared"}
	}
	effect := func(class string, destructive bool) any {
		return map[string]any{"class": class, "summary_id": "read", "decision": "delegated", "destructive": destructive}
	}
	target := func(host string, port int) any { return map[string]any{"protocol": "tcp", "host": host, "port": port} }
	cases := []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"valid alias", func(m map[string]any) { m["aliases"] = []any{alias("a"), alias("b")} }, true},
		{"alias duplicate", func(m map[string]any) { m["aliases"] = []any{alias("a"), alias("a")} }, false},
		{"alias reversed", func(m map[string]any) { m["aliases"] = []any{alias("b"), alias("a")} }, false},
		{"alias unknown kind", func(m map[string]any) {
			a := alias("a").(map[string]any)
			a["kind"] = "missing"
			m["aliases"] = []any{a}
		}, false},
		{"alias unknown target", func(m map[string]any) {
			a := alias("a").(map[string]any)
			a["target"] = "missing"
			m["aliases"] = []any{a}
		}, false},
		{"effect ordered bool", func(m map[string]any) { m["effects"] = []any{effect("read", false), effect("read", true)} }, true},
		{"effect duplicate", func(m map[string]any) { m["effects"] = []any{effect("read", false), effect("read", false)} }, false},
		{"effect reversed", func(m map[string]any) { m["effects"] = []any{effect("read", true), effect("read", false)} }, false},
		{"schema duplicate", func(m map[string]any) { s := m["schemas"].([]any)[0]; m["schemas"] = []any{s, s} }, false},
		{"schema reversed", func(m map[string]any) {
			s := m["schemas"].([]any)[0].(map[string]any)
			other := map[string]any{"id": "a", "digest": s["digest"], "document": s["document"]}
			m["schemas"] = []any{s, other}
		}, false},
		{"network ordered numeric", func(m map[string]any) {
			m["network"].(map[string]any)["policy"] = "allow_list"
			m["network"].(map[string]any)["targets"] = []any{target("a.example", 2), target("a.example", 10)}
		}, true},
		{"network duplicate", func(m map[string]any) {
			m["network"].(map[string]any)["policy"] = "allow_list"
			m["network"].(map[string]any)["targets"] = []any{target("a.example", 2), target("a.example", 2)}
		}, false},
		{"network reversed", func(m map[string]any) {
			m["network"].(map[string]any)["policy"] = "allow_list"
			m["network"].(map[string]any)["targets"] = []any{target("a.example", 10), target("a.example", 2)}
		}, false},
		{"unsupported schema", func(m map[string]any) {
			s := m["schemas"].([]any)[0].(map[string]any)
			doc := s["document"].(map[string]any)
			doc["$ref"] = "#"
			raw, _ := json.Marshal(doc)
			b, _ := canonicaljson.Canonicalize(raw)
			h := sha256.Sum256(append([]byte("ssjack-schema-v1\x00"), b...))
			s["digest"] = hex.EncodeToString(h[:])
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := fixture()
			c.mutate(m)
			err := validateFixture(m)
			if (err == nil) != c.valid {
				t.Fatalf("valid=%v: %v", c.valid, err)
			}
		})
	}
}
