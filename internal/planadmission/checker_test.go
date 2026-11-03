package planadmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/planbinding"
)

const schema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"capacity":{"maximum":10,"minimum":1,"type":"integer"}},"required":["capacity"],"type":"object"}`

func configuration() Config {
	h := sha256.Sum256([]byte("ssjack-schema-v1\x00" + schema))
	return Config{Document: []byte(schema), ID: "schema", Digest: hex.EncodeToString(h[:]), Target: "target", Kind: "cache"}
}

func now() time.Time { return time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC) }

func binding(config Config) map[string]any {
	d := strings.Repeat("a", 64)
	effects := sha256.Sum256([]byte("ssjack-effects-v1\x00[]"))
	return map[string]any{
		"protocol": 1, "plan_id": "AAAAAAAAAAAAAAAAAAAAAA", "session_id": "AAAAAAAAAAAAAAAAAAAAAA",
		"declaration": map[string]any{"kind": config.Kind, "schema_id": config.ID, "schema_digest": config.Digest, "resource_id": "r", "target": config.Target},
		"target":      config.Target, "resource_id": "r", "canonical_target": "target1", "canonical_resource": "r1",
		"driver_id": "driver", "driver_protocol": 1, "code_digest": d, "dependency_digests": map[string]any{}, "configuration_digest": d, "artifact_digests": map[string]any{"main": d},
		"principal": map[string]any{"issuer": "issuer", "subject": "subject"}, "kind": config.Kind,
		"schema_id": config.ID, "schema_digest": config.Digest, "policy_revision": "rev", "precondition": nil,
		"desired_schema_id": config.ID, "desired_schema_digest": config.Digest, "desired": map[string]any{"capacity": 1},
		"effects": []any{}, "effect_digest": hex.EncodeToString(effects[:]), "projection_schema_id": "projection", "projection_schema_digest": d, "enrollment_digest": d,
		"created_at": "2026-01-01T00:00:00.000Z", "expires_at": "2026-01-01T00:01:00.000Z",
	}
}

func encode(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFixedPinAdmitsDesiredAndOwnsSchema(t *testing.T) {
	cfg := configuration()
	checker, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, binding(cfg))
	expected, err := planbinding.ValidateAt(raw, now())
	if err != nil {
		t.Fatal(err)
	}
	clear(cfg.Document)
	cfg.ID = "other"
	cfg.Digest = strings.Repeat("b", 64)
	cfg.Target = "elsewhere"
	cfg.Kind = "other"
	saved := append([]byte(nil), raw...)
	got, err := checker.Check(raw, now())
	if err != nil || got != expected || !bytes.Equal(saved, raw) {
		t.Fatalf("pin ownership/digest: %v", err)
	}
}

func TestSchemaAndCorrelationFailuresAreNotMaskedByStructure(t *testing.T) {
	cfg := configuration()
	checker, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"range":   func(m map[string]any) { m["desired"] = map[string]any{"capacity": 11} },
		"type":    func(m map[string]any) { m["desired"] = map[string]any{"capacity": "one"} },
		"missing": func(m map[string]any) { m["desired"] = map[string]any{} },
		"extra":   func(m map[string]any) { m["desired"] = map[string]any{"capacity": 1, "extra": true} },
		"target":  func(m map[string]any) { m["target"] = "other"; m["declaration"].(map[string]any)["target"] = "other" },
		"kind":    func(m map[string]any) { m["kind"] = "other"; m["declaration"].(map[string]any)["kind"] = "other" },
		"id": func(m map[string]any) {
			m["schema_id"] = "other"
			m["desired_schema_id"] = "other"
			m["declaration"].(map[string]any)["schema_id"] = "other"
		},
		"digest": func(m map[string]any) {
			d := strings.Repeat("b", 64)
			m["schema_digest"] = d
			m["desired_schema_digest"] = d
			m["declaration"].(map[string]any)["schema_digest"] = d
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := binding(cfg)
			mutate(m)
			raw := encode(t, m)
			if _, err := planbinding.ValidateAt(raw, now()); err != nil {
				t.Fatalf("fixture failed before schema/correlation check: %v", err)
			}
			if digest, err := checker.Check(raw, now()); err != ErrInvalid || digest != "" {
				t.Fatalf("accepted invalid pin/value: %v", err)
			}
		})
	}
}

func TestInvalidPinAndZeroChecker(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.Document = nil },
		func(c *Config) { c.Document = bytes.Repeat([]byte{' '}, canonicaljson.MaxInput+1) },
		func(c *Config) { c.Document = []byte(`{"type":"unknown"}`) },
		func(c *Config) {
			c.Document = bytes.Replace(c.Document, []byte(`"maximum":10`), []byte(`"maximum":9`), 1)
		},
		func(c *Config) { c.ID = "Bad" },
		func(c *Config) { c.Digest = strings.Repeat("A", 64) },
		func(c *Config) { c.Target = "" },
		func(c *Config) { c.Kind = "Bad" },
	}
	for i, mutate := range cases {
		cfg := configuration()
		mutate(&cfg)
		if checker, err := New(cfg); !errors.Is(err, ErrPin) || checker != nil {
			t.Fatalf("pin case %d accepted: %v", i, err)
		}
	}
	var empty Checker
	for _, checker := range []*Checker{nil, &empty} {
		if digest, err := checker.Check(nil, now()); !errors.Is(err, ErrPin) || digest != "" {
			t.Fatal("zero checker accepted")
		}
	}
}

func TestPinnedCheckRetainsStructuralAndClockGates(t *testing.T) {
	cfg := configuration()
	checker, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, binding(cfg))
	for _, tc := range []struct {
		raw   []byte
		clock time.Time
	}{
		{nil, now()},
		{append(append([]byte(nil), raw...), []byte(" {}")...), now()},
		{bytes.Repeat([]byte{' '}, canonicaljson.MaxInput+1), now()},
		{raw, time.Time{}},
		{raw, now().Add(time.Minute)},
	} {
		if digest, err := checker.Check(tc.raw, tc.clock); err != ErrInvalid || digest != "" {
			t.Fatal("structural/clock gate bypassed", err)
		}
	}
}
