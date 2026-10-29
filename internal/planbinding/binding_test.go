package planbinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/domaindigest"
)

func fixture(t *testing.T) map[string]any {
	t.Helper()
	d := strings.Repeat("a", 64)
	m := map[string]any{
		"protocol": 1, "plan_id": "AAAAAAAAAAAAAAAAAAAAAA", "session_id": "AAAAAAAAAAAAAAAAAAAAAA",
		"declaration": map[string]any{"kind": "cache", "schema_id": "schema", "schema_digest": d, "resource_id": "r", "target": "target"},
		"target":      "target", "resource_id": "r", "canonical_target": "target1", "canonical_resource": "r1", "driver_id": "driver", "driver_protocol": 1,
		"code_digest": d, "dependency_digests": map[string]any{}, "configuration_digest": d, "artifact_digests": map[string]any{"main": d},
		"principal": map[string]any{"issuer": "issuer", "subject": "subject"}, "kind": "cache", "schema_id": "schema", "schema_digest": d,
		"policy_revision": "rev", "precondition": nil, "desired_schema_id": "schema", "desired_schema_digest": d, "desired": map[string]any{"capacity": 1},
		"effects":              []any{map[string]any{"class": "read", "summary_id": "ok", "destructive": false}},
		"projection_schema_id": "projection", "projection_schema_digest": d, "enrollment_digest": d,
		"created_at": "2026-01-01T00:00:00.000Z", "expires_at": "2026-01-01T00:01:00.000Z",
	}
	setEffectDigest(t, m)
	return m
}

func setEffectDigest(t *testing.T, m map[string]any) {
	t.Helper()
	b, err := json.Marshal(m["effects"])
	if err != nil {
		t.Fatal(err)
	}
	d, err := domaindigest.Sum(domaindigest.Effects, b)
	if err != nil {
		t.Fatal(err)
	}
	m["effect_digest"] = d
}

func encode(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidAndDigest(t *testing.T) {
	b := encode(t, fixture(t))
	got, err := Validate(b)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicaljson.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte("ssjack-plan-v1\x00"), canonical...))
	if got != hex.EncodeToString(h[:]) {
		t.Fatal("wrong domain digest")
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	again, err := Validate(pretty.Bytes())
	if err != nil || again != got {
		t.Fatal("canonical identity differs", err)
	}
}

func TestSortedEffectsAndDigestMaps(t *testing.T) {
	m := fixture(t)
	m["effects"] = []any{
		map[string]any{"class": "read", "summary_id": "alpha", "destructive": false},
		map[string]any{"class": "read", "summary_id": "beta", "destructive": false},
		map[string]any{"class": "write", "summary_id": "alpha", "destructive": true},
	}
	m["artifact_digests"] = map[string]any{"alpha": strings.Repeat("a", 64), "beta": strings.Repeat("b", 64)}
	m["dependency_digests"] = map[string]any{"alpha": strings.Repeat("c", 64), "beta": strings.Repeat("d", 64)}
	setEffectDigest(t, m)
	b := encode(t, m)
	got, err := Validate(b)
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	again, err := Validate(pretty.Bytes())
	if err != nil || again != got {
		t.Fatal("canonical identity differs", err)
	}
	m["dependency_digests"].(map[string]any)["beta"] = strings.Repeat("e", 64)
	changed, err := Validate(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if changed == got {
		t.Fatal("dependency change did not change plan digest")
	}
}

func TestRejectMutations(t *testing.T) {
	tests := map[string]func(map[string]any){
		"missing":              func(m map[string]any) { delete(m, "plan_id") },
		"extra":                func(m map[string]any) { m["effect_schema_id"] = "x" },
		"protocol":             func(m map[string]any) { m["protocol"] = true },
		"id":                   func(m map[string]any) { m["plan_id"] = "bad" },
		"digest":               func(m map[string]any) { m["code_digest"] = strings.Repeat("A", 64) },
		"principal null":       func(m map[string]any) { m["principal"] = nil },
		"principal field null": func(m map[string]any) { m["principal"] = map[string]any{"issuer": nil, "subject": "s"} },
		"principal too long": func(m map[string]any) {
			m["principal"] = map[string]any{"issuer": strings.Repeat("x", 257), "subject": "s"}
		},
		"schema equality":      func(m map[string]any) { m["desired_schema_id"] = "other" },
		"declaration equality": func(m map[string]any) { m["target"] = "other" },
		"declaration extra":    func(m map[string]any) { m["declaration"].(map[string]any)["desired"] = map[string]any{} },
		"precondition":         func(m map[string]any) { m["precondition"] = false },
		"time":                 func(m map[string]any) { m["created_at"] = "2026-02-30T00:00:00.000Z" },
		"desired type":         func(m map[string]any) { m["desired"] = nil },
		"desired size":         func(m map[string]any) { m["desired"] = map[string]any{"v": strings.Repeat("x", 32768)} },
		"effects digest":       func(m map[string]any) { m["effect_digest"] = strings.Repeat("0", 64) },
		"empty artifacts":      func(m map[string]any) { m["artifact_digests"] = map[string]any{} },
		"null dependencies":    func(m map[string]any) { m["dependency_digests"] = nil },
		"bad map digest":       func(m map[string]any) { m["dependency_digests"] = map[string]any{"x": "bad"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			m := fixture(t)
			mutate(m)
			if _, err := Validate(encode(t, m)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRejectEffectsWithMatchingDigest(t *testing.T) {
	tests := map[string][]any{
		"null destructive": {map[string]any{"class": "read", "summary_id": "ok", "destructive": nil}},
		"missing field":    {map[string]any{"class": "read", "summary_id": "ok"}},
		"extra field":      {map[string]any{"class": "read", "summary_id": "ok", "destructive": false, "extra": true}},
		"duplicate": {
			map[string]any{"class": "read", "summary_id": "ok", "destructive": false},
			map[string]any{"class": "read", "summary_id": "ok", "destructive": false},
		},
		"ambiguous destructive": {
			map[string]any{"class": "read", "summary_id": "ok", "destructive": false},
			map[string]any{"class": "read", "summary_id": "ok", "destructive": true},
		},
		"unsorted": {
			map[string]any{"class": "z", "summary_id": "x", "destructive": false},
			map[string]any{"class": "a", "summary_id": "x", "destructive": false},
		},
	}
	for name, effects := range tests {
		t.Run(name, func(t *testing.T) {
			m := fixture(t)
			m["effects"] = effects
			setEffectDigest(t, m)
			if _, err := Validate(encode(t, m)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRejectRaw(t *testing.T) {
	b := string(encode(t, fixture(t)))
	d := strings.Repeat("a", 64)
	cases := []string{
		strings.Replace(b, `"protocol":1`, `"protocol":1,"protocol":1`, 1),
		strings.Replace(b, `"protocol":1`, `"protocol":1.0`, 1),
		b + " {}",
		strings.Replace(b, `"desired":{`, `"desired":{"x":"\u0000",`, 1),
		strings.Replace(b, `"dependency_digests":{}`, `"dependency_digests":{"z":"`+d+`","a":"`+d+`"}`, 1),
		strings.Replace(b, `"artifact_digests":{"main":"`+d+`"}`, `"artifact_digests":{"z":"`+d+`","a":"`+d+`"}`, 1),
	}
	for _, raw := range cases {
		if _, err := Validate([]byte(raw)); err == nil {
			t.Fatal("accepted invalid raw input")
		}
	}
}

func TestEmptyEffectsAndPrincipal(t *testing.T) {
	m := fixture(t)
	m["effects"] = []any{}
	m["principal"] = map[string]any{"issuer": "", "subject": ""}
	setEffectDigest(t, m)
	if _, err := Validate(encode(t, m)); err != nil {
		t.Fatal(err)
	}
}
