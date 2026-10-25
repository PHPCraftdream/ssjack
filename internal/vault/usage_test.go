package vault

import (
	"strings"
	"testing"
)

func TestUsageCompatibilityAndGates(t *testing.T) {
	for _, usage := range []string{"", "both", "human", "agent"} {
		target := testTarget(t)
		target.Usage = usage
		v := New()
		v.Targets["record"] = target
		encoded, err := marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if usage == "" && strings.Contains(string(encoded), "usage:") {
			t.Fatal("legacy record acquired an implicit policy field")
		}
		decoded, err := unmarshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"human", "agent"} {
			err := decoded.Targets["record"].RequireUsage(mode)
			allowed := usage == "" || usage == "both" || usage == mode
			if (err == nil) != allowed {
				t.Fatalf("usage=%q mode=%q error=%v", usage, mode, err)
			}
		}
		decoded.Close()
		v.Close()
	}
	target := testTarget(t)
	defer clear(target.PrivateKey)
	target.Usage = "readonly"
	if err := target.Validate(); err == nil {
		t.Fatal("unsupported client-side readonly policy was accepted")
	}
	if err := target.RequireUsage("unknown"); err == nil {
		t.Fatal("unknown caller mode was accepted")
	}
}
