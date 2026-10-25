package vault

import (
	"bytes"
	"testing"
)

func TestServerPinReplacementPreservesCredentials(t *testing.T) {
	v := New()
	defer v.Close()
	original := testTarget(t)
	original.Usage = "human"
	v.Targets["home"] = original
	if err := v.ReplaceHostKeys("home", []string{"invalid"}); err == nil {
		t.Fatal("invalid server key was accepted")
	}
	other := testTarget(t)
	defer clear(other.PrivateKey)
	pins := append([]string(nil), other.HostKeys...)
	if err := v.ReplaceHostKeys("home", pins); err != nil {
		t.Fatal(err)
	}
	pins[0] = "caller mutation"
	updated := v.Targets["home"]
	if updated.Address != original.Address || updated.User != original.User || updated.Usage != original.Usage || !bytes.Equal(updated.PrivateKey, original.PrivateKey) {
		t.Fatal("host pin replacement changed credential identity or usage")
	}
	if updated.HostKeys[0] != other.HostKeys[0] {
		t.Fatal("host pin replacement did not own its input")
	}
	if err := v.ReplaceHostKeys("missing", other.HostKeys); err == nil {
		t.Fatal("host pin replacement created an incomplete record")
	}
}
