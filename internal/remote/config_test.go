package remote

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKtavExampleAndStrictFields(t *testing.T) {
	config, err := LoadConfig(filepath.Join("..", "..", ".ssh", "ssjack.example.ktav"))
	if err != nil {
		t.Fatal(err)
	}
	target := config.Targets["storagehost"]
	if target.User != "mcp-agent" || target.Address != "CHANGE_ME:22" || target.Key != "storage" || config.Keys["storage"] == "" {
		t.Fatalf("unexpected example configuration: %+v", config)
	}
	const valid = "keys.storage: key\ntargets.test.address: localhost:22\ntargets.test.user: user\ntargets.test.key: storage\ntargets.test.known_hosts: known_hosts\n"
	path := filepath.Join(t.TempDir(), "config.ktav")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"unknown: true\n", "targets.test.typo: true\n"} {
		if err := os.WriteFile(path, []byte(valid+extra), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("unknown configuration field was accepted")
		}
	}
}
