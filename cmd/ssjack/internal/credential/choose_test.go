package credential

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestDefaultProfileIsMainWithoutFallback(t *testing.T) {
	v := vault.New()
	defer v.Close()
	v.Targets["work"] = vault.Target{}
	if _, err := ChooseCredential(v, ""); err == nil {
		t.Fatal("missing main silently selected another profile")
	}
	v.Targets["main"] = vault.Target{}
	for _, test := range []struct{ input, want string }{{"", "main"}, {"main", "main"}, {"work", "work"}} {
		name, err := ChooseCredential(v, test.input)
		if err != nil || name != test.want {
			t.Fatalf("profile %q: got %q %v", test.input, name, err)
		}
	}
	for _, name := range []string{"missing", "../invalid"} {
		if _, err := ChooseCredential(v, name); err == nil {
			t.Fatal("unknown or malformed profile was accepted")
		}
	}
}

func TestNamedCredentialSelectionNeverFallsBackAcrossAccounts(t *testing.T) {
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Close()
	v.Version, v.Servers, v.Secrets = 2, make(map[string]vault.Server), make(map[string]vault.SecretBinding)
	target := vault.Target{Address: "example.invalid:22", User: "deploy", Password: []byte("synthetic-deploy-password"), HostKeys: []string{string(ssh.MarshalAuthorizedKey(key))}}
	server, err := v.AddServer("production", "deploy", target)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ChooseCredential(v, "@production")
	if err != nil || first != v.Servers[server].Accounts["deploy"] {
		t.Fatal("single-account server did not resolve exactly")
	}
	target.User, target.Password = "maintenance", []byte("synthetic-maintenance-password")
	if err := v.SetAccount(server, "maintenance", target); err != nil {
		t.Fatal(err)
	}
	if _, err := ChooseCredential(v, "@production"); err == nil || !strings.Contains(err.Error(), "--account") {
		t.Fatal("ambiguous server silently chose an account")
	}
	for _, account := range []string{"deploy", "maintenance"} {
		selected, err := ChooseCredential(v, "@production/"+account)
		if err != nil || selected != v.Servers[server].Accounts[account] {
			t.Fatal("named account resolved another credential identity")
		}
	}
	for _, selector := range []string{"@missing", "@Production/deploy", "@production/missing", "@production/", "@production/deploy/extra"} {
		if _, err := ChooseCredential(v, selector); err == nil {
			t.Fatal("unknown or malformed selection fell back")
		}
	}
	legacy := vault.New()
	defer legacy.Close()
	if _, err := ChooseCredential(legacy, "@production/deploy"); err == nil || !strings.Contains(err.Error(), "directory payload schema v2") {
		t.Fatal("legacy database silently acquired directory semantics")
	}
}
