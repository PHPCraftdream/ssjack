package routes

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestFlagsAndResolution(t *testing.T) {
	t.Run("flag_set_accepts_valid_and_parses_route", func(t *testing.T) {
		var flags Flags
		if err := flags.Set("alpha=incus:box:user"); err != nil {
			t.Fatal("valid route rejected")
		}
		if got := flags.Overrides()["alpha"]; got != "incus:box:user" {
			t.Fatalf("route = %q", got)
		}
	})
	t.Run("flag_set_rejects_malformed", func(t *testing.T) {
		for _, value := range []string{"alpha", "alpha=ssh:box:user", "alpha=incus:box", "alpha=incus:bad;box:user", "alpha=incus:box:--bad", "=incus:box:user", "Bad=incus:box:user", "a_b=incus:box:user"} {
			var flags Flags
			if err := flags.Set(value); err == nil {
				t.Fatalf("malformed flag accepted: %s", value)
			}
		}
	})
	t.Run("flag_set_rejects_duplicate_app", func(t *testing.T) {
		var flags Flags
		if err := flags.Set("alpha=incus:box:user"); err != nil {
			t.Fatal("first route rejected")
		}
		if err := flags.Set("alpha=incus:box:user"); err == nil || !strings.Contains(err.Error(), "alpha") {
			t.Fatal("duplicate route accepted")
		}
		if err := flags.Set("beta=incus:box:user"); err != nil || len(flags) != 2 {
			t.Fatal("different application route rejected")
		}
	})
	t.Run("check_enabled_rejects_unknown_app", func(t *testing.T) {
		var flags Flags
		if err := flags.Set("alpha=incus:box:user"); err != nil {
			t.Fatal("route rejected")
		}
		if flags.CheckEnabled(map[string]bool{"beta": true}) == nil {
			t.Fatal("unknown app accepted")
		}
		if err := flags.CheckEnabled(map[string]bool{"alpha": true}); err != nil {
			t.Fatal("enabled app rejected")
		}
	})
	t.Run("resolve_precedence_matrix", func(t *testing.T) {
		got := Resolve(map[string]string{"flag": "incus:flagbox:flaguser"}, map[string]string{"flag": "incus:vaultbox:vaultuser", "vault": "incus:vaultbox:vaultuser"}, "globalbox", "globaluser", []string{"flag", "vault", "global", "none"})
		want := map[string]Spec{
			"flag":   {Container: "flagbox", User: "flaguser"},
			"vault":  {Container: "vaultbox", User: "vaultuser"},
			"global": {Container: "globalbox", User: "globaluser"},
			"none":   {Container: "globalbox", User: "globaluser"},
		}
		for name, spec := range want {
			if got[name] != spec {
				t.Fatalf("%s resolved to %+v", name, got[name])
			}
		}
	})
	t.Run("vault_routes_apply_only_to_discovered", func(t *testing.T) {
		got := VaultRoutes([]vault.Approval{{Name: "found", Route: "incus:box:user"}, {Name: "explicit", Route: "incus:other:user"}, {Name: "empty"}}, map[string]bool{"found": true})
		if len(got) != 1 || got["found"] != "incus:box:user" {
			t.Fatalf("vault routes = %+v", got)
		}
	})
}
