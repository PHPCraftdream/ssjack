package main

import "testing"

func TestLegacyVaultMutationClassification(t *testing.T) {
	for _, action := range []string{"passwd", "add", "edit", "remove", "import"} {
		if !writesVault(action) {
			t.Fatalf("legacy mutation %s lacks early writer admission", action)
		}
	}
	for _, action := range []string{"list", "show", "public", "export"} {
		if writesVault(action) {
			t.Fatalf("read-only capture %s unnecessarily claims the database", action)
		}
	}
}
