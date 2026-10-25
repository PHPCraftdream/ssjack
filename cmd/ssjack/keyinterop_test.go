package main

import "testing"

func TestExportSecretMustBeIndependent(t *testing.T) {
	for _, pair := range []struct{ export, vault string }{{"", "vault"}, {"export", ""}, {"same", "same"}} {
		if err := validateExportSecret([]byte(pair.export), []byte(pair.vault)); err == nil {
			t.Fatal("empty authorization or reused vault secret was accepted")
		}
	}
	if err := validateExportSecret([]byte("separate export secret"), []byte("vault secret")); err != nil {
		t.Fatal(err)
	}
}
