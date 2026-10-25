package main

import (
	"context"
	"testing"

	"storagehost/internal/vault"
)

func TestDefaultProfileIsMainWithoutFallback(t *testing.T) {
	v := vault.New()
	defer v.Close()
	v.Targets["work"] = vault.Target{}
	if _, err := chooseCredential(v, ""); err == nil {
		t.Fatal("missing main silently selected another profile")
	}
	v.Targets["main"] = vault.Target{}
	for _, test := range []struct{ input, want string }{{"", "main"}, {"main", "main"}, {"work", "work"}} {
		name, err := chooseCredential(v, test.input)
		if err != nil || name != test.want {
			t.Fatalf("profile %q: got %q %v", test.input, name, err)
		}
	}
	for _, name := range []string{"missing", "../invalid"} {
		if _, err := chooseCredential(v, name); err == nil {
			t.Fatal("unknown or malformed profile was accepted")
		}
	}
}

func TestProfileModeValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "legacy", "run", "claude"},
		{"ssh", "positional-profile"},
		{"--generate-key", "new", "run", "claude"},
		{"run"},
		{"-p", "../invalid", "ssh"},
		{"--profile", "../invalid", "edit"},
	} {
		if code, err := run(context.Background(), args); code == 0 || err == nil {
			t.Fatalf("invalid profile mode accepted: %v", args)
		}
	}
}
