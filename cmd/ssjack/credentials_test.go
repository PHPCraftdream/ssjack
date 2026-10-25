package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"storagehost/internal/vault"
)

func TestNamedCredentialsSelection(t *testing.T) {
	v := vault.New()
	defer v.Close()
	v.Targets["beta"] = vault.Target{}
	v.Targets["alpha"] = vault.Target{}
	unexpectedPrompt := func(_ []string) (string, error) {
		t.Fatal("explicit credential name prompted for another selection")
		return "", nil
	}
	if name, err := chooseCredential(v, "beta", unexpectedPrompt); err != nil || name != "beta" {
		t.Fatalf("explicit selection: %q %v", name, err)
	}
	if _, err := chooseCredential(v, "missing", unexpectedPrompt); err == nil {
		t.Fatal("unknown credential name was accepted")
	}
	name, err := chooseCredential(v, "", func(names []string) (string, error) {
		if !reflect.DeepEqual(names, []string{"alpha", "beta"}) {
			t.Fatalf("unsorted choices: %v", names)
		}
		return "alpha", nil
	})
	if err != nil || name != "alpha" {
		t.Fatalf("interactive selection: %q %v", name, err)
	}
	delete(v.Targets, "alpha")
	if name, err := chooseCredential(v, "", unexpectedPrompt); err != nil || name != "beta" {
		t.Fatal("single record was not selected")
	}
	delete(v.Targets, "beta")
	if _, err := chooseCredential(v, "", unexpectedPrompt); err == nil {
		t.Fatal("empty vault was accepted")
	}
}

func TestCredentialModeValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--config", "legacy", "run", "selected", "claude", "-c"},
		{"ssh", "selected", "claude"},
		{"--generate-key", "new", "run", "selected", "claude"},
		{"run", "selected"},
		{"run", "../invalid", "claude"},
	} {
		if code, err := run(context.Background(), args); code == 0 || err == nil {
			t.Fatalf("invalid credential mode accepted: %v", args)
		}
	}
	v := vault.New()
	v.Targets["one"] = vault.Target{}
	v.Targets["two"] = vault.Target{}
	defer v.Close()
	failure := errors.New("input cancelled")
	if _, err := chooseCredential(v, "", func(_ []string) (string, error) { return "", failure }); !errors.Is(err, failure) {
		t.Fatal("selection error was lost")
	}
	if _, err := chooseCredential(v, "", func(_ []string) (string, error) { return "outside", nil }); err == nil {
		t.Fatal("interactive selection escaped the vault")
	}
}
