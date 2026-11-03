package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestInteractiveFlagRejectsCommandAndOtherModesBeforeUnlock(t *testing.T) {
	for _, args := range [][]string{
		{"--interactive", "ssh"},
		{"--interactive", "--generate-key", "unused"},
		{"--interactive", "--version"},
		{"--interactive", "--mode", "declarative"},
	} {
		code, err := run(context.Background(), args)
		if code != 1 || err == nil || !strings.Contains(err.Error(), "--interactive accepts only") {
			t.Fatal("interactive mode accepted a conflicting operation")
		}
	}
}

func TestInteractiveRequiresTerminalBeforeUnlock(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	code, err := run(context.Background(), []string{"--interactive", "--vault", "nonexistent-synthetic-database"})
	if code != 1 || err == nil || !strings.Contains(err.Error(), "requires a trusted input and output terminal") {
		t.Fatal("nonterminal interactive mode reached database unlock")
	}
}

func TestMissingCommandNeverStartsInteractiveEditor(t *testing.T) {
	code, err := run(context.Background(), nil)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "specify a command") {
		t.Fatal("missing command implicitly entered the owner editor")
	}
}
