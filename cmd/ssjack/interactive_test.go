package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func TestShellOutcomeFailsClosedOnlyWhenInputNotReleased(t *testing.T) {
	for _, err := range []error{
		remote.ErrInputNotReleased,
		errors.Join(context.Canceled, remote.ErrInputNotReleased),
	} {
		if resume, fatal := shellOutcome(1, err); resume || fatal == nil {
			t.Fatal("unreleased terminal input must not resume the picker")
		}
	}
	for _, tc := range []struct {
		code int
		err  error
	}{{0, nil}, {7, nil}, {1, errors.New("ordinary failure")}, {1, context.Canceled}} {
		if resume, fatal := shellOutcome(tc.code, tc.err); !resume || fatal != nil {
			t.Fatal("ordinary shell outcome must resume the picker")
		}
	}
}

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

func TestSharedShellRejectsMissingConfigurationWithoutTerminal(t *testing.T) {
	if code, err := runShell(context.Background(), nil, "example.test:22"); code != 1 || err == nil {
		t.Fatal("shared shell accepted a missing client configuration")
	}
	if code, err := runShell(context.Background(), &ssh.ClientConfig{}, ""); code != 1 || err == nil {
		t.Fatal("shared shell accepted an empty address")
	}
}
