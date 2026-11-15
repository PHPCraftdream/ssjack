package main

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

func remoteMCPStartupDrive(t *testing.T, ctx context.Context, scenario string, fixture *remoteMCPStartupFixture, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture) {
	t.Helper()
	wait := func(text string) {
		t.Helper()
		childCaptureWaitDiag(t, ctx, capture, text, "native startup missed terminal text "+text)
		fixture.phases.mark("saw " + text)
	}
	if scenario != "mcp-nonterminal-refusal" && scenario != "prepared-launch-no-output-filter" {
		wait("Vault secret:")
		ending := byte('\n')
		if runtime.GOOS == "windows" {
			ending = '\r'
		}
		input := append(append([]byte(nil), fixture.password...), ending)
		_, writeErr := terminal.Input.Write(input)
		clear(input)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		fixture.phases.mark("password input")
	}
	interactive := scenario != "absent-directory" && scenario != "mcp-nonterminal-refusal"
	if interactive {
		wait("Select MCP connections for SSH profile " + strconv.Quote(fixture.profile))
		wait("Continue")
	}
	if scenario == "receipt-remembered" || scenario == "empty" || scenario == "prepared-launch-no-output-filter" {
		if !capture.Contains([]byte("[x]")) {
			t.Fatal("nonempty remembered binding was not shown as a suggestion")
		}
	} else if scenario != "no-record" && scenario != "absent-directory" && scenario != "mcp-nonterminal-refusal" && !capture.Contains([]byte("[ ]")) {
		t.Fatal("first-use singleton was not left unchecked")
	}
	if scenario == "no-record" && !capture.Contains([]byte("(No remote MCP accounts configured.)")) {
		t.Fatal("empty MCP directory did not present its explicit Continue choice")
	}
	if scenario == "stale-ciphertext" {
		origin, err := os.ReadFile(fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		mutated := append(append([]byte(nil), origin...), 0)
		if err := os.WriteFile(fixture.path, mutated, 0600); err != nil {
			t.Fatal(err)
		}
		fixture.expectedFinal = mutated
		clear(origin)
	}
	if scenario == "connected-empty" && (fixture.connected.authorized.Load() != 0 || fixture.connected.rejected.Load() != 0 || fixture.connected.calls.Load() != 0 || fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0) {
		t.Fatal("confirmed empty choice contacted or called an upstream")
	}
	if scenario == "connected-cancel" && (fixture.connected.authorized.Load() != 0 || fixture.connected.rejected.Load() != 0 || fixture.connected.calls.Load() != 0 || fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0) {
		t.Fatal("cancelled selection contacted or called an upstream")
	}
	switch scenario {
	case "connected-basic", "connected-bypass", "connected-active-cancel":
		if _, err := terminal.Input.Write([]byte(" ")); err != nil {
			t.Fatal("cannot toggle confirmed account")
		}
		if _, err := terminal.Input.Write([]byte("\t\t\r")); err != nil {
			t.Fatal("cannot confirm selected account")
		}
	case "connected-empty":
		if _, err := terminal.Input.Write([]byte("\t\t\r")); err != nil {
			t.Fatal("cannot confirm empty account choice")
		}
	case "connected-cancel":
		if _, err := terminal.Input.Write([]byte("q")); err != nil {
			t.Fatal("cannot cancel before account launch")
		}
	case "cancel":
		_, _ = terminal.Input.Write([]byte("q"))
	case "esc":
		_, _ = terminal.Input.Write([]byte{27})
	case "ctrl-c":
		_, _ = terminal.Input.Write([]byte{3})
	case "continue", "stale-ciphertext", "issue-refusal":
		_, _ = terminal.Input.Write([]byte(" \t\r"))
	case "receipt-remembered":
		_, _ = terminal.Input.Write([]byte("\t\r"))
	case "empty":
		_, _ = terminal.Input.Write([]byte(" \t\r"))
	case "prepared-launch-no-output-filter":
		_, _ = terminal.Input.Write([]byte("\t\r"))
	case "mcp-nonterminal-refusal", "absent-directory":
		// Nonterminal refusal uses the production loader directly; an absent
		// directory intentionally has no selector or mandatory interaction.
	default:
		_, _ = terminal.Input.Write([]byte("\r"))
	}
	fixture.phases.mark("drive inputs sent")
}
