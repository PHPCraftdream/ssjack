//go:build linux && amd64

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestNativeRemoteMCPStartupChild(t *testing.T) {
	if os.Getenv("SSJACK_REMOTE_MCP_STARTUP_CHILD") != "1" {
		t.Skip("native startup child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("startup child lacks real terminal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	scenario := os.Getenv("SSJACK_REMOTE_MCP_STARTUP_SCENARIO")
	var args []string
	for i, argument := range os.Args {
		if argument == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	path := remoteMCPStartupVaultArg(args)
	if path == "" {
		t.Fatal("startup child lacks its vault path")
	}
	profile := remoteMCPStartupProfileArg(args)
	if profile == "" {
		t.Fatal("startup child lacks its SSH profile")
	}
	if scenario == "mcp-nonterminal-refusal" {
		remoteMCPNonterminalRefusalChild(t, ctx, path, profile)
		return
	}
	if scenario == "prepared-launch-no-output-filter" {
		remoteMCPPreparedLaunchChild(t, ctx, path, profile)
		return
	}
	code, err := run(ctx, args)
	if expected := remoteMCPExpectedRunRefusal(scenario); expected != "" {
		if code != 1 || err == nil || err.Error() != expected {
			t.Fatal("startup child returned an unexpected refusal result")
		}
		fmt.Fprintln(os.Stdout, remoteMCPRefusalMarker(scenario))
		return
	}
	if err != nil || code != 0 {
		t.Fatal("confirmed startup child did not complete successfully")
	}
}

func TestNativeRemoteMCPStartupHarness(t *testing.T) {
	if os.Getenv("SSJACK_REMOTE_MCP_STARTUP_CHILD") != "1" {
		t.Skip("native startup harness only")
	}
	fmt.Fprintln(os.Stdout, "REMOTE-MCP-HARNESS-RAN")
}

func nativeStartupEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" && !strings.HasPrefix(key, "SSJACK_OWNER_") {
			env = append(env, entry)
		}
	}
	return append(env, "TERM=xterm-256color", "NO_COLOR=1")
}

func remoteMCPStartupProfileArg(args []string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--profile" {
			return args[index+1]
		}
	}
	return ""
}
