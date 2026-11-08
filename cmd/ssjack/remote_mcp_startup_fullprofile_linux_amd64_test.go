//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultRemoteMCPStartupFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("native remote MCP startup acceptance is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	for _, scenario := range []string{"continue", "receipt-remembered", "empty", "no-record", "absent-directory", "cancel", "esc", "ctrl-c", "stale-ciphertext", "mcp-nonterminal-refusal", "issue-refusal", "prepared-launch-no-output-filter"} {
		t.Run(scenario, func(t *testing.T) { remoteMCPStartupPTY(t, ctx, scenario) })
	}
}

func remoteMCPStartupPTY(t *testing.T, parent context.Context, scenario string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	fixture := newRemoteMCPStartupFixture(t, ctx, scenario)
	defer clear(fixture.password)
	terminal, capture := remoteMCPStartupStart(t, ctx, fixture)
	defer remoteMCPTeardown(t, terminal, capture, fixture.password)
	remoteMCPStartupDrive(t, ctx, scenario, fixture, terminal, capture)
	shouldLaunch := scenario == "continue" || scenario == "receipt-remembered" || scenario == "empty" || scenario == "no-record" || scenario == "absent-directory"
	if scenario == "mcp-nonterminal-refusal" {
		if terminal.Wait(ctx) != nil {
			t.Fatal("MCP nonterminal-refusal child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte(remoteMCPRefusalMarker(scenario))) {
			t.Fatal("MCP nonterminal refusal did not join with its exact marker")
		}
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("MCP nonterminal refusal reached the harness")
		}
	} else if scenario == "prepared-launch-no-output-filter" {
		if terminal.Wait(ctx) != nil {
			t.Fatal("prepared-launch direct-loader child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte(remoteMCPPreparedMarker)) {
			t.Fatal("prepared-launch direct-loader output did not join with its positive marker")
		}
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("prepared-launch fixture invoked a fake bridge/harness")
		}
		if !capture.Contains([]byte("Remote MCP launch is prepared; no remote bridge is available.")) || capture.Contains([]byte("#357")) {
			t.Fatal("prepared-launch warning did not accurately describe the available capability")
		}
	} else if shouldLaunch {
		if terminal.Wait(ctx) != nil {
			t.Fatal("confirmed startup child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil {
			t.Fatal("confirmed startup output did not join")
		}
		if !capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("confirmed startup omitted harness marker")
		}
	} else {
		if terminal.Wait(ctx) != nil {
			t.Fatal("verified refusal child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil {
			t.Fatal("refusal child output did not join")
		}
		marker := remoteMCPRefusalMarker(scenario)
		if marker == "" || !capture.Contains([]byte(marker)) {
			t.Fatal("child did not emit its exact verified refusal marker")
		}
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("refused startup reached the harness")
		}
	}
	for _, refusal := range []string{"remote MCP selection cancelled; no database changes were made", "remote MCP capture could not validate the selected saved state", "remote MCP launch preparation failed", mcpdirectory.ErrChanged.Error()} {
		if capture.Contains([]byte(refusal)) {
			t.Fatal("verified refusal leaked its error text to the PTY")
		}
	}
	after, err := os.ReadFile(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if scenario == "stale-ciphertext" {
		if !bytes.Equal(fixture.expectedFinal, after) {
			t.Fatal("stale ciphertext refusal changed the database")
		}
	} else if scenario == "cancel" || scenario == "esc" || scenario == "ctrl-c" || scenario == "mcp-nonterminal-refusal" {
		if !bytes.Equal(fixture.expectedCiphertext, after) {
			t.Fatal("refusal changed ciphertext")
		}
	}
	if shouldLaunch && scenario != "empty" && scenario != "no-record" && scenario != "absent-directory" && bytes.Equal(fixture.expectedCiphertext, after) {
		t.Fatal("confirmed selection did not persist")
	}
	if scenario == "absent-directory" && !bytes.Equal(fixture.expectedCiphertext, after) {
		t.Fatal("startup without an MCP directory changed ciphertext")
	}
	if scenario == "issue-refusal" {
		if bytes.Equal(fixture.expectedCiphertext, after) {
			t.Fatal("confirmed launch refusal failed to persist its owner preference")
		}
		loaded, err := vault.Load(fixture.path, fixture.password)
		if err != nil {
			t.Fatal("launch refusal cleanup left the encrypted database unreadable")
		}
		if !reflect.DeepEqual(loaded.RemoteMCP.Suggested(fixture.profile), fixture.selected) {
			loaded.Close()
			t.Fatal("launch refusal did not retain the exact confirmed preference")
		}
		loaded.Close()
	}
	if scenario == "continue" || scenario == "receipt-remembered" {
		loaded, err := vault.Load(fixture.path, fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		defer loaded.Close()
		if !reflect.DeepEqual(loaded.RemoteMCP.Suggested(fixture.profile), fixture.selected) {
			t.Fatal("confirmed selection did not persist exact remembered binding")
		}
	} else if scenario == "empty" || scenario == "no-record" {
		loaded, err := vault.Load(fixture.path, fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		defer loaded.Close()
		got, exists := loaded.RemoteMCP.Last[fixture.profile]
		if !exists || len(got) != 0 {
			t.Fatal("explicit empty choice was not persisted as an empty preference")
		}
		if bytes.Equal(fixture.expectedCiphertext, after) {
			t.Fatal("explicit empty confirmation did not change ciphertext")
		}
	} else if scenario == "absent-directory" {
		loaded, err := vault.Load(fixture.path, fixture.password)
		if err != nil {
			t.Fatal(err)
		}
		defer loaded.Close()
		if loaded.RemoteMCP != nil {
			t.Fatal("absent remote MCP directory was synthesized")
		}
	}
}
