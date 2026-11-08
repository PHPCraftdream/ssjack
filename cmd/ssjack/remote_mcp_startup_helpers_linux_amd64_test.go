//go:build linux && amd64

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

const remoteMCPPreparedMarker = "REMOTE-MCP-PREPARED-LAUNCH-VERIFIED"

func remoteMCPStartupVaultArg(args []string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--vault" {
			return args[index+1]
		}
	}
	return ""
}

func remoteMCPExpectedRunRefusal(scenario string) string {
	switch scenario {
	case "cancel", "esc", "ctrl-c":
		return "remote MCP selection cancelled; no database changes were made"
	case "stale-ciphertext":
		return "remote MCP capture could not validate the selected saved state"
	case "issue-refusal":
		return "remote MCP launch preparation failed"
	default:
		return ""
	}
}

func remoteMCPRefusalMarker(scenario string) string {
	switch scenario {
	case "cancel":
		return "REMOTE-MCP-REFUSAL-CANCEL-VERIFIED"
	case "esc":
		return "REMOTE-MCP-REFUSAL-ESC-VERIFIED"
	case "ctrl-c":
		return "REMOTE-MCP-REFUSAL-CTRL-C-VERIFIED"
	case "stale-ciphertext":
		return "REMOTE-MCP-REFUSAL-STALE-CIPHERTEXT-VERIFIED"
	case "mcp-nonterminal-refusal":
		return "REMOTE-MCP-REFUSAL-NONTERMINAL-VERIFIED"
	case "issue-refusal":
		return "REMOTE-MCP-REFUSAL-ISSUE-VERIFIED"
	default:
		return ""
	}
}

// Keep the real input PTY, but replace stdout only while the production loader
// checks its trusted input/output terminal requirement.
func remoteMCPNonterminalRefusalChild(t *testing.T, ctx context.Context, path string, profile string) {
	t.Helper()
	if ctx == nil || ctx.Err() != nil {
		t.Fatal("nonterminal refusal fixture is unavailable")
	}
	password := []byte("synthetic remote MCP startup database password")
	defer clear(password)
	startup := startupsecret.New(string(password), true)
	defer startup.Close()
	ctx = context.WithValue(ctx, startupPasswordKey{}, startup)
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(drained)
	}()
	os.Stdout = writer
	credentials, loadErr := loadAgentCredentials(ctx, path, profile)
	os.Stdout = original
	_ = writer.Close()
	<-drained
	_ = reader.Close()
	if credentials != nil || loadErr == nil || loadErr.Error() != "remote MCP selection requires a trusted input and output terminal" {
		t.Fatal("MCP-present nonterminal startup did not refuse before selection")
	}
	fmt.Fprintln(os.Stdout, remoteMCPRefusalMarker("mcp-nonterminal-refusal"))
}
