package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const remoteMCPPreparedMarker = "REMOTE-MCP-PREPARED-LAUNCH-VERIFIED"

func remoteMCPPreparedOwnerEndpoint(t *testing.T, path string) ownerlocal.Endpoint {
	t.Helper()
	endpoint, err := ownerlocal.Identity(path)
	if err != nil || !remoteMCPOwnerAddressShape(endpoint.Address, runtime.GOOS == "windows") {
		t.Fatal("prepared owner endpoint did not use its native IPC address")
	}
	return endpoint
}

func remoteMCPOwnerAddressShape(address string, windows bool) bool {
	if windows {
		prefix := `\\.\pipe\ssjack-owner-`
		value := strings.TrimPrefix(address, prefix)
		decoded, err := hex.DecodeString(value)
		return strings.HasPrefix(address, prefix) && len(value) == 64 && err == nil && len(decoded) == 32
	}
	parent := filepath.Dir(filepath.Dir(address))
	directory := filepath.Base(filepath.Dir(address))
	value := strings.TrimPrefix(directory, "ssjack-owner-")
	decoded, err := hex.DecodeString(value)
	return filepath.IsAbs(address) && filepath.Clean(address) == address && parent == "/tmp" && filepath.Base(address) == "control.sock" && strings.HasPrefix(directory, "ssjack-owner-") && len(value) == 32 && err == nil && len(decoded) == 16
}

func remoteMCPPreparedOwnerDial(t *testing.T, ctx context.Context, path string, serviceDone <-chan struct{}) {
	t.Helper()
	if ctx == nil || ctx.Err() != nil {
		t.Fatal("prepared owner IPC proof context expired")
	}
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := ownerlocal.Dial(attempt, path)
	if err != nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		t.Fatal("prepared owner native IPC endpoint did not accept a local peer")
	}
	if err := connection.Close(); err != nil {
		t.Fatal("unauthenticated native owner IPC peer did not close")
	}
	select {
	case <-serviceDone:
		t.Fatal("unauthenticated native owner IPC peer stopped the service")
	default:
	}
}

func remoteMCPPreparedOwnerDialRefused(t *testing.T, ctx context.Context, path string, endpoint ownerlocal.Endpoint) {
	t.Helper()
	if ctx == nil || ctx.Err() != nil {
		t.Fatal("prepared owner IPC refusal context expired")
	}
	current, err := ownerlocal.Identity(path)
	if err != nil || current != endpoint {
		t.Fatal("prepared owner IPC identity changed during cleanup")
	}
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := ownerlocal.Dial(attempt, path)
	if connection != nil {
		_ = connection.Close()
	}
	if attempt.Err() != nil || ctx.Err() != nil || !errors.Is(err, ownerlocal.ErrAbsent) {
		t.Fatal("prepared owner native IPC endpoint absence was not proven after cleanup")
	}
}

func remoteMCPConnectedCapabilityNegativeControl(t *testing.T, ctx context.Context, encoded string, session *mcp.ClientSession) {
	t.Helper()
	admitted := remoteMCPReconnectAttempt(ctx, encoded, func(attemptCtx context.Context, descriptor mcpchannel.Descriptor, _ context.CancelFunc) (func(), bool, error) {
		client, err := mcpchannel.Connect(attemptCtx, descriptor)
		if client == nil {
			return nil, false, err
		}
		return client.Close, true, err
	})
	if !admitted {
		t.Fatal("connected local capability reconnect did not produce bounded refusal evidence")
	}
	if session != nil {
		listing, err := session.ListTools(ctx, nil)
		remote := 0
		if listing != nil {
			for _, tool := range listing.Tools {
				if tool != nil && strings.HasPrefix(tool.Name, "mcp") {
					remote++
				}
			}
		}
		if err != nil || remote != 3 {
			t.Fatal("original connected bridge was unusable after rejected reconnect")
		}
	}
}

func remoteMCPConnectedHarnessEnvironment(t *testing.T) {
	t.Helper()
	private := []string{"synthetic SSH account password", "synthetic remote MCP startup database password", "synthetic-mcp-owner", "synthetic startup Basic credential", "synthetic MCP custom header", "synthetic-unselected-account-secret"}
	basic := base64.StdEncoding.EncodeToString([]byte("synthetic-mcp-owner:synthetic startup Basic credential"))
	private = append(private, basic, "Basic "+basic)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "SSJACK_VAULT_PASSWORD") {
			t.Fatal("connected harness inherited a vault password environment variable")
		}
		if strings.EqualFold(key, remoteMCPConnectedRouteEnv) {
			t.Fatal("fixture route survived startup-only setup at the harness boundary")
		}
		for _, value := range private {
			if strings.Contains(entry, value) {
				t.Fatal("connected harness inherited synthetic upstream authentication")
			}
		}
	}
	for _, argument := range os.Args {
		if strings.EqualFold(argument, "--vault-password") || strings.HasPrefix(strings.ToLower(argument), "--vault-password=") {
			t.Fatal("connected harness inherited a vault password argument")
		}
		for _, value := range private {
			if strings.Contains(argument, value) {
				t.Fatal("connected harness inherited synthetic upstream authentication")
			}
		}
	}
}

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
