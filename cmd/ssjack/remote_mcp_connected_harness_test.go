package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const remoteMCPConnectedHarnessMarker = "REMOTE-MCP-CONNECTED-HARNESS-VERIFIED:"
const remoteMCPConnectedBridgeChildEnv = "SSJACK_REMOTE_MCP_CONNECTED_BRIDGE_CHILD"
const remoteMCPConnectedScenarioEnv = "SSJACK_REMOTE_MCP_CONNECTED_SCENARIO"

func TestNativeRemoteMCPConnectedStartupChild(t *testing.T) {
	if os.Getenv("SSJACK_REMOTE_MCP_STARTUP_CHILD") != "1" || !remoteMCPConnectedScenario(os.Getenv("SSJACK_REMOTE_MCP_STARTUP_SCENARIO")) {
		t.Skip("connected startup fixture only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	scenario := os.Getenv("SSJACK_REMOTE_MCP_STARTUP_SCENARIO")
	if err := installRemoteMCPConnectedRouteFromEnvironment(); err != nil {
		t.Fatal("connected route setup refused")
	}
	_ = os.Unsetenv(remoteMCPConnectedRouteEnv)
	var args []string
	for index, argument := range os.Args {
		if argument == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	code, err := run(ctx, args)
	if scenario == "connected-cancel" {
		if code != 1 || err == nil || err.Error() != "remote MCP selection cancelled; no database changes were made" {
			t.Fatal("connected prelaunch cancellation was not refused")
		}
		fmt.Fprintln(os.Stderr, "REMOTE-MCP-CONNECTED-CANCEL-VERIFIED")
		return
	}
	if err != nil || code != 0 {
		t.Fatal("connected startup command did not complete")
	}
}

// This is the real stdio MCP process spawned by the production launcher.
func TestNativeRemoteMCPConnectedBridge(t *testing.T) {
	if os.Getenv(remoteMCPConnectedBridgeChildEnv) != "1" {
		t.Skip("connected MCP bridge process only")
	}
	remoteMCPConnectedHarnessEnvironment(t)
	code, err := runMCP(context.Background())
	if err != nil || code != 0 {
		fmt.Fprintln(os.Stderr, "REMOTE-MCP-CONNECTED-BRIDGE-CLEANUP-FAILED")
		os.Exit(1)
	}
	os.Exit(0)
}

// This real SDK client is the launcher harness and calls namespaced tools over
// the production stdio bridge; the separate bridge process uses runMCP above.
func TestNativeRemoteMCPConnectedHarness(t *testing.T) {
	scenario := os.Getenv(remoteMCPConnectedScenarioEnv)
	if !remoteMCPConnectedScenario(scenario) {
		t.Skip("connected MCP harness only")
	}
	remoteMCPConnectedHarnessEnvironment(t)
	_ = os.Unsetenv(remoteMCPConnectedScenarioEnv)
	_ = os.Unsetenv(remoteMCPConnectedRouteEnv)
	encodedChannels := os.Getenv(mcpchannel.Env)
	var capability string
	if scenario == "connected-empty" {
		if encodedChannels != "" {
			t.Fatal("empty confirmed choice carried a private channel descriptor")
		}
	} else {
		descriptors, err := mcpchannel.DecodeDescriptors(encodedChannels)
		if err != nil || len(descriptors) != 1 || descriptors[0].Ordinal != 0 {
			t.Fatal("confirmed local channel capability is unavailable")
		}
		capability = descriptors[0].Token
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	command := exec.Command(executable, "-test.run=^TestNativeRemoteMCPConnectedBridge$")
	command.Stderr = io.Discard
	command.Env = append(nativeStartupEnvironment(), remoteMCPConnectedBridgeChildEnv+"=1")
	if encodedChannels != "" {
		command.Env = append(command.Env, mcpchannel.Env+"="+encodedChannels)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "connected-acceptance-harness", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal("connected harness could not attach to the real stdio bridge")
	}
	closed := false
	defer func() {
		if !closed {
			_ = session.Close()
		}
	}()
	listing := remoteMCPConnectedList(ctx, t, session, scenario != "connected-empty")
	if scenario != "connected-empty" {
		remoteMCPConnectedCapabilityNegativeControl(t, ctx, encodedChannels, session)
	}
	if scenario == "connected-cancel" {
		t.Fatal("cancelled selection unexpectedly launched the harness")
	}
	if scenario == "connected-empty" {
		if len(listing) != 8 {
			t.Fatal("empty confirmed choice exposed non-base tools")
		}
	} else {
		remote := make([]string, 0, 3)
		for _, tool := range listing {
			if tool != nil && strings.HasPrefix(tool.Name, "mcp") {
				remote = append(remote, tool.Name)
			}
		}
		if len(remote) != 3 || remoteMCPConnectedTool(remote, "echo") == "" || remoteMCPConnectedTool(remote, "fail") == "" || remoteMCPConnectedTool(remote, "wait") == "" {
			t.Fatal("selected account inventory was not exactly scoped")
		}
		prefix := remote[0][:strings.LastIndex(remote[0], "_")+1]
		for _, name := range remote {
			if !strings.HasPrefix(name, prefix) {
				t.Fatal("connected tools crossed binding namespaces")
			}
		}
		if prefix != os.Getenv("SSJACK_REMOTE_MCP_EXPECTED_NAMESPACE") {
			t.Fatal("connected tools escaped the exact confirmed binding")
		}
		echo := remoteMCPConnectedTool(remote, "echo")
		fail := remoteMCPConnectedTool(remote, "fail")
		waitTool := remoteMCPConnectedTool(remote, "wait")
		remoteMCPConnectedCall(t, ctx, session, echo, false, scenario == "connected-bypass", capability)
		remoteMCPConnectedCall(t, ctx, session, fail, true, scenario == "connected-bypass", "")
		if scenario == "connected-bypass" {
			remoteMCPConnectedRPCFailure(t, ctx, session, fail)
		}
		missing, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: prefix + "not_selected", Arguments: map[string]any{}})
		if callErr == nil || missing != nil {
			t.Fatal("unknown remote tool was not denied locally")
		}
		if scenario == "connected-active-cancel" {
			callCtx, stop := context.WithTimeout(ctx, time.Second)
			_, waitErr := session.CallTool(callCtx, &mcp.CallToolParams{Name: waitTool, Arguments: map[string]any{}})
			stop()
			if waitErr == nil {
				t.Fatal("active upstream call did not observe cancellation")
			}
		}
	}
	if err := session.Close(); err != nil {
		t.Fatal("connected bridge session cleanup did not join")
	}
	closed = true
	if scenario != "connected-empty" {
		remoteMCPConnectedCapabilityNegativeControl(t, ctx, encodedChannels, nil)
	}
	fmt.Fprintln(os.Stderr, remoteMCPConnectedHarnessMarker+scenario)
}

func remoteMCPConnectedList(ctx context.Context, t *testing.T, session *mcp.ClientSession, wantRemote bool) []*mcp.Tool {
	t.Helper()
	deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		listing, err := session.ListTools(deadline, nil)
		if err != nil {
			t.Fatal("connected harness tool listing failed")
		}
		if listing != nil && len(listing.Tools) <= 72 {
			remote := 0
			for _, tool := range listing.Tools {
				if tool != nil && strings.HasPrefix(tool.Name, "mcp") {
					remote++
				}
			}
			if wantRemote && remote == 3 || !wantRemote && remote == 0 {
				return listing.Tools
			}
		}
		select {
		case <-deadline.Done():
			t.Fatal("bounded tool listing did not reach the expected registration state")
		case <-ticker.C:
		}
	}
}

func remoteMCPConnectedTool(names []string, suffix string) string {
	for _, name := range names {
		if strings.HasSuffix(name, "_"+suffix) {
			return name
		}
	}
	return ""
}

func remoteMCPConnectedCall(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, wantError, bypass bool, capability string) {
	t.Helper()
	if name == "" {
		t.Fatal("selected synthetic tool is missing")
	}
	arguments := map[string]any{}
	if capability != "" {
		arguments["capability"] = capability
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil || result == nil || len(result.Content) != 1 || result.StructuredContent == nil || result.IsError != wantError {
		t.Fatal("actual connected tool call omitted its structured or error result")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal("connected result could not be inspected")
	}
	joined := []byte("synthetic-mcp-owner:synthetic startup Basic credential")
	basicEncoded := []byte(base64.StdEncoding.EncodeToString(joined))
	if capability != "" {
		structured, ok := result.StructuredContent.(map[string]any)
		text, textOK := result.Content[0].(*mcp.TextContent)
		if !ok || !textOK || text == nil || structured["capability"] != outputguard.Marker || !strings.HasSuffix(text.Text, "|"+outputguard.Marker) || strings.Contains(string(encoded), capability) {
			t.Fatal("actual connected result did not guard the echoed local capability")
		}
	}
	if !bypass {
		for _, secret := range [][]byte{[]byte("synthetic startup Basic credential"), []byte("Basic " + string(basicEncoded)), basicEncoded, []byte("synthetic MCP custom header")} {
			if strings.Contains(string(encoded), string(secret)) {
				t.Fatal("actual MCP result exposed a captured credential")
			}
		}
	}
	if bypass {
		structured, ok := result.StructuredContent.(map[string]any)
		text, textOK := result.Content[0].(*mcp.TextContent)
		if !ok || !textOK || text == nil || !strings.Contains(text.Text, "synthetic SSH account password") || !strings.Contains(text.Text, "synthetic-unselected-account-secret") || structured["owner"] != "synthetic SSH account password" || structured["known"] != "synthetic-unselected-account-secret" {
			t.Fatal("explicit bypass did not preserve known owner literals")
		}
	} else {
		structured, ok := result.StructuredContent.(map[string]any)
		text, textOK := result.Content[0].(*mcp.TextContent)
		if !ok || !textOK || text == nil || !strings.Contains(text.Text, "[REDACTED]") || structured["owner"] != "[REDACTED]" || structured["known"] != "[REDACTED]" || structured["raw"] != "[REDACTED]" || structured["authorization"] != "[REDACTED]" || structured["encoded"] != "[REDACTED]" || structured["custom"] != "[REDACTED]" {
			t.Fatal("connected text or structured output was not faithfully guarded")
		}
	}
	if !strings.Contains(string(encoded), `"n":7`) {
		t.Fatal("connected structured output was not faithfully preserved")
	}
}

func remoteMCPConnectedRPCFailure(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"rpc": true}})
	if err != nil || result == nil || !result.IsError || result.StructuredContent != nil || len(result.Content) != 1 {
		t.Fatal("private RPC failure did not become a fixed tool result")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "remote MCP tool call failed" {
		t.Fatal("private RPC failure text was not fixed under bypass")
	}
}
