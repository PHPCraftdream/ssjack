//go:build linux && amd64

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
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
	remoteMCPHarnessMCPProbe(t)
	fmt.Fprintln(os.Stdout, "REMOTE-MCP-HARNESS-RAN")
}

func TestNativeRemoteMCPStartupMCPChild(t *testing.T) {
	if os.Getenv("SSJACK_REMOTE_MCP_STARTUP_MCP_CHILD") != "1" {
		t.Skip("MCP child only")
	}
	code, err := runMCP(context.Background())
	if err != nil || code != 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

func remoteMCPHarnessMCPProbe(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable for MCP child")
	}
	command := exec.Command(executable, "-test.run=^TestNativeRemoteMCPStartupMCPChild$")
	stderr := &remoteMCPStderr{}
	command.Stderr = stderr
	command.Env = append(nativeStartupEnvironment(), "SSJACK_REMOTE_MCP_STARTUP_MCP_CHILD=1")
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "SSJACK_REMOTE_MCP_CHANNELS=") {
			command.Env = append(command.Env, entry)
		}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "native-harness-probe", Version: "dev"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatalf("harness MCP probe could not attach: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			closed = true
			_ = session.Close()
		}
	}()
	listing, listErr := session.ListTools(ctx, nil)
	if listErr != nil {
		t.Fatal("harness MCP probe tools/list failed")
	}
	if len(os.Getenv(mcpchannel.Env)) != 0 {
		for {
			remote := false
			for _, tool := range listing.Tools {
				remote = remote || strings.HasPrefix(tool.Name, "mcp")
			}
			if remote || strings.Contains(stderr.String(), "Some remote MCP connections are unavailable for this session.") {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("harness MCP probe did not observe remote registration completion")
			case <-time.After(20 * time.Millisecond):
			}
			listing, listErr = session.ListTools(ctx, nil)
			if listErr != nil {
				t.Fatal("harness MCP probe tools/list failed")
			}
		}
	}
	closeErr := session.Close()
	if closeErr != nil {
		t.Fatal("harness MCP probe failed to close")
	}
	closed = true
	names := map[string]bool{}
	for _, tool := range listing.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel"} {
		if !names[want] {
			t.Fatalf("harness MCP probe lost base tool %s", want)
		}
	}
	for name := range names {
		if strings.HasPrefix(name, "mcp") {
			t.Fatalf("harness MCP probe observed remote tool %s without a connected upstream", name)
		}
	}
}

type remoteMCPStderr struct {
	mu   sync.Mutex
	data []byte
}

func (w *remoteMCPStderr) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	written := len(data)
	remaining := 4096 - len(w.data)
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		w.data = append(w.data, data...)
	}
	return written, nil
}

func (w *remoteMCPStderr) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.data)
}

func nativeStartupEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" && key != mcpchannel.Env && !strings.HasPrefix(key, "SSJACK_OWNER_") {
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
