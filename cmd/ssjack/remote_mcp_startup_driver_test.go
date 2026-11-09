package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"golang.org/x/crypto/ssh"
)

type remoteMCPStartupFixture struct {
	scenario           string
	path               string
	profile            string
	password           []byte
	selected           []mcpdirectory.Binding
	connected          *remoteMCPConnectedServer
	connectedRoute     string
	expectedCiphertext []byte
	expectedFinal      []byte
	executable         string
	ptyBridge          string
	environment        []string
	args               []string
}

func newRemoteMCPStartupFixture(t *testing.T, ctx context.Context, scenario string) *remoteMCPStartupFixture {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	privatePEM := remoteMCPDeterministicSSHKeyPEM(private, "synthetic startup SSH key")
	defer clear(privatePEM)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	loopback := startLoopbackSSH(t, public, connectPassword, "keeper-lifetime")
	target := vault.Target{Address: loopback.address(), User: "native", PrivateKey: append([]byte(nil), privatePEM...), HostKeys: []string{string(ssh.MarshalAuthorizedKey(loopback.hostKey))}, Usage: "agent"}
	defer clear(target.PrivateKey)
	password := []byte("synthetic remote MCP startup database password")
	defer clear(password)
	v := vault.NewDirectory()
	defer v.Close()
	v.RemoteMCP = mcpdirectory.New()
	if scenario == "absent-directory" {
		v.RemoteMCP = nil
	}
	profileID, err := v.AddServer("production", "main", target)
	if err != nil {
		t.Fatal(err)
	}
	profile := v.Servers[profileID].Accounts["main"]
	var selected []mcpdirectory.Binding
	var connectedServer *remoteMCPConnectedServer
	var encodedRoute string
	if remoteMCPConnectedScenario(scenario) {
		otherTarget := target
		otherTarget.PrivateKey = nil
		otherTarget.Password = []byte(connectPassword)
		otherTarget.User = "second"
		if err := v.SetAccount(profileID, "secondary", otherTarget); err != nil {
			t.Fatal("cannot prepare an unselected SSH account")
		}
		profile = v.Servers[profileID].Accounts["main"]
		connected, route := newRemoteMCPConnectedServer(t, []byte(connectPassword))
		endpoint := remoteMCPConnectedEndpoint
		server, err := v.RemoteMCP.AddServer("coordinator", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		selectedID := "00000000000000000000000000000001"
		unselectedID := "00000000000000000000000000000002"
		v.RemoteMCP.Accounts[selectedID] = mcpdirectory.Account{ServerID: server, Name: "main", Enabled: true, Revision: 1, Auth: mcpdirectory.Authentication{Kind: "basic", Username: "synthetic-mcp-owner", Secret: []byte("synthetic startup Basic credential")}, Headers: []mcpdirectory.Header{{Name: "X-Api-Key", Value: []byte("synthetic MCP custom header")}}}
		v.RemoteMCP.Accounts[unselectedID] = mcpdirectory.Account{ServerID: server, Name: "secondary", Enabled: true, Revision: 1, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-unselected-account-secret")}}
		if err := v.RemoteMCP.Validate(); err != nil {
			t.Fatal("connected fixture directory did not validate")
		}
		if len(v.RemoteMCP.Accounts) != 2 || v.RemoteMCP.Accounts[selectedID].Name != "main" || v.RemoteMCP.Accounts[unselectedID].Name != "secondary" {
			t.Fatal("connected fixture did not contain the exact selected and unselected accounts")
		}
		binding, err := v.RemoteMCP.CurrentBinding(selectedID)
		if err != nil {
			t.Fatal(err)
		}
		selected = []mcpdirectory.Binding{binding}
		connectedServer, encodedRoute = connected, route
	} else if scenario != "no-record" && scenario != "absent-directory" {
		endpoint := "https://coordinator.invalid/mcp"
		if scenario == "issue-refusal" {
			endpoint = "https://127.0.0.1:8443/mcp"
		}
		server, err := v.RemoteMCP.AddServer("coordinator", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		accountValue := mcpdirectory.Account{ServerID: server, Name: "main", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: []byte("synthetic-mcp-startup-secret")}}
		if scenario == "prepared-launch-no-output-filter" {
			accountValue.Auth = mcpdirectory.Authentication{Kind: "basic", Username: "synthetic-mcp-owner", Secret: []byte("synthetic startup Basic credential")}
			accountValue.Headers = []mcpdirectory.Header{{Name: "X-Api-Key", Value: []byte("synthetic MCP custom header")}}
		}
		account, err := v.RemoteMCP.AddAccount(accountValue)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := v.RemoteMCP.CurrentBinding(account)
		if err != nil {
			t.Fatal(err)
		}
		selected = []mcpdirectory.Binding{binding}
	}
	if scenario == "connected-empty" {
		if err := v.RememberRemoteMCP(profileID, "main", nil); err != nil {
			t.Fatal(err)
		}
	} else if scenario == "receipt-remembered" || scenario == "empty" || scenario == "prepared-launch-no-output-filter" {
		if err := v.RememberRemoteMCP(profileID, "main", selected); err != nil {
			t.Fatal(err)
		}
		if len(selected) != 1 || !reflect.DeepEqual(v.RemoteMCP.Suggested(profile), selected) {
			t.Fatal("remembered fixture did not carry an exact nonempty binding")
		}
	}
	path := filepath.Join(t.TempDir(), "remote-mcp-startup.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	expectedCiphertext := append([]byte(nil), before...)
	clear(before)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ptyBridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	args = []string{"-test.run=^TestNativeRemoteMCPStartupChild$", "--", "--vault", path, "--profile", profile, "run", executable, "-test.run=^TestNativeRemoteMCPStartupHarness$"}
	environment := nativeStartupEnvironment()
	environment = append(environment, "SSJACK_REMOTE_MCP_STARTUP_CHILD=1", "SSJACK_REMOTE_MCP_STARTUP_SCENARIO="+scenario)
	if remoteMCPConnectedScenario(scenario) {
		if scenario != "connected-cancel" {
			environment = append(environment, remoteMCPConnectedScenarioEnv+"="+scenario, "SSJACK_REMOTE_MCP_EXPECTED_NAMESPACE="+remoteMCPConnectedNamespace(selected[0]))
		} else {
			environment = append(environment, remoteMCPConnectedScenarioEnv+"=connected-cancel")
		}
		environment = append(environment, remoteMCPConnectedRouteEnv+"="+encodedRoute)
		args = []string{"-test.run=^TestNativeRemoteMCPConnectedStartupChild$", "--", "--vault", path, "--profile", profile, "run", executable, "-test.run=^TestNativeRemoteMCPConnectedHarness$"}
		if scenario == "connected-bypass" {
			args = append(args[:2], append([]string{"--no-output-filter"}, args[2:]...)...)
		}
	}
	if scenario == "connected-cancel" {
		// Keep the child scenario explicit for the pre-launch refusal test.
		environment = append(environment, remoteMCPConnectedScenarioEnv+"=connected-cancel")
	}
	if scenario == "prepared-launch-no-output-filter" {
		environment = append(environment, "SSJACK_REMOTE_MCP_EXPECTED_BINDING="+fmt.Sprintf("%s/%s/%d/%d", selected[0].ServerID, selected[0].AccountID, selected[0].ServerRevision, selected[0].AccountRevision))
	}
	if !remoteMCPConnectedScenario(scenario) {
		args = []string{"-test.run=^TestNativeRemoteMCPStartupChild$", "--", "--vault", path, "--profile", profile, "run", executable, "-test.run=^TestNativeRemoteMCPStartupHarness$"}
	}
	return &remoteMCPStartupFixture{scenario: scenario, path: path, profile: profile, password: append([]byte(nil), password...), selected: selected, connected: connectedServer, connectedRoute: encodedRoute, expectedCiphertext: expectedCiphertext, expectedFinal: expectedCiphertext, executable: executable, ptyBridge: ptyBridge, environment: environment, args: args}
}

func remoteMCPStartupStart(t *testing.T, ctx context.Context, fixture *remoteMCPStartupFixture) (*ownerterminal.Terminal, *ownerterminal.Capture) {
	t.Helper()
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: fixture.executable, UnixBridge: fixture.ptyBridge, Directory: t.TempDir(), Environment: fixture.environment, Args: fixture.args})
	if err != nil {
		t.Fatal(err)
	}
	return terminal, ownerterminal.CaptureOutput(terminal.Output)
}

func remoteMCPTeardown(t *testing.T, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture, password []byte) {
	t.Helper()
	cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	if err := terminal.Close(cleanup); err != nil {
		t.Error("terminal cleanup failed")
	}
	if err := capture.Join(cleanup); err != nil {
		t.Error("terminal output cleanup did not join")
	}
	for _, secret := range [][]byte{password, []byte("synthetic-mcp-startup-secret"), []byte("synthetic startup Basic credential"), []byte("synthetic MCP custom header"), []byte("synthetic-mcp-owner"), []byte("synthetic-unselected-account-secret")} {
		if capture.Contains(secret) {
			t.Error("terminal disclosed startup credential")
		}
	}
	capture.Clear()
	clear(password)
}

func remoteMCPStartupDrive(t *testing.T, ctx context.Context, scenario string, fixture *remoteMCPStartupFixture, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture) {
	t.Helper()
	wait := func(text string) {
		t.Helper()
		if capture.Wait(ctx, text) != nil {
			t.Fatal("native startup missed terminal text", text)
		}
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
}
