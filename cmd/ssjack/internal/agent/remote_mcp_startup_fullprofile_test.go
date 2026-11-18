package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// The trusted-terminal bypass warning literal is pinned to the production
// internal/cli selection copy; the constant itself is unexported.
const remoteMCPOutputFilterWarning = "WARNING: MCP known-literal output filtering is DISABLED for this launch. Encryption, grants and application bootstrap-token masking remain enabled. Human SSH sessions are always unfiltered.\n"

func TestVaultRemoteMCPStartupFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("native remote MCP startup acceptance is CI-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if os.Getenv("SSJACK_TEST_REMOTE_MCP_CONNECTED") == "1" {
		for _, scenario := range []string{"connected-basic", "connected-bypass", "connected-active-cancel", "connected-empty", "connected-cancel"} {
			t.Run(scenario, func(t *testing.T) { remoteMCPConnectedStartupPTY(t, ctx, scenario) })
		}
		return
	}
	for _, scenario := range []string{"continue", "receipt-remembered", "empty", "no-record", "absent-directory", "cancel", "esc", "ctrl-c", "stale-ciphertext", "mcp-nonterminal-refusal", "issue-refusal", "prepared-launch-no-output-filter"} {
		t.Run(scenario, func(t *testing.T) { remoteMCPStartupPTY(t, ctx, scenario) })
	}
}

func remoteMCPConnectedStartupPTY(t *testing.T, parent context.Context, scenario string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		if !t.Failed() && !t.Skipped() {
			t.Log("REMOTE-MCP-CONNECTED-OBSERVED:" + scenario)
		}
	})
	fixture := newRemoteMCPStartupFixture(t, ctx, scenario)
	defer clear(fixture.password)
	terminal, capture := remoteMCPStartupStart(t, ctx, fixture)
	defer remoteMCPTeardown(t, terminal, capture, fixture.password)
	remoteMCPStartupDrive(t, ctx, scenario, fixture, terminal, capture)
	switch scenario {
	case "connected-empty":
		if childdiag.TerminalWait(t, "connected-empty child exit", ctx, terminal) != nil {
			t.Fatal("confirmed empty connected run did not exit")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte(remoteMCPConnectedHarnessMarker+scenario)) {
			t.Fatal("empty connected run omitted its positive harness marker")
		}
		if fixture.connected.authorized.Load() != 0 || fixture.connected.rejected.Load() != 0 || fixture.connected.calls.Load() != 0 || fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0 {
			t.Fatal("confirmed empty choice contacted or called an upstream")
		}
	case "connected-cancel":
		if childdiag.TerminalWait(t, "connected-cancel child exit", ctx, terminal) != nil {
			t.Fatal("cancelled connected run did not exit")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte("REMOTE-MCP-CONNECTED-CANCEL-VERIFIED")) {
			t.Fatal("connected cancellation omitted its positive refusal marker")
		}
		if fixture.connected.authorized.Load() != 0 || fixture.connected.rejected.Load() != 0 || fixture.connected.calls.Load() != 0 || fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0 {
			t.Fatal("cancelled selection contacted or called an upstream")
		}
	default:
		if childdiag.TerminalWait(t, "connected child exit", ctx, terminal) != nil {
			t.Fatal("connected startup child did not exit")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte(remoteMCPConnectedHarnessMarker+scenario)) {
			t.Fatal("connected harness did not report its exact positive scenario marker")
		}
		if fixture.connected.authorized.Load() == 0 || fixture.connected.rejected.Load() != 0 {
			t.Fatal("verified TLS upstream did not accept only the selected private credential")
		}
		wantCalls := int32(2)
		if scenario == "connected-active-cancel" || scenario == "connected-bypass" {
			wantCalls = 3
		}
		if fixture.connected.calls.Load() != wantCalls {
			t.Fatal("connected fixture call count showed replay or missing call")
		}
		if scenario == "connected-active-cancel" {
			waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
			defer waitCancel()
			select {
			case <-fixture.connected.waitStarted:
			case <-waitCtx.Done():
				t.Fatal("active call never reached the upstream cancellation barrier")
			}
			select {
			case <-fixture.connected.waitFinish:
			case <-waitCtx.Done():
				t.Fatal("upstream cancellation handler did not finish")
			}
			if fixture.connected.waitCalls.Load() != 1 || fixture.connected.waitDone.Load() != 1 {
				t.Fatal("active cancellation was replayed or left an uncertain upstream handler")
			}
		} else if fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0 {
			t.Fatal("inactive cancellation scenario touched the waiting tool")
		}
	}
	if scenario != "connected-bypass" {
		for _, secret := range [][]byte{[]byte("synthetic startup Basic credential"), []byte("synthetic MCP custom header"), []byte("synthetic-mcp-owner"), []byte("synthetic-unselected-account-secret")} {
			if capture.Contains(secret) {
				t.Fatal("connected acceptance output exposed credential material")
			}
		}
	}
	if scenario == "connected-bypass" &&
		!capture.Contains([]byte(remoteMCPOutputFilterWarning)) &&
		!capture.Contains([]byte(strings.ReplaceAll(remoteMCPOutputFilterWarning, "\n", "\r\n"))) {
		t.Fatal("connected explicit bypass omitted its warning")
	}
	after, err := os.ReadFile(fixture.path)
	if err != nil {
		t.Fatal("connected encrypted database readback failed")
	}
	if scenario == "connected-cancel" {
		if !bytes.Equal(fixture.expectedCiphertext, after) {
			t.Fatal("prelaunch cancellation changed encrypted preference bytes")
		}
	} else if bytes.Equal(fixture.expectedCiphertext, after) {
		t.Fatal("confirmed connected selection did not persist its receipt")
	}
	clear(after)
	loaded, loadErr := vault.Load(fixture.path, fixture.password)
	if loadErr != nil {
		t.Fatal("connected encrypted database could not be reloaded for receipt inspection")
	}
	defer loaded.Close()
	switch scenario {
	case "connected-basic", "connected-bypass", "connected-active-cancel":
		// Compare the raw persisted map: Suggested filters stale entries, so
		// it would let an extra stale remembered binding slip through.
		got, exists := loaded.RemoteMCP.Last[fixture.profile]
		if !exists || !reflect.DeepEqual(got, fixture.selected) {
			t.Fatal("connected scenario did not persist the exact raw confirmed selection")
		}
	case "connected-empty":
		got, exists := loaded.RemoteMCP.Last[fixture.profile]
		if !exists || len(got) != 0 {
			t.Fatal("connected empty choice was not persisted as an empty preference")
		}
	case "connected-cancel":
		got, exists := loaded.RemoteMCP.Last[fixture.profile]
		if exists && len(got) != 0 {
			t.Fatal("connected cancellation recorded a preference despite unchanged ciphertext")
		}
	}
}

func remoteMCPStartupPTY(t *testing.T, parent context.Context, scenario string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		if !t.Failed() && !t.Skipped() {
			t.Log("REMOTE-MCP-STARTUP-OBSERVED:" + scenario)
		}
	})
	fixture := newRemoteMCPStartupFixture(t, ctx, scenario)
	defer clear(fixture.password)
	terminal, capture := remoteMCPStartupStart(t, ctx, fixture)
	defer remoteMCPTeardown(t, terminal, capture, fixture.password)
	remoteMCPStartupDrive(t, ctx, scenario, fixture, terminal, capture)
	shouldLaunch := scenario == "continue" || scenario == "receipt-remembered" || scenario == "empty" || scenario == "no-record" || scenario == "absent-directory"
	if scenario == "mcp-nonterminal-refusal" {
		if childdiag.TerminalWait(t, "mcp-nonterminal-refusal child exit", ctx, terminal) != nil {
			t.Fatal("MCP nonterminal-refusal child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte(remoteMCPRefusalMarker(scenario))) {
			t.Fatal("MCP nonterminal refusal did not join with its exact marker")
		}
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("MCP nonterminal refusal reached the harness")
		}
	} else if scenario == "prepared-launch-no-output-filter" {
		if childdiag.TerminalWait(t, "prepared-launch child exit", ctx, terminal) != nil {
			t.Fatal("prepared-launch direct-loader child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil || !capture.Contains([]byte(remoteMCPPreparedMarker)) {
			t.Fatal("prepared-launch direct-loader output did not join with its positive marker")
		}
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("prepared-launch fixture invoked a fake bridge/harness")
		}
		if !capture.Contains([]byte("Remote MCP bridge is active for this session's selected connections.")) || capture.Contains([]byte("#357")) {
			t.Fatal("prepared-launch warning did not accurately describe the available capability")
		}
	} else if shouldLaunch {
		if childdiag.TerminalWait(t, "confirmed startup child exit", ctx, terminal) != nil {
			t.Fatal("confirmed startup child did not exit successfully")
		}
		if err := capture.Join(ctx); err != nil {
			t.Fatal("confirmed startup output did not join")
		}
		if !capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("confirmed startup omitted harness marker")
		}
	} else {
		if childdiag.TerminalWait(t, "refusal child exit", ctx, terminal) != nil {
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

func remoteMCPStartupDrive(t *testing.T, ctx context.Context, scenario string, fixture *remoteMCPStartupFixture, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture) {
	t.Helper()
	wait := func(text string) {
		t.Helper()
		childdiag.CaptureWaitDiag(t, ctx, capture, text, "native startup missed terminal text "+text)
		fixture.phases.Mark("saw " + text)
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
		fixture.phases.Mark("password input")
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
	fixture.phases.Mark("drive inputs sent")
}

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
	phases             *childdiag.Phases
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
	loopback := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "keeper-lifetime")
	target := vault.Target{Address: loopback.Address(), User: "native", PrivateKey: append([]byte(nil), privatePEM...), HostKeys: []string{string(ssh.MarshalAuthorizedKey(loopback.HostKey))}, Usage: "agent"}
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
		otherTarget.Password = []byte(sshfixture.ConnectPassword)
		otherTarget.User = "second"
		if err := v.SetAccount(profileID, "secondary", otherTarget); err != nil {
			t.Fatal("cannot prepare an unselected SSH account")
		}
		profile = v.Servers[profileID].Accounts["main"]
		connected, route := newRemoteMCPConnectedServer(t, []byte(sshfixture.ConnectPassword))
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
	ptyBridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
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
	started := time.Now()
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: fixture.executable, UnixBridge: fixture.ptyBridge, Directory: t.TempDir(), Environment: fixture.environment, Args: fixture.args})
	if err != nil {
		t.Fatal(err)
	}
	// Failure-only child evidence: command name, phase timing and a tail of
	// the PTY output. The pid is not exposed by ownerterminal, so it cannot
	// be reported without production changes.
	tail := childdiag.NewTail()
	phases := childdiag.NewPhases()
	fixture.phases = phases
	capture := ownerterminal.CaptureOutput(childdiag.TeeOutput(terminal.Output, tail))
	flakediag.OnFailure(t, func() string {
		return "startup PTY child: scenario=" + fixture.scenario +
			" name=" + filepath.Base(fixture.executable) +
			" bridge=" + filepath.Base(fixture.ptyBridge) +
			" args=" + fmt.Sprint(len(fixture.args)) +
			" started=" + started.Format(time.RFC3339) +
			" elapsed=" + time.Since(started).Round(time.Millisecond).String() + "\n" +
			phases.Render() +
			"\noutput tail:" + flakediag.Tail(tail.Snapshot(), 16*1024) +
			"\ngoroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	return terminal, capture
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
