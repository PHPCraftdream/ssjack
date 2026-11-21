package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
	"github.com/charmbracelet/x/ansi"
	"golang.org/x/crypto/ssh"
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
	defer remoteMCPTeardown(t, terminal, capture, fixture)
	remoteMCPStartupDrive(t, ctx, scenario, fixture, terminal, capture)
	fixture.pty.requireOutcome(t, ctx, terminal, capture)
	switch scenario {
	case "connected-empty":
		if fixture.connected.authorized.Load() != 0 || fixture.connected.rejected.Load() != 0 || fixture.connected.calls.Load() != 0 || fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0 {
			t.Fatal("confirmed empty choice contacted or called an upstream")
		}
	case "connected-cancel":
		if fixture.connected.authorized.Load() != 0 || fixture.connected.rejected.Load() != 0 || fixture.connected.calls.Load() != 0 || fixture.connected.waitCalls.Load() != 0 || fixture.connected.waitDone.Load() != 0 {
			t.Fatal("cancelled selection contacted or called an upstream")
		}
	default:
		authorized, rejected := fixture.connected.authorized.Load(), fixture.connected.rejected.Load()
		if authorized == 0 {
			t.Errorf("verified TLS upstream accepted no selected credential: authorized=%d", authorized)
		}
		if rejected != 0 {
			t.Errorf("verified TLS upstream rejected credentials: rejected=%d", rejected)
		}
		if t.Failed() {
			return
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
	defer remoteMCPTeardown(t, terminal, capture, fixture)
	remoteMCPStartupDrive(t, ctx, scenario, fixture, terminal, capture)
	fixture.pty.requireOutcome(t, ctx, terminal, capture)
	shouldLaunch := fixture.pty.marker == "REMOTE-MCP-HARNESS-RAN"
	if scenario == "mcp-nonterminal-refusal" {
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("MCP nonterminal refusal reached the harness")
		}
	} else if scenario == "prepared-launch-no-output-filter" {
		if capture.Contains([]byte("REMOTE-MCP-HARNESS-RAN")) {
			t.Fatal("prepared-launch fixture invoked a fake bridge/harness")
		}
		if !capture.Contains([]byte("Remote MCP bridge is active for this session's selected connections.")) {
			t.Errorf("prepared-launch warning missing: present=%d", 0)
		}
		if capture.Contains([]byte("#357")) {
			t.Errorf("prepared-launch warning check found forbidden reference: present=%d", 1)
		}
		if t.Failed() {
			return
		}
	} else if !shouldLaunch {
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
	d := fixture.pty
	if d.prompt.result != "skipped" {
		d.wait(t, ctx, capture, "vault-prompt", &d.prompt, func(data []byte) bool {
			d.prompt.title = bytes.Contains(data, []byte("Vault secret:"))
			return d.prompt.title
		})
		ending := byte('\n')
		if runtime.GOOS == "windows" {
			ending = '\r'
		}
		input := append(append([]byte(nil), fixture.password...), ending)
		writeErr := d.write(terminal, "password", input)
		clear(input)
		if writeErr != nil {
			t.Fatal("startup PTY password write failed")
		}
	}
	if d.selector.result != "skipped" {
		screen := newRemoteMCPStartupScreen()
		defer screen.reset()
		title := "Select MCP connections for SSH profile " + strconv.Quote(fixture.profile)
		d.wait(t, ctx, capture, "selector", &d.selector, func(data []byte) bool {
			screen.observe(data, title, &d.selector)
			return d.selector.title && d.selector.action && d.selector.marker
		})
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
		if err := d.write(terminal, "toggle", []byte(" ")); err != nil {
			t.Fatal("cannot toggle confirmed account")
		}
		if err := d.write(terminal, "confirm", []byte("\t\t\r")); err != nil {
			t.Fatal("cannot confirm selected account")
		}
	case "connected-empty":
		if err := d.write(terminal, "confirm", []byte("\t\t\r")); err != nil {
			t.Fatal("cannot confirm empty account choice")
		}
	case "connected-cancel":
		if err := d.write(terminal, "cancel", []byte("q")); err != nil {
			t.Fatal("cannot cancel before account launch")
		}
	case "cancel":
		_ = d.write(terminal, "cancel", []byte("q"))
	case "esc":
		_ = d.write(terminal, "cancel-escape", []byte{27})
	case "ctrl-c":
		_ = d.write(terminal, "cancel-interrupt", []byte{3})
	case "continue", "stale-ciphertext", "issue-refusal", "empty":
		_ = d.write(terminal, "toggle-confirm", []byte(" \t\r"))
	case "receipt-remembered", "prepared-launch-no-output-filter":
		_ = d.write(terminal, "confirm", []byte("\t\r"))
	case "mcp-nonterminal-refusal", "absent-directory":
	default:
		_ = d.write(terminal, "confirm", []byte("\r"))
	}
	d.phases.Mark("drive-finished")
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
	pty                *remoteMCPStartupPTYDiag
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
	var encodedRoute, waitAck string
	if remoteMCPConnectedScenario(scenario) {
		otherTarget := target
		otherTarget.PrivateKey = nil
		otherTarget.Password = []byte(sshfixture.ConnectPassword)
		otherTarget.User = "second"
		if err := v.SetAccount(profileID, "secondary", otherTarget); err != nil {
			t.Fatal("cannot prepare an unselected SSH account")
		}
		profile = v.Servers[profileID].Accounts["main"]
		if scenario == "connected-active-cancel" {
			waitAck = filepath.Join(t.TempDir(), "upstream-wait")
		}
		connected, route := newRemoteMCPConnectedServer(t, []byte(sshfixture.ConnectPassword), waitAck)
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
	args := []string{"-test.run=^TestNativeRemoteMCPStartupChild$", "--", "--vault", path, "--profile", profile, "run", executable, "-test.run=^TestNativeRemoteMCPStartupHarness$"}
	environment := nativeStartupEnvironment()
	environment = append(environment, "SSJACK_REMOTE_MCP_STARTUP_CHILD=1", "SSJACK_REMOTE_MCP_STARTUP_SCENARIO="+scenario)
	if remoteMCPConnectedScenario(scenario) {
		if scenario != "connected-cancel" {
			environment = append(environment, remoteMCPConnectedScenarioEnv+"="+scenario, "SSJACK_REMOTE_MCP_EXPECTED_NAMESPACE="+remoteMCPConnectedNamespace(selected[0]))
		} else {
			environment = append(environment, remoteMCPConnectedScenarioEnv+"=connected-cancel")
		}
		if waitAck != "" {
			environment = append(environment, remoteMCPConnectedWaitAckEnv+"="+waitAck)
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
	return &remoteMCPStartupFixture{scenario: scenario, path: path, profile: profile, password: append([]byte(nil), password...), selected: selected, connected: connectedServer, connectedRoute: encodedRoute, expectedCiphertext: expectedCiphertext, expectedFinal: expectedCiphertext, executable: executable, ptyBridge: ptyBridge, environment: environment, args: args}
}

const (
	remoteMCPStartupCols = 200
	remoteMCPStartupRows = 60
)

type remoteMCPStartupScreen struct {
	parser         *ansi.Parser
	cells          [remoteMCPStartupCols * remoteMCPStartupRows]rune
	seen, x, y     int
	savedX, savedY int
	wrap, insert   bool
	last           rune
}

func newRemoteMCPStartupScreen() *remoteMCPStartupScreen {
	s := &remoteMCPStartupScreen{parser: ansi.NewParser()}
	s.parser.SetDataSize(1)
	s.parser.SetHandler(ansi.Handler{Print: s.print, Execute: s.execute, HandleCsi: s.csi, HandleEsc: s.esc})
	return s
}
func (s *remoteMCPStartupScreen) observe(data []byte, title string, o *remoteMCPStartupObservation) {
	for _, b := range data[s.seen:] {
		s.parser.Advance(b)
	}
	s.seen = len(data)
	o.title, o.action, o.marker = false, false, false
	var row [remoteMCPStartupCols]rune
	for y := range remoteMCPStartupRows {
		for x, r := range s.cells[y*remoteMCPStartupCols : (y+1)*remoteMCPStartupCols] {
			if r == 0 {
				r = ' '
			}
			row[x] = r
		}
		line := strings.TrimSpace(string(row[:]))
		o.title = o.title || line == title
		o.action = o.action || line == "Continue" || line == "> Continue"
		account := strings.TrimPrefix(line, "> ")
		switch o.markerKind {
		case "checked-account":
			o.marker = o.marker || strings.HasPrefix(account, "[x] \"coordinator\" / \"main\" / ")
		case "unchecked-account":
			o.marker = o.marker || strings.HasPrefix(account, "[ ] \"coordinator\" / \"main\" / ")
		case "empty-directory":
			o.marker = o.marker || line == "(No remote MCP accounts configured.)"
		}
	}
}

func (s *remoteMCPStartupScreen) move(x, y int) {
	s.x = max(0, min(x, remoteMCPStartupCols-1))
	s.y = max(0, min(y, remoteMCPStartupRows-1))
	s.wrap = false
}

func (s *remoteMCPStartupScreen) scroll(y, lines int) {
	cells := s.cells[y*remoteMCPStartupCols:]
	n := min(len(cells), max(lines, -lines)*remoteMCPStartupCols)
	if lines > 0 {
		copy(cells, cells[n:])
		clear(cells[len(cells)-n:])
	} else {
		copy(cells[n:], cells)
		clear(cells[:n])
	}
}

func (s *remoteMCPStartupScreen) index() {
	if s.y == remoteMCPStartupRows-1 {
		s.scroll(0, 1)
	}
	s.move(s.x, s.y+1)
}

func (s *remoteMCPStartupScreen) print(r rune) {
	w := 1
	if r > 127 {
		w = ansi.StringWidthWc(string(r))
	}
	if w == 0 {
		return
	}
	if s.wrap || s.x+w > remoteMCPStartupCols {
		s.x = 0
		s.index()
	}
	row := s.cells[s.y*remoteMCPStartupCols+s.x : (s.y+1)*remoteMCPStartupCols]
	if s.insert {
		copy(row[w:], row)
	}
	row[0] = r
	for i := 1; i < w; i++ {
		row[i] = -1
	}
	s.last = r
	s.wrap = s.x+w == remoteMCPStartupCols
	s.x = min(s.x+w, remoteMCPStartupCols-1)
}

func (s *remoteMCPStartupScreen) execute(b byte) {
	switch b {
	case '\r':
		s.move(0, s.y)
	case '\n', '\v', '\f':
		s.index()
	case '\b':
		s.move(s.x-1, s.y)
	case '\t':
		s.move((s.x/8+1)*8, s.y)
	}
}

func (s *remoteMCPStartupScreen) reset() {
	clear(s.cells[:])
	s.move(0, 0)
	s.last, s.insert = 0, false
}

func (s *remoteMCPStartupScreen) esc(cmd ansi.Cmd) {
	if cmd.Intermediate() != 0 {
		return
	}
	switch cmd.Final() {
	case 'D':
		s.index()
	case 'E':
		s.x = 0
		s.index()
	case 'M':
		if s.y == 0 {
			s.scroll(0, -1)
		}
		s.move(s.x, s.y-1)
	case '7':
		s.savedX, s.savedY = s.x, s.y
	case '8':
		s.move(s.savedX, s.savedY)
	case 'c':
		s.reset()
	}
}

func (s *remoteMCPStartupScreen) csi(cmd ansi.Cmd, params ansi.Params) {
	if cmd.Intermediate() != 0 {
		return
	}
	final := cmd.Final()
	if final == 'h' || final == 'l' {
		for _, p := range params {
			n := p.Param(0)
			if cmd.Prefix() == '?' && (n == 47 || n == 1047 || n == 1049) {
				s.reset()
			} else if cmd.Prefix() == 0 && n == 4 {
				s.insert = final == 'h'
			}
		}
		return
	}
	if cmd.Prefix() != 0 {
		return
	}
	p, _, _ := params.Param(0, 0)
	n := min(len(s.cells), max(1, p))
	x, y := s.x, s.y
	pos := y*remoteMCPStartupCols + x
	switch final {
	case 'H', 'f':
		col, _, _ := params.Param(1, 1)
		s.move(max(1, col)-1, n-1)
	case 'G', '`':
		s.move(n-1, y)
	case 'd':
		s.move(x, n-1)
	case 'A':
		s.move(x, y-n)
	case 'B', 'e':
		s.move(x, y+n)
	case 'C', 'a':
		s.move(x+n, y)
	case 'D':
		s.move(x-n, y)
	case 'E':
		s.move(0, y+n)
	case 'F':
		s.move(0, y-n)
	case 'J', 'K':
		lo, hi := 0, len(s.cells)
		if final == 'K' {
			lo, hi = y*remoteMCPStartupCols, (y+1)*remoteMCPStartupCols
		}
		switch p {
		case 0:
			clear(s.cells[pos:hi])
		case 1:
			clear(s.cells[lo : pos+1])
		case 2:
			clear(s.cells[lo:hi])
		}
	case '@', 'P', 'X':
		row := s.cells[pos : (y+1)*remoteMCPStartupCols]
		n = min(n, len(row))
		switch final {
		case '@':
			copy(row[n:], row)
			clear(row[:n])
		case 'P':
			copy(row, row[n:])
			clear(row[len(row)-n:])
		case 'X':
			clear(row[:n])
		}
	case 'S':
		s.scroll(0, n)
	case 'T':
		s.scroll(0, -n)
	case 'L':
		s.scroll(y, -n)
	case 'M':
		s.scroll(y, n)
	case 'b':
		if s.last != 0 {
			for range n {
				s.print(s.last)
			}
		}
	}
}

type remoteMCPStartupObservation struct {
	result, markerKind    string
	offset                int
	title, action, marker bool
}

func (o remoteMCPStartupObservation) missing() string {
	var missing []string
	if !o.title {
		if o.markerKind == "" {
			missing = append(missing, "vault-secret-prompt")
		} else {
			missing = append(missing, "selector-title")
		}
	}
	if o.markerKind != "" && !o.action {
		missing = append(missing, "continue-action-row")
	}
	if o.markerKind != "" && !o.marker {
		missing = append(missing, o.markerKind)
	}
	if len(missing) == 0 {
		return "none"
	}
	return strings.Join(missing, ",")
}
func (o remoteMCPStartupObservation) String() string {
	if o.result == "skipped" || o.result == "pending" {
		return o.result
	}
	return fmt.Sprintf("%s offset=%d missing=%s", o.result, o.offset, o.missing())
}

type remoteMCPStartupPTYDiag struct {
	phases           *childdiag.Phases
	lifetime         context.Context
	marker           string
	start, snapshot  string
	exit, drain      string
	prompt, selector remoteMCPStartupObservation
}

func remoteMCPStartupClass(err error, other string) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return other
	}
}
func (d *remoteMCPStartupPTYDiag) wait(t *testing.T, ctx context.Context, capture *ownerterminal.Capture, label string, o *remoteMCPStartupObservation, match func([]byte) bool) {
	t.Helper()
	d.phases.Mark(label + "-wait-begin")
	err := capture.WaitFor(ctx, func(data []byte) bool {
		o.offset = len(data)
		return match(data)
	})
	o.result = remoteMCPStartupClass(err, "eof-or-read-error")
	if errors.Is(err, ownerterminal.ErrTerminal) {
		capture.Inspect(func(_ []byte, _ int, overflow bool) {
			if overflow {
				o.result = "overflow"
			}
		})
	}
	d.phases.Mark(label + "-wait-" + o.result)
	if err != nil {
		t.Fatalf("startup PTY %s wait failed: %s", label, o)
	}
}
func (d *remoteMCPStartupPTYDiag) write(terminal *ownerterminal.Terminal, label string, data []byte) error {
	d.phases.Mark(fmt.Sprintf("write-attempt[label=%s requested=%d]", label, len(data)))
	n, err := terminal.Input.Write(data)
	result := "complete"
	if err != nil {
		result = "error"
	} else if n != len(data) {
		result = "short"
	}
	d.phases.Mark(fmt.Sprintf("write-result[label=%s class=%s requested=%d written=%d]", label, result, len(data), n))
	return err
}
func (d *remoteMCPStartupPTYDiag) requireOutcome(t *testing.T, ctx context.Context, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture) {
	t.Helper()
	d.phases.Mark("child-wait-begin")
	d.exit = remoteMCPStartupClass(terminal.Wait(ctx), "terminal-error")
	d.phases.Mark("child-wait-" + d.exit)
	if d.exit != "ok" {
		t.Fatalf("startup PTY child exit failed: %s", d.exit)
	}
	d.phases.Mark("capture-join-begin")
	d.drain = remoteMCPStartupClass(capture.Join(ctx), "drained-overflow")
	d.phases.Mark("capture-join-" + d.drain)
	if d.drain != "ok" {
		t.Fatalf("startup PTY capture join failed: %s", d.drain)
	}
	if d.marker == "" || !capture.Contains([]byte(d.marker)) {
		t.Fatal("startup PTY expected outcome marker missing")
	}
	d.phases.Mark("outcome-marker-visible")
}

func remoteMCPConnectedObservation(s *remoteMCPConnectedServer) string {
	closed := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
	return fmt.Sprintf("connected pre-cleanup: authorized=%d rejected=%d calls=%d wait-calls=%d wait-done=%d started=%t finished=%t ack-publication-failed=%t",
		s.authorized.Load(), s.rejected.Load(), s.calls.Load(), s.waitCalls.Load(), s.waitDone.Load(), closed(s.waitStarted), closed(s.waitFinish), s.waitAckFailed.Load())
}

func (d *remoteMCPStartupPTYDiag) snapshotBeforeCleanup(t *testing.T, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture, connected *remoteMCPConnectedServer) {
	exitProbe, drainProbe := "not-run", "not-run"
	if t.Failed() && (d.exit != "ok" && d.exit != "terminal-error" || d.drain != "ok" && d.drain != "drained-overflow") {
		probe, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer stop()
		if d.drain != "ok" && d.drain != "drained-overflow" {
			drainProbe = remoteMCPStartupClass(capture.Join(probe), "drained-overflow")
		}
		if d.exit != "ok" && d.exit != "terminal-error" {
			exitProbe = remoteMCPStartupClass(terminal.Wait(probe), "terminal-error")
		}
	}
	capture.Inspect(func(data []byte, total int, overflow bool) {
		marker := "missing"
		switch {
		case d.marker == "":
			marker = "unset"
		case bytes.Contains(data, []byte(d.marker)):
			marker = "visible"
		case overflow:
			marker = "unknown-overflow"
		}
		d.snapshot = fmt.Sprintf("pre-cleanup: child-wait=%s child-probe=%s capture-join=%s capture-probe=%s lifetime=%s marker=%s retained=%d total=%d overflow=%t",
			d.exit, exitProbe, d.drain, drainProbe, remoteMCPStartupClass(d.lifetime.Err(), "error"), marker, len(data), total, overflow)
		if t.Failed() {
			d.snapshot += "\nchild signals: " + remoteMCPStartupChildSignals(data)
		}
	})
	if connected != nil {
		d.snapshot += "\n" + remoteMCPConnectedObservation(connected)
	}
	d.phases.Mark("pre-cleanup-snapshot")
}

func remoteMCPStartupStart(t *testing.T, ctx context.Context, fixture *remoteMCPStartupFixture) (*ownerterminal.Terminal, *ownerterminal.Capture) {
	t.Helper()
	d := &remoteMCPStartupPTYDiag{
		phases: childdiag.NewPhases(), lifetime: ctx, marker: remoteMCPStartupMarker(fixture.scenario),
		start: "pending", snapshot: "pre-cleanup: unavailable (no terminal)", exit: "unobserved", drain: "unobserved",
		prompt: remoteMCPStartupObservation{result: "pending"}, selector: remoteMCPStartupObservation{result: "pending", markerKind: "unchecked-account"},
	}
	fixture.pty = d
	switch fixture.scenario {
	case "mcp-nonterminal-refusal":
		d.prompt.result, d.selector.result = "skipped", "skipped"
	case "absent-directory":
		d.selector.result = "skipped"
	case "prepared-launch-no-output-filter":
		d.prompt.result = "skipped"
		d.selector.markerKind = "checked-account"
	case "receipt-remembered", "empty":
		d.selector.markerKind = "checked-account"
	case "no-record":
		d.selector.markerKind = "empty-directory"
	}
	flakediag.OnFailure(t, func() string {
		return fmt.Sprintf("startup PTY: scenario=%s start=%s\nprompt: %s\nselector: %s\n%s\n%s",
			fixture.scenario, d.start, d.prompt, d.selector, d.snapshot, d.phases.Render())
	})
	d.phases.Mark("terminal-start-begin")
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: fixture.executable, UnixBridge: fixture.ptyBridge, Directory: t.TempDir(), Environment: fixture.environment, Args: fixture.args})
	d.start = remoteMCPStartupClass(err, "terminal-error")
	d.phases.Mark("terminal-start-" + d.start)
	if err != nil {
		t.Fatalf("startup PTY terminal start failed: %s", d.start)
	}
	capture := ownerterminal.CaptureOutput(terminal.Output)
	d.phases.Mark("capture-started")
	return terminal, capture
}

func remoteMCPTeardown(t *testing.T, terminal *ownerterminal.Terminal, capture *ownerterminal.Capture, fixture *remoteMCPStartupFixture) {
	t.Helper()
	d := fixture.pty
	d.snapshotBeforeCleanup(t, terminal, capture, fixture.connected)
	password := fixture.password
	cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	closeResult := remoteMCPStartupClass(terminal.Close(cleanup), "terminal-error")
	d.phases.Mark("cleanup-close-" + closeResult)
	if closeResult != "ok" {
		t.Errorf("startup PTY terminal cleanup failed: %s", closeResult)
	}
	joinResult := remoteMCPStartupClass(capture.Join(cleanup), "drained-overflow")
	d.phases.Mark("cleanup-join-" + joinResult)
	if joinResult != "ok" {
		t.Errorf("startup PTY capture cleanup failed: %s", joinResult)
	}
	for _, secret := range [][]byte{password, []byte("synthetic-mcp-startup-secret"), []byte("synthetic startup Basic credential"), []byte("synthetic MCP custom header"), []byte("synthetic-mcp-owner"), []byte("synthetic-unselected-account-secret")} {
		if capture.Contains(secret) {
			t.Error("terminal disclosed startup credential")
		}
	}
	capture.Clear()
	clear(password)
	d.phases.Mark("cleanup-cleared")
}
