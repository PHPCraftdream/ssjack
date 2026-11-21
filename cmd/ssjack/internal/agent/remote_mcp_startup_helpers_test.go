package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/launchguard"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/remotemcp"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

func remoteMCPStartupMarker(scenario string) string {
	switch scenario {
	case "connected-cancel":
		return "REMOTE-MCP-CONNECTED-CANCEL-VERIFIED"
	case "prepared-launch-no-output-filter":
		return remoteMCPPreparedMarker
	case "continue", "receipt-remembered", "empty", "no-record", "absent-directory":
		return "REMOTE-MCP-HARNESS-RAN"
	default:
		if remoteMCPConnectedScenario(scenario) {
			return remoteMCPConnectedHarnessMarker + scenario
		}
		return remoteMCPRefusalMarker(scenario)
	}
}

func remoteMCPStartupChildSignals(data []byte) string {
	lines := bytes.Split(data, []byte{'\n'})
	var seen []string
	for _, signal := range []struct{ text, class string }{
		{"connected wait ACK environment could not be cleared", "ack-env-clear"},
		{"connected wait ACK base is missing or not absolute", "ack-base-invalid"},
		{"connected wait ACK was set outside active cancellation", "ack-env-unexpected"},
		{"connected wait call returned before explicit cancellation", "wait-returned-early"},
		{"connected wait dispatch ACK deadline expired", "dispatch-ack-timeout"},
		{"connected wait started marker probe failed", "started-probe-error"},
		{"connected wait call return deadline expired", "wait-return-timeout"},
		{"connected wait call did not return context.Canceled", "wait-cancel-error-missing"},
		{"connected harness tool listing failed", "registration-rpc-error"},
		{"bounded tool listing did not reach the expected registration state", "registration-state-missing"},
		{"connected harness could not attach to the real stdio bridge", "bridge-attach-error"},
		{"connected bridge did not negotiate the latest protocol", "bridge-negotiation-error"},
		{"selected account inventory was not exactly scoped", "bridge-inventory-error"},
		{"connected bridge session cleanup did not join", "bridge-session-cleanup-error"},
		{"harness MCP probe could not attach", "probe-attach-error"},
		{"harness MCP probe tools/list failed", "probe-list-rpc-error"},
		{"harness MCP probe tools/list returned a nil listing", "probe-list-nil"},
		{"harness MCP probe tools/list returned a nil tool entry", "probe-tool-nil"},
		{"harness MCP probe did not observe remote registration completion", "probe-registration-timeout"},
		{"harness MCP probe failed to close", "probe-close-error"},
	} {
		for _, line := range lines {
			line = bytes.TrimSuffix(line, []byte{'\r'})
			if bytes.HasSuffix(line, []byte(": "+signal.text)) {
				seen = append(seen, signal.class)
				break
			}
		}
	}
	if len(seen) == 0 {
		return "none-observed"
	}
	return strings.Join(seen, ",")
}

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
	code, err := cli.Run(ctx, args)
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
	flakediag.Begin(t)
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
	code, err := remotemcp.Run(context.Background())
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
	probeStarted := time.Now()
	childdiag.ProcessOnFailure(t, "harness MCP probe child", command, nil, probeStarted)
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
		t.Fatal("harness MCP probe could not attach")
	}
	closed := false
	defer func() {
		if !closed {
			closed = true
			_ = session.Close()
		}
	}()
	listToolsFailed := errors.New("tools/list failed")
	checkListing := func(listing *mcp.ListToolsResult, err error) error {
		if err != nil {
			return listToolsFailed
		}
		if listing == nil {
			return errors.New("tools/list returned a nil listing")
		}
		for _, tool := range listing.Tools {
			if tool == nil {
				return errors.New("tools/list returned a nil tool entry")
			}
		}
		return nil
	}
	listing, listErr := session.ListTools(ctx, nil)
	if err := checkListing(listing, listErr); err != nil {
		t.Fatalf("harness MCP probe %s", err)
	}
	if len(os.Getenv(mcpchannel.Env)) != 0 {
		done, _, lastErr := flakediag.WaitForDesc(t, "harness MCP probe remote registration", childdiag.DeadlineOf(ctx), func() (string, bool, error) {
			remote := false
			for _, tool := range listing.Tools {
				remote = remote || strings.HasPrefix(tool.Name, "mcp")
			}
			if remote || strings.Contains(stderr.String(), "Some remote MCP connections are unavailable for this session.") {
				return "", true, nil
			}
			next, listErr := session.ListTools(ctx, nil)
			if err := checkListing(next, listErr); err != nil {
				return err.Error(), false, err
			}
			listing = next
			return "remote tools not registered yet", false, nil
		})
		if lastErr != nil {
			t.Fatalf("harness MCP probe %s", lastErr)
		}
		if !done {
			t.Fatal("harness MCP probe did not observe remote registration completion")
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
	for _, want := range []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"} {
		if !names[want] {
			t.Fatalf("harness MCP probe lost base tool %s", want)
		}
	}
	for name := range names {
		if strings.HasPrefix(name, "mcp") {
			t.Fatal("harness MCP probe observed a remote tool without a connected upstream")
		}
	}
}

func TestRemoteMCPStartupScreenObserve(t *testing.T) {
	const title = "Select remote MCP accounts"
	for _, tc := range []struct{ kind, row string }{
		{"checked-account", `[x] "coordinator" / "main" / fixture`},
		{"unchecked-account", `[ ] "coordinator" / "main" / fixture`},
		{"empty-directory", "(No remote MCP accounts configured.)"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			screen := newRemoteMCPStartupScreen()
			observation := remoteMCPStartupObservation{markerKind: tc.kind}
			var transcript []byte
			check := func(stage, chunk string, action, marker bool) {
				t.Helper()
				transcript = append(transcript, chunk...)
				screen.observe(transcript, title, &observation)
				if !observation.title || observation.action != action || observation.marker != marker {
					t.Fatalf("%s: got title=%t action=%t marker=%t; want title=true action=%t marker=%t", stage, observation.title, observation.action, observation.marker, action, marker)
				}
			}
			check("instruction only", title+"\r\n"+tc.row+"\r\nSpace toggles; choose Continue explicitly", false, true)
			check("partial clear sequence", "\x1b[2", false, true)
			check("cleared viewport", "J\x1b[H"+title+"\r\n\r\n> Continue", true, false)
			check("complete viewport", "\x1b[2;1H"+tc.row, true, true)
			check("overwritten marker", "\r!", true, false)
		})
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
	startupSecret := startupsecret.New(string(password), true)
	defer startupSecret.Close()
	ctx = startup.WithInput(ctx, startupSecret)
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
	credentials, loadErr := agent.Load(ctx, path, profile)
	os.Stdout = original
	_ = writer.Close()
	<-drained
	_ = reader.Close()
	if credentials != nil || loadErr == nil || loadErr.Error() != "remote MCP selection requires a trusted input and output terminal" {
		t.Fatal("MCP-present nonterminal startup did not refuse before selection")
	}
	fmt.Fprintln(os.Stdout, remoteMCPRefusalMarker("mcp-nonterminal-refusal"))
}

type remoteMCPConnectedServer struct {
	server        *http.Server
	listener      net.Listener
	rootDER       []byte
	authorized    atomic.Int32
	rejected      atomic.Int32
	calls         atomic.Int32
	waitCalls     atomic.Int32
	waitStarted   chan struct{}
	waitDone      atomic.Int32
	waitFinish    chan struct{}
	waitAck       string
	waitAckFailed atomic.Bool
	waitStart     sync.Once
	waitEnd       sync.Once
	knownLiteral  []byte
	shutdown      chan struct{}
	serveDone     chan struct{}
	workMu        sync.Mutex
	closing       bool
	active        int
	activeDone    chan struct{}
	shutdownOnce  sync.Once
}

func newRemoteMCPConnectedServer(t *testing.T, knownLiteral []byte, waitAck string) (*remoteMCPConnectedServer, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot prepare private TLS fixture")
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "coordinator.invalid"}, DNSNames: []string{"coordinator.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal("cannot prepare private TLS certificate")
	}
	keypair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot listen for private TLS fixture")
	}
	fixture := &remoteMCPConnectedServer{listener: listener, rootDER: der, waitStarted: make(chan struct{}), waitFinish: make(chan struct{}), waitAck: waitAck, knownLiteral: append([]byte(nil), knownLiteral...)}
	fixture.initLifetime()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic-mcp-owner:synthetic startup Basic credential"))
	fixture.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fixture.beginWork() {
			http.Error(w, "fixture shutting down", http.StatusServiceUnavailable)
			return
		}
		defer fixture.endWork()
		if r.TLS == nil || r.URL.Path != "/mcp" || r.Header.Get("Authorization") != want || r.Header.Get("X-Api-Key") != "synthetic MCP custom header" {
			fixture.rejected.Add(1)
			http.Error(w, "fixture refused", http.StatusUnauthorized)
			return
		}
		fixture.authorized.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		fixture.handlerForRequest(r.Context()).ServeHTTP(w, r)
	})}
	go func() {
		defer close(fixture.serveDone)
		_ = fixture.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{keypair}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() {
		fixture.closeAdmission()
		closeErr := fixture.server.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		fixture.workMu.Lock()
		activeDone := fixture.activeDone
		fixture.workMu.Unlock()
		joined := true
		select {
		case <-fixture.serveDone:
		case <-cleanupCtx.Done():
			joined = false
		}
		select {
		case <-activeDone:
		case <-cleanupCtx.Done():
			joined = false
		}
		if !joined {
			t.Error("connected fixture shutdown did not finish within 10 seconds")
			return
		}
		if closeErr != nil {
			t.Error("connected fixture HTTP server did not close")
			return
		}
		clear(fixture.knownLiteral)
	})
	metadata, err := json.Marshal(remoteMCPConnectedRoute{Address: listener.Addr().String(), RootDER: der})
	if err != nil {
		t.Fatal("cannot encode private route metadata")
	}
	encoded := base64.RawStdEncoding.EncodeToString(metadata)
	clear(metadata)
	return fixture, encoded
}

func (s *remoteMCPConnectedServer) initLifetime() {
	s.shutdown = make(chan struct{})
	s.serveDone = make(chan struct{})
	s.activeDone = make(chan struct{})
}

func (s *remoteMCPConnectedServer) beginWork() bool {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.closing {
		return false
	}
	s.active++
	return true
}

func (s *remoteMCPConnectedServer) endWork() {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	s.active--
	if s.closing && s.active == 0 {
		close(s.activeDone)
	}
}

func (s *remoteMCPConnectedServer) stopWaitWorkers() {
	s.shutdownOnce.Do(func() { close(s.shutdown) })
}

func (s *remoteMCPConnectedServer) closeAdmission() {
	s.workMu.Lock()
	if !s.closing {
		s.closing = true
		if s.active == 0 {
			close(s.activeDone)
		}
	}
	s.workMu.Unlock()
	s.stopWaitWorkers()
}

// The fixture listens on loopback but is addressed by a remote-style host name,
// which the SDK's DNS-rebinding protection (v1.8.0) refuses with 403 by default.
func (s *remoteMCPConnectedServer) handlerForRequest(requestCtx context.Context) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "synthetic-connected-upstream", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", Description: "synthetic verified TLS echo", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.beginWork() {
			return nil, context.Canceled
		}
		defer s.endWork()
		s.calls.Add(1)
		var input struct {
			Capability string `json:"capability"`
		}
		if request != nil && request.Params != nil {
			_ = json.Unmarshal(request.Params.Arguments, &input)
		}
		return s.result(false, input.Capability), nil
	})
	server.AddTool(&mcp.Tool{Name: "fail", Description: "synthetic guarded error result", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.beginWork() {
			return nil, context.Canceled
		}
		defer s.endWork()
		s.calls.Add(1)
		var input struct {
			RPC bool `json:"rpc"`
		}
		if request != nil && request.Params != nil && json.Unmarshal(request.Params.Arguments, &input) == nil && input.RPC {
			return nil, errors.New("synthetic private RPC detail")
		}
		return s.result(true), nil
	})
	server.AddTool(&mcp.Tool{Name: "wait", Description: "synthetic cancellable call", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.beginWork() {
			return nil, context.Canceled
		}
		defer s.endWork()
		return s.wait(ctx, requestCtx)
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, DisableLocalhostProtection: true})
}

func (s *remoteMCPConnectedServer) wait(ctx, requestCtx context.Context) (*mcp.CallToolResult, error) {
	s.calls.Add(1)
	s.waitCalls.Add(1)
	s.waitStart.Do(func() {
		s.publishWaitStartedAck()
		close(s.waitStarted)
	})
	defer s.waitEnd.Do(func() { close(s.waitFinish) })
	select {
	case <-ctx.Done():
		s.waitDone.Add(1)
		return nil, ctx.Err()
	case <-requestCtx.Done():
		s.waitDone.Add(1)
		return nil, requestCtx.Err()
	case <-s.shutdown:
		return nil, context.Canceled
	}
}

func (s *remoteMCPConnectedServer) publishWaitStartedAck() {
	if s.waitAck == "" {
		return
	}
	file, err := os.OpenFile(s.waitAck+".started", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		s.waitAckFailed.Store(true)
		return
	}
	if err := file.Close(); err != nil {
		s.waitAckFailed.Store(true)
	}
}

func (s *remoteMCPConnectedServer) result(isError bool, capability ...string) *mcp.CallToolResult {
	raw := "synthetic startup Basic credential"
	joined := "synthetic-mcp-owner:" + raw
	encoded := base64.StdEncoding.EncodeToString([]byte(joined))
	authorization := "Basic " + encoded
	text := raw + "|" + authorization + "|" + encoded + "|synthetic MCP custom header|synthetic-unselected-account-secret|" + string(s.knownLiteral)
	structured := map[string]any{"raw": raw, "authorization": authorization, "encoded": encoded, "custom": "synthetic MCP custom header", "known": "synthetic-unselected-account-secret", "owner": string(s.knownLiteral), "n": 7}
	if len(capability) != 0 && capability[0] != "" {
		text += "|" + capability[0]
		structured["capability"] = capability[0]
	}
	return &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: text}}, StructuredContent: structured}
}

func remoteMCPPreparedLaunchChild(t *testing.T, ctx context.Context, path string, profile string) {
	t.Helper()
	agent.AssertRemoteMCPPreparedLaunch(t, ctx, path, profile, agent.PreparedLaunchHelpers{
		OwnerEndpoint:               remoteMCPPreparedOwnerEndpoint,
		OwnerDial:                   remoteMCPPreparedOwnerDial,
		OwnerDialRefused:            remoteMCPPreparedOwnerDialRefused,
		SSHKeyPEM:                   remoteMCPDeterministicSSHKeyPEM,
		RequireOutputFilterTerminal: launchguard.RequireTerminal,
		SelectOutputGuard:           launchguard.Select,
		OutputFilterWarning:         launchguard.Warning,
		Marker:                      remoteMCPPreparedMarker,
	})
}

func remoteMCPDeterministicSSHKeyPEM(private ed25519.PrivateKey, comment string) []byte {
	sshString := func(value []byte) []byte {
		out := make([]byte, 4+len(value))
		binary.BigEndian.PutUint32(out, uint32(len(value)))
		copy(out[4:], value)
		return out
	}
	algorithm := sshString([]byte("ssh-ed25519"))
	publicPart := append(append([]byte(nil), algorithm...), sshString(private[32:])...)
	check := make([]byte, 4)
	section := append([]byte(nil), check...)
	section = append(section, check...)
	section = append(section, algorithm...)
	section = append(section, sshString(private[32:])...)
	section = append(section, sshString(private)...)
	section = append(section, sshString([]byte(comment))...)
	for pad := byte(1); len(section)%8 != 0; pad++ {
		section = append(section, pad)
	}
	blob := append([]byte(nil), []byte("openssh-key-v1\x00")...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString(nil)...)
	blob = append(blob, 0, 0, 0, 1)
	blob = append(blob, sshString(publicPart)...)
	blob = append(blob, sshString(section)...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: blob})
}

func remoteMCPConnectedScenario(scenario string) bool {
	return scenario == "connected-basic" || scenario == "connected-bypass" || scenario == "connected-active-cancel" || scenario == "connected-cancel" || scenario == "connected-empty"
}

func remoteMCPConnectedNamespace(binding mcpdirectory.Binding) string {
	identity := fmt.Sprintf("%d:%s|%d:%s|%d|%d", len(binding.ServerID), binding.ServerID, len(binding.AccountID), binding.AccountID, binding.ServerRevision, binding.AccountRevision)
	digest := sha256.Sum256([]byte(identity))
	return "mcp" + hex.EncodeToString(digest[:6]) + "_"
}
