package ownertest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const nativeTestCleanupReserve = time.Minute
const nativeKeeperServiceBudget = 10 * time.Minute

// nativeDeadline caps a finite root by its parent and leaves the test cleanup reserve.
func nativeDeadline(now time.Time, budget, reserve time.Duration, parentDeadline time.Time, hasParent bool, testDeadline time.Time, hasTest bool) (time.Time, error) {
	if budget <= 0 || reserve < 0 {
		return time.Time{}, errors.New("invalid native acceptance budget")
	}
	deadline := now.Add(budget)
	if hasParent && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if hasTest {
		available := testDeadline.Add(-reserve)
		if available.Before(deadline) {
			deadline = available
		}
	}
	if !deadline.After(now) {
		return time.Time{}, errors.New("native acceptance deadline leaves no time before cleanup reserve")
	}
	return deadline, nil
}

func nativePhaseDeadline(now time.Time, budget time.Duration, parentDeadline time.Time, hasParent bool) (time.Time, error) {
	if budget <= 0 {
		return time.Time{}, errors.New("invalid native operation budget")
	}
	deadline := now.Add(budget)
	if hasParent && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if !deadline.After(now) {
		return time.Time{}, errors.New("native operation deadline has expired")
	}
	return deadline, nil
}

func nativeAcceptanceRoot(t *testing.T, parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	if parent == nil || parent.Err() != nil {
		t.Fatal("native acceptance root parent is unavailable")
	}
	parentDeadline, hasParent := parent.Deadline()
	testDeadline, hasTest := t.Deadline()
	deadline, err := nativeDeadline(time.Now(), budget, nativeTestCleanupReserve, parentDeadline, hasParent, testDeadline, hasTest)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithDeadline(parent, deadline)
}

func nativeOperationPhase(t *testing.T, parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	if parent == nil || parent.Err() != nil {
		t.Fatal("native acceptance service lifetime ended before its operation phase")
	}
	parentDeadline, hasParent := parent.Deadline()
	deadline, err := nativePhaseDeadline(time.Now(), budget, parentDeadline, hasParent)
	if err != nil {
		t.Fatal(err)
	}
	return context.WithDeadline(parent, deadline)
}

func nativePhaseCleanup(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), nativeTestCleanupReserve)
}

func TestNativeAcceptancePhaseBudgetTopology(t *testing.T) {
	now := time.Date(2026, time.November, 11, 0, 0, 0, 0, time.UTC)
	parentDeadline, testDeadline := now.Add(10*time.Minute), now.Add(11*time.Minute)
	if _, err := nativeDeadline(now, 10*time.Minute, time.Minute, parentDeadline, true, testDeadline, true); err != nil {
		t.Fatalf("finite root with cleanup reserve was refused: %v", err)
	}
	if deadline, err := nativeDeadline(now, 10*time.Minute, time.Minute, parentDeadline, true, testDeadline.Add(-5*time.Minute), true); err != nil || !deadline.Equal(testDeadline.Add(-6*time.Minute)) {
		t.Fatalf("root did not preserve test cleanup reserve under a shorter test deadline: deadline=%v err=%v", deadline, err)
	}
	if _, err := nativeDeadline(now, 10*time.Minute, time.Minute, parentDeadline, true, now.Add(time.Minute), true); err == nil {
		t.Fatal("root accepted a deadline with no time before cleanup reserve")
	}
	phaseStart := now.Add(83*time.Second + 600*time.Millisecond)
	oldEnd := now.Add(2 * time.Minute)
	oldPhase, err := nativePhaseDeadline(phaseStart, time.Minute, oldEnd, true)
	if err != nil || !oldPhase.Equal(oldEnd) || oldPhase.Sub(phaseStart) != 36*time.Second+400*time.Millisecond {
		t.Fatalf("old two-minute root did not cap the phase at 36.4 seconds: deadline=%v err=%v", oldPhase, err)
	}
	freshEnd, err := nativeDeadline(now, nativeKeeperServiceBudget, time.Minute, now.Add(15*time.Minute), true, testDeadline, true)
	if err != nil || !freshEnd.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("fresh ten-minute root deadline was not retained: deadline=%v err=%v", freshEnd, err)
	}
	freshPhase, err := nativePhaseDeadline(phaseStart, time.Minute, freshEnd, true)
	if err != nil || !freshPhase.Equal(phaseStart.Add(time.Minute)) {
		t.Fatalf("fresh ten-minute root did not retain the full phase: %v", err)
	}
}

func TestNativeAcceptancePhaseCancellationTopology(t *testing.T) {
	service, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	first, cancelFirst := nativeOperationPhase(t, service, time.Minute)
	cancelFirst()
	if !errors.Is(first.Err(), context.Canceled) || service.Err() != nil {
		t.Fatal("canceling the first operation phase canceled its service lifetime")
	}
	second, cancelSecond := nativeOperationPhase(t, service, time.Minute)
	defer cancelSecond()
	if second.Err() != nil {
		t.Fatal("fresh operation phase inherited cancellation from the first phase")
	}
	cancelService()
	if !errors.Is(service.Err(), context.Canceled) || !errors.Is(second.Err(), context.Canceled) {
		t.Fatal("service cancellation did not propagate to the fresh operation phase")
	}
}

const (
	refusalStdinTTY   nativeChildFailure = "refusal-stdin-tty"
	refusalStdoutTTY  nativeChildFailure = "refusal-stdout-tty"
	refusalRawMode    nativeChildFailure = "refusal-raw-mode"
	refusalCLICode    nativeChildFailure = "refusal-cli-code"
	refusalCLIVerdict nativeChildFailure = "refusal-cli-verdict"
)

func TestNativeWriterRefusalChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_REFUSAL_CHILD") != "1" {
		t.Skip("actual native writer refusal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		nativeChildFatal(t, refusalStdinTTY, "writer refusal child stdin is not a terminal")
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		nativeChildFatal(t, refusalStdoutTTY, "writer refusal child stdout is not a terminal")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		nativeChildFatal(t, refusalRawMode, "writer refusal child could not set raw terminal mode")
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	var args []string
	for index, value := range os.Args {
		if value == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	code, err := cli.Run(ctx, args)
	if code != 1 {
		nativeChildFatal(t, refusalCLICode, "legacy writer CLI code mismatch: got=%d want=1", code)
	}
	if !errors.Is(err, vault.ErrWriterRole) {
		nativeChildFatal(t, refusalCLIVerdict, "legacy writer verdict mismatch: class=%s", nativeResultClass(err, "other-error"))
	}
	fmt.Fprintln(os.Stdout, "ACTUAL-LEGACY-WRITER-REFUSED")
}

func nativeWriterRefusal(t, diagnostics *testing.T, parent context.Context, path string, password []byte, name string, server *sshfixture.LoopbackSSH) {
	t.Helper()
	ctx, cancel := nativeOperationPhase(t, parent, time.Minute)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("refusal baseline ciphertext read failed: class=%s bytes=%d", nativeResultClass(err, "read-error"), len(before))
	}
	connections := server.AcceptedConnections()
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "SSJACK_OWNER_NATIVE_REFUSAL_CHILD=1")
	trace := startNativeTerminal(t, diagnostics, ctx, "legacy writer refusal", ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeWriterRefusalChild$", "--", "--vault", path, "--server", name, "--account", "key-only", "rotate"}})
	trace.addChildFailureMarkers(refusalStdinTTY, refusalStdoutTTY, refusalRawMode, refusalCLICode, refusalCLIVerdict)
	defer func() {
		trace.cleanup(t, "writer refusal child did not close cleanly", "writer refusal child did not drain cleanly")
		leaked := trace.capture.Contains(password)
		trace.recordCaptured("hidden-input", "check", "matched=%t ", leaked)
		if leaked {
			trace.report(t).Error("writer refusal exposed hidden input")
		}
	}()
	trace.expectText(t, ctx, "vault-prompt", "Vault secret:", "actual legacy writer did not request its unlock")
	trace.write(t, "vault-unlock", nativeUnlockInput(password))
	trace.wait(t, ctx, "actual legacy writer did not complete its process")
	trace.expectText(t, ctx, "writer-refusal", "ACTUAL-LEGACY-WRITER-REFUSED", "actual legacy writer did not report its refusal")
	trace.recordCaptured("ciphertext-read", "check-start", "before=%d ", len(before))
	after, err := os.ReadFile(path)
	readClass := nativeResultClass(err, "read-error")
	trace.recordCaptured("ciphertext-read", "check-result", "class=%s after=%d ", readClass, len(after))
	if err != nil {
		trace.report(t).Fatalf("refusal ciphertext read failed: class=%s before=%d after=%d", readClass, len(before), len(after))
	}
	unchanged := bytes.Equal(before, after)
	trace.recordCaptured("ciphertext-compare", "check-result", "before=%d after=%d equal=%t ", len(before), len(after), unchanged)
	if !unchanged {
		trace.report(t).Fatalf("refused legacy writer changed ciphertext: before=%d after=%d", len(before), len(after))
	}
	accepted := server.AcceptedConnections()
	trace.recordCaptured("ssh-connections", "check-result", "before=%d after=%d ", connections, accepted)
	if accepted != connections {
		trace.report(t).Fatalf("refused legacy writer reached SSH server: before=%d after=%d", connections, accepted)
	}
	trace.flow.Complete()
}

const nativeGuardCommand = "ssjack-ci-known-literal-output"
const nativeGuardAddedCredential = "synthetic keeper MCP credential"

const (
	keeperForwardedOption      nativeChildFailure = "keeper-forwarded-option"
	keeperCommandEOF           nativeChildFailure = "keeper-command-eof"
	keeperCommandRead          nativeChildFailure = "keeper-command-read"
	keeperCommandUnknown       nativeChildFailure = "keeper-command-unknown"
	keeperBrokerConnect        nativeChildFailure = "keeper-broker-connect"
	keeperMCPServerConnect     nativeChildFailure = "keeper-mcp-server-connect"
	keeperMCPClientConnect     nativeChildFailure = "keeper-mcp-client-connect"
	keeperMCPCall              nativeChildFailure = "keeper-mcp-call"
	keeperMCPResultMissing     nativeChildFailure = "keeper-mcp-result-missing"
	keeperMCPToolError         nativeChildFailure = "keeper-mcp-tool-error"
	keeperMCPMarshal           nativeChildFailure = "keeper-mcp-marshal"
	keeperMCPConnectionLiteral nativeChildFailure = "keeper-mcp-connection-literal"
	keeperMCPAddedLiteral      nativeChildFailure = "keeper-mcp-added-literal"
	keeperMCPTextExtract       nativeChildFailure = "keeper-mcp-text-extract"
	keeperMCPTextParse         nativeChildFailure = "keeper-mcp-text-parse"
	keeperScopeRefusalCount    nativeChildFailure = "keeper-scope-refusal-count"
	keeperScopeRefusalCall     nativeChildFailure = "keeper-scope-refusal-call"
	keeperScopeRefusalMissing  nativeChildFailure = "keeper-scope-refusal-missing"
	keeperScopeRefusalSuccess  nativeChildFailure = "keeper-scope-refusal-success"
	keeperScopeAdmissionMarker nativeChildFailure = "keeper-scope-admission-marker"
	keeperGuardScopeCount      nativeChildFailure = "keeper-guard-scope-count"
	keeperMCPPoll              nativeChildFailure = "keeper-mcp-poll"
	keeperStdoutBase64         nativeChildFailure = "keeper-stdout-base64"
	keeperStderrBase64         nativeChildFailure = "keeper-stderr-base64"
	keeperStdoutBytes          nativeChildFailure = "keeper-stdout-bytes"
	keeperStderrBytes          nativeChildFailure = "keeper-stderr-bytes"
	keeperExitCode             nativeChildFailure = "keeper-exit-code"
	keeperJobError             nativeChildFailure = "keeper-job-error"
	keeperStdoutOffset         nativeChildFailure = "keeper-stdout-offset"
	keeperStderrOffset         nativeChildFailure = "keeper-stderr-offset"
	keeperStdoutTextEmpty      nativeChildFailure = "keeper-stdout-text-empty"
	keeperStderrTextMismatch   nativeChildFailure = "keeper-stderr-text-mismatch"
)

func (trace *nativeTerminalTrace) addKeeperHarnessFailureMarkers() {
	trace.addChildFailureMarkers(
		keeperForwardedOption, keeperCommandEOF, keeperCommandRead, keeperCommandUnknown,
		keeperBrokerConnect, keeperMCPServerConnect, keeperMCPClientConnect,
		keeperMCPCall, keeperMCPResultMissing, keeperMCPToolError, keeperMCPMarshal,
		keeperMCPConnectionLiteral, keeperMCPAddedLiteral, keeperMCPTextExtract, keeperMCPTextParse,
		keeperScopeRefusalCount, keeperScopeRefusalCall, keeperScopeRefusalMissing,
		keeperScopeRefusalSuccess, keeperScopeAdmissionMarker, keeperGuardScopeCount,
		keeperMCPPoll, keeperStdoutBase64, keeperStderrBase64, keeperStdoutBytes, keeperStderrBytes,
		keeperExitCode, keeperJobError, keeperStdoutOffset, keeperStderrOffset,
		keeperStdoutTextEmpty, keeperStderrTextMismatch,
	)
}

func TestNativeKeeperHarnessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_KEEPER_CHILD") != "1" {
		t.Skip("owned finite keeper harness only")
	}
	for _, argument := range os.Args[1:] {
		if argument == "--no-output-filter" {
			nativeChildFatal(t, keeperForwardedOption, "root output-filter option was forwarded to the harness")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	session := nativeGuardHarnessSession(t, ctx)
	nativeGuardHarnessCheck(t, ctx, session, false)
	fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-MCP-GUARD-READY")
	fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-HARNESS-READY")
	for {
		var command [1]byte
		if _, err := io.ReadFull(os.Stdin, command[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				nativeChildFatal(t, keeperCommandEOF, "keeper harness did not receive its graceful exit request")
			} else {
				nativeChildFatal(t, keeperCommandRead, "keeper harness could not read its fixture command")
			}
		}
		switch command[0] {
		case 'q':
			fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-HARNESS-STOPPED")
			return
		case 'g':
			nativeGuardHarnessCheck(t, ctx, session, true)
			fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-MCP-GUARD-REFRESHED")
		case 'r':
			nativeGuardHarnessRefusesChangedScope(t, ctx, session)
			fmt.Fprintln(os.Stdout, "ACTUAL-KEEPER-SSH-SCOPE-REFUSED")
		case '\r', '\n':
		default:
			nativeChildFatal(t, keeperCommandUnknown, "keeper harness received an unexpected fixture command")
		}
	}
}

func TestVaultOutputFilterFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("native output-filter acceptance runs in GitHub CI")
	}
	ctx, cancel := nativeAcceptanceRoot(t, context.Background(), 10*time.Minute)
	defer cancel()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal("bypass fixture public key setup failed")
	}
	server := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "owner-control")
	v := vault.NewDirectory()
	defer v.Close()
	target := vault.Target{Address: server.Address(), User: "second", Password: []byte(sshfixture.ConnectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.HostKey))}, Usage: "both"}
	serverID, err := v.AddServer("production", "main", target)
	if err != nil {
		t.Fatal("bypass fixture server setup failed")
	}
	block, err := ssh.MarshalPrivateKey(private, "synthetic bypass writer refusal")
	if err != nil {
		t.Fatal("bypass fixture private key setup failed")
	}
	defer clear(block.Bytes)
	key := target
	key.User, key.Password, key.PrivateKey, key.Usage = "first", nil, pem.EncodeToMemory(block), "agent"
	defer clear(key.PrivateKey)
	if err := v.SetAccount(serverID, "key-only", key); err != nil {
		t.Fatal("bypass fixture key account setup failed")
	}
	added := target
	added.User, added.Password, added.Usage = "native-user", []byte(nativeGuardAddedCredential), "agent"
	if err := v.SetAccount(serverID, "keeper-added", added); err != nil {
		t.Fatal("bypass fixture added account setup failed")
	}
	password := []byte("synthetic native bypass database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "bypass.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatalf("bypass database creation failed: class=%s", nativeResultClass(err, "create-error"))
	}
	nativeKeeperCycles(t, ctx, path, password, serverID, "production", server, []string{"bypass"}, nil)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("bypass ciphertext read failed: class=%s bytes=%d", nativeResultClass(err, "read-error"), len(encoded))
	}
	if bytes.Contains(encoded, password) {
		t.Fatalf("bypass ciphertext contains unlock literal: bytes=%d", len(encoded))
	}
	if bytes.Contains(encoded, []byte(sshfixture.ConnectPassword)) {
		t.Fatalf("bypass ciphertext contains connection literal: bytes=%d", len(encoded))
	}
	if bytes.Contains(encoded, []byte(nativeGuardAddedCredential)) {
		t.Fatalf("bypass ciphertext contains added-account literal: bytes=%d", len(encoded))
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal("bypass database failed authenticated readback")
	}
	loaded.Close()
}

func nativeGuardMCPCall(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, arguments, output any) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		nativeChildFatal(t, keeperMCPCall, "native guard MCP call failed: tool=%s class=%s", name, nativeResultClass(err, "call-error"))
	}
	if result == nil {
		nativeChildFatal(t, keeperMCPResultMissing, "native guard MCP result missing: tool=%s", name)
	}
	if result.IsError {
		nativeChildFatal(t, keeperMCPToolError, "native guard MCP tool error: tool=%s content=%d", name, len(result.Content))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		nativeChildFatal(t, keeperMCPMarshal, "native guard MCP marshal failed: tool=%s", name)
	}
	if os.Getenv("SSJACK_OWNER_GUARD_BYPASS_CHILD") != "1" {
		if bytes.Contains(encoded, []byte(sshfixture.ConnectPassword)) {
			nativeChildFatal(t, keeperMCPConnectionLiteral, "native guard MCP result contains connection literal: tool=%s bytes=%d", name, len(encoded))
		}
		if bytes.Contains(encoded, []byte(nativeGuardAddedCredential)) {
			nativeChildFatal(t, keeperMCPAddedLiteral, "native guard MCP result contains added-account literal: tool=%s bytes=%d", name, len(encoded))
		}
	}
	text, err := bridge.ResultText(result)
	if err != nil {
		nativeChildFatal(t, keeperMCPTextExtract, "native guard MCP text extraction failed: tool=%s content=%d", name, len(result.Content))
	}
	if err := bridge.ParseResult(text, output); err != nil {
		nativeChildFatal(t, keeperMCPTextParse, "native guard MCP text parse failed: tool=%s bytes=%d", name, len(text))
	}
}

func nativeGuardHarnessSession(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	connection, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		nativeChildFatal(t, keeperBrokerConnect, "actual harness could not authenticate to the keeper broker")
	}
	t.Cleanup(func() { _ = connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server, err := bridge.NewServer(connection).Connect(ctx, serverTransport, nil)
	if err != nil {
		nativeChildFatal(t, keeperMCPServerConnect, "actual harness MCP server could not connect")
	}
	t.Cleanup(func() { _ = server.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "native-guard-fixture", Version: "dev"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		nativeChildFatal(t, keeperMCPClientConnect, "actual harness MCP client could not connect")
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func nativeGuardHarnessRefusesChangedScope(t *testing.T, parent context.Context, session *mcp.ClientSession) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var targets remote.TargetsOutput
	nativeGuardMCPCall(t, ctx, session, "remote_targets", map[string]any{}, &targets)
	if len(targets.Targets) != 1 {
		nativeChildFatal(t, keeperScopeRefusalCount, "native guard SSH scope count mismatch: got=%d want=1", len(targets.Targets))
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": targets.Targets[0], "command": nativeGuardCommand}})
	if err != nil {
		nativeChildFatal(t, keeperScopeRefusalCall, "native guard scope refusal call failed: class=%s", nativeResultClass(err, "call-error"))
	}
	if result == nil {
		nativeChildFatal(t, keeperScopeRefusalMissing, "native guard scope refusal result missing")
	}
	if !result.IsError {
		nativeChildFatal(t, keeperScopeRefusalSuccess, "native guard scope refusal unexpectedly succeeded: content=%d", len(result.Content))
	}
	foundAdmissionError := false
	for _, content := range result.Content {
		text, ok := content.(*mcp.TextContent)
		if ok && text.Text == remote.ErrAdmission.Error() {
			foundAdmissionError = true
			break
		}
	}
	if !foundAdmissionError {
		nativeChildFatal(t, keeperScopeAdmissionMarker, "native guard scope refusal admission marker missing: content=%d", len(result.Content))
	}
}

func nativeGuardHarnessCheck(t *testing.T, parent context.Context, session *mcp.ClientSession, refreshed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var targets remote.TargetsOutput
	nativeGuardMCPCall(t, ctx, session, "remote_targets", map[string]any{}, &targets)
	if len(targets.Targets) != 1 {
		nativeChildFatal(t, keeperGuardScopeCount, "native guard SSH scope count mismatch: got=%d want=1", len(targets.Targets))
	}
	command := nativeGuardCommand
	want := "[REDACTED]|\xff"
	if refreshed {
		command += "-refresh"
		want = "[REDACTED]|[REDACTED]|\xff"
	}
	stderrWant, textWant := "[REDACTED]|\xfe", "[REDACTED]|\ufffd"
	if os.Getenv("SSJACK_OWNER_GUARD_BYPASS_CHILD") == "1" {
		want = sshfixture.ConnectPassword + "|\xff"
		if refreshed {
			want = sshfixture.ConnectPassword + "|" + nativeGuardAddedCredential + "|\xff"
		}
		stderrWant, textWant = sshfixture.ConnectPassword+"|\xfe", sshfixture.ConnectPassword+"|\ufffd"
	}
	var started remote.StartOutput
	nativeGuardMCPCall(t, ctx, session, "remote_exec", map[string]any{"target": targets.Targets[0], "command": command}, &started)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var out bridge.ReadOutput
	polls := 0
	for {
		polls++
		nativeGuardMCPCall(t, ctx, session, "remote_read", map[string]any{"job_id": started.JobID}, &out)
		if out.Done {
			break
		}
		select {
		case <-ctx.Done():
			nativeChildFatal(t, keeperMCPPoll, "native guard MCP poll unfinished: polls=%d class=%s", polls, nativeResultClass(ctx.Err(), "context-error"))
		case <-ticker.C:
		}
	}
	stdout, err := base64.StdEncoding.DecodeString(out.StdoutBase64)
	if err != nil {
		nativeChildFatal(t, keeperStdoutBase64, "native guard MCP stdout base64 invalid: encoded=%d decoded=%d", len(out.StdoutBase64), len(stdout))
	}
	stderr, err := base64.StdEncoding.DecodeString(out.StderrBase64)
	if err != nil {
		nativeChildFatal(t, keeperStderrBase64, "native guard MCP stderr base64 invalid: encoded=%d decoded=%d", len(out.StderrBase64), len(stderr))
	}
	if !bytes.Equal(stdout, []byte(want)) {
		nativeChildFatal(t, keeperStdoutBytes, "native guard MCP stdout bytes mismatch: got=%d want=%d", len(stdout), len(want))
	}
	if !bytes.Equal(stderr, []byte(stderrWant)) {
		nativeChildFatal(t, keeperStderrBytes, "native guard MCP stderr bytes mismatch: got=%d want=%d", len(stderr), len(stderrWant))
	}
	if out.ExitCode != 23 {
		nativeChildFatal(t, keeperExitCode, "native guard MCP exit code mismatch: got=%d want=23", out.ExitCode)
	}
	if out.Error != "" {
		nativeChildFatal(t, keeperJobError, "native guard MCP job reported an error")
	}
	if out.StdoutOffset != int64(len(stdout)) {
		nativeChildFatal(t, keeperStdoutOffset, "native guard MCP stdout offset mismatch: got=%d want=%d", out.StdoutOffset, len(stdout))
	}
	if out.StderrOffset != int64(len(stderr)) {
		nativeChildFatal(t, keeperStderrOffset, "native guard MCP stderr offset mismatch: got=%d want=%d", out.StderrOffset, len(stderr))
	}
	if out.Stdout == "" {
		nativeChildFatal(t, keeperStdoutTextEmpty, "native guard MCP stdout text empty")
	}
	if out.Stderr != textWant {
		nativeChildFatal(t, keeperStderrTextMismatch, "native guard MCP stderr text mismatch: got=%d want=%d", len(out.Stderr), len(textWant))
	}
}

// nativeTerminalTrace flow failure marking and the shared flow reporter live
// here to keep native_command_tui_fullprofile_test.go under its line cap.
func (trace *nativeTerminalTrace) flowFail() {
	if trace == nil || trace.flow == nil {
		return
	}
	trace.flow.Fail()
}

type nativeFlowReporter struct {
	t     *testing.T
	trace *nativeTerminalTrace
}

func (trace *nativeTerminalTrace) report(t *testing.T) nativeFlowReporter {
	return nativeFlowReporter{t, trace}
}

func (r nativeFlowReporter) Helper() { r.t.Helper() }
func (r nativeFlowReporter) Fatal(args ...any) {
	r.t.Helper()
	r.trace.flowFail()
	r.t.Fatal(args...)
}
func (r nativeFlowReporter) Fatalf(format string, args ...any) {
	r.t.Helper()
	r.trace.flowFail()
	r.t.Fatalf(format, args...)
}
func (r nativeFlowReporter) Error(args ...any) {
	r.t.Helper()
	r.trace.flowFail()
	r.t.Error(args...)
}
func (r nativeFlowReporter) Errorf(format string, args ...any) {
	r.t.Helper()
	r.trace.flowFail()
	r.t.Errorf(format, args...)
}
