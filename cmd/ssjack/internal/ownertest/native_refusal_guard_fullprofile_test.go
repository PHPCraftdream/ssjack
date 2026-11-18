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
	"runtime"
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

func TestNativeWriterRefusalChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_REFUSAL_CHILD") != "1" {
		t.Skip("actual native writer refusal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Fatal("writer refusal child lacks a real terminal")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
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
	if code, err := cli.Run(ctx, args); code != 1 || !errors.Is(err, vault.ErrWriterRole) {
		t.Fatal("actual legacy writer did not refuse at native role admission")
	}
	fmt.Fprintln(os.Stdout, "ACTUAL-LEGACY-WRITER-REFUSED")
}

func nativeWriterRefusal(t *testing.T, parent context.Context, path string, password []byte, name string, server *sshfixture.LoopbackSSH) {
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
		t.Fatal(err)
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
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeWriterRefusalChild$", "--", "--vault", path, "--server", name, "--account", "key-only", "rotate"}})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	tail := newOwnerChildTail()
	terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
	ownerChildTerminal(t, "legacy writer refusal", executable, terminal, tail, started)
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, cancel := nativePhaseCleanup(t)
		defer cancel()
		if err := terminal.Close(cleanup); err != nil {
			t.Error("writer refusal child did not close cleanly")
		}
		if capture.Join(cleanup) != nil || capture.Contains(password) {
			t.Error("writer refusal did not join safely or exposed hidden input")
		}
		capture.Clear()
	}()
	captureWaitDiag(t, ctx, capture, "Vault secret:", "actual legacy writer did not request its unlock")
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	input := append(append([]byte(nil), password...), ending)
	_, err = terminal.Input.Write(input)
	clear(input)
	if err != nil {
		t.Fatal("actual legacy writer unlock input failed")
	}
	if err := terminal.Wait(ctx); err != nil {
		t.Fatal("actual legacy writer did not complete its process")
	}
	captureWaitDiag(t, ctx, capture, "ACTUAL-LEGACY-WRITER-REFUSED", "actual legacy writer did not report its refusal")
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || server.AcceptedConnections() != connections {
		t.Fatal("refused legacy writer changed ciphertext or reached the SSH server")
	}
}

const nativeGuardCommand = "ssjack-ci-known-literal-output"
const nativeGuardAddedCredential = "synthetic keeper MCP credential"

func TestNativeKeeperHarnessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_KEEPER_CHILD") != "1" {
		t.Skip("owned finite keeper harness only")
	}
	for _, argument := range os.Args[1:] {
		if argument == "--no-output-filter" {
			t.Fatal("root output-filter option was forwarded to the harness")
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
			t.Fatal("keeper harness did not receive its graceful exit request")
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
			t.Fatal("keeper harness received an unexpected fixture command")
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
		t.Fatal(err)
	}
	server := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "owner-control")
	v := vault.NewDirectory()
	defer v.Close()
	target := vault.Target{Address: server.Address(), User: "second", Password: []byte(sshfixture.ConnectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.HostKey))}, Usage: "both"}
	serverID, err := v.AddServer("production", "main", target)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "synthetic bypass writer refusal")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(block.Bytes)
	key := target
	key.User, key.Password, key.PrivateKey, key.Usage = "first", nil, pem.EncodeToMemory(block), "agent"
	defer clear(key.PrivateKey)
	if err := v.SetAccount(serverID, "key-only", key); err != nil {
		t.Fatal(err)
	}
	added := target
	added.User, added.Password, added.Usage = "native-user", []byte(nativeGuardAddedCredential), "agent"
	if err := v.SetAccount(serverID, "keeper-added", added); err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic native bypass database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "bypass.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	nativeKeeperCycles(t, ctx, path, password, serverID, "production", server, []string{"bypass"})
	encoded, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encoded, password) || bytes.Contains(encoded, []byte(sshfixture.ConnectPassword)) || bytes.Contains(encoded, []byte(nativeGuardAddedCredential)) {
		t.Fatal("output-filter bypass changed encrypted persistence boundaries")
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
	if err != nil || result == nil || result.IsError {
		t.Fatal("actual native guard MCP call failed")
	}
	encoded, err := json.Marshal(result)
	if err != nil || (os.Getenv("SSJACK_OWNER_GUARD_BYPASS_CHILD") != "1" && (bytes.Contains(encoded, []byte(sshfixture.ConnectPassword)) || bytes.Contains(encoded, []byte(nativeGuardAddedCredential)))) {
		t.Fatal("actual native MCP result exposed a known credential")
	}
	text, err := bridge.ResultText(result)
	if err != nil || bridge.ParseResult(text, output) != nil {
		t.Fatal("actual native MCP result is not the plain-text contract")
	}
}

func nativeGuardHarnessSession(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	connection, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		t.Fatal("actual harness could not authenticate to the keeper broker")
	}
	t.Cleanup(func() { _ = connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server, err := bridge.NewServer(connection).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal("actual harness MCP server could not connect")
	}
	t.Cleanup(func() { _ = server.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "native-guard-fixture", Version: "dev"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal("actual harness MCP client could not connect")
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
		t.Fatal("actual harness did not retain its exact SSH scope")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": targets.Targets[0], "command": nativeGuardCommand}})
	if err != nil || result == nil || !result.IsError {
		t.Fatal("actual harness did not return a scoped admission refusal")
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
		t.Fatal("actual harness refusal was not the fixed capability admission error")
	}
}

func nativeGuardHarnessCheck(t *testing.T, parent context.Context, session *mcp.ClientSession, refreshed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var targets remote.TargetsOutput
	nativeGuardMCPCall(t, ctx, session, "remote_targets", map[string]any{}, &targets)
	if len(targets.Targets) != 1 {
		t.Fatal("actual harness did not retain its exact SSH scope")
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
	for {
		nativeGuardMCPCall(t, ctx, session, "remote_read", map[string]any{"job_id": started.JobID}, &out)
		if out.Done {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual native guarded SSH job did not finish")
		case <-ticker.C:
		}
	}
	stdout, first := base64.StdEncoding.DecodeString(out.StdoutBase64)
	stderr, second := base64.StdEncoding.DecodeString(out.StderrBase64)
	if first != nil || second != nil || !bytes.Equal(stdout, []byte(want)) || !bytes.Equal(stderr, []byte(stderrWant)) || out.ExitCode != 23 || out.Error != "" || out.StdoutOffset != int64(len(stdout)) || out.StderrOffset != int64(len(stderr)) {
		t.Fatal("actual native MCP text/base64 capture lost guard coverage or control fields")
	}
	if out.Stdout == "" || out.Stderr != textWant {
		t.Fatal("actual native MCP text representation was not guarded")
	}
}
