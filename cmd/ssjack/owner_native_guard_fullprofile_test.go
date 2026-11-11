package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

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
	server := startLoopbackSSH(t, public, connectPassword, "owner-control")
	v := vault.NewDirectory()
	defer v.Close()
	target := vault.Target{Address: server.address(), User: "second", Password: []byte(connectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.hostKey))}, Usage: "both"}
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
	if err != nil || bytes.Contains(encoded, password) || bytes.Contains(encoded, []byte(connectPassword)) || bytes.Contains(encoded, []byte(nativeGuardAddedCredential)) {
		t.Fatal("output-filter bypass changed encrypted persistence boundaries")
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal("bypass database failed authenticated readback")
	}
	loaded.Close()
}

func nativeGuardSSHReply(server *loopbackSSH, channel ssh.Channel, request *ssh.Request) bool {
	var command struct{ Command string }
	if server.marker != "owner-control" || ssh.Unmarshal(request.Payload, &command) != nil || (command.Command != nativeGuardCommand && command.Command != nativeGuardCommand+"-refresh") {
		return false
	}
	if request.WantReply {
		_ = request.Reply(true, nil)
	}
	output := []byte(connectPassword + "|")
	if command.Command == nativeGuardCommand+"-refresh" {
		output = append(output, []byte(nativeGuardAddedCredential+"|")...)
	}
	output = append(output, 255)
	for _, value := range output {
		if _, err := channel.Write([]byte{value}); err != nil {
			return true
		}
	}
	_, _ = channel.Stderr().Write(append([]byte(connectPassword+"|"), 254))
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{23}))
	_ = channel.Close()
	return true
}

func nativeGuardMCPCall(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, arguments, output any) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil || result == nil || result.IsError {
		t.Fatal("actual native guard MCP call failed")
	}
	encoded, err := json.Marshal(result)
	if err != nil || (os.Getenv("SSJACK_OWNER_GUARD_BYPASS_CHILD") != "1" && (bytes.Contains(encoded, []byte(connectPassword)) || bytes.Contains(encoded, []byte(nativeGuardAddedCredential)))) {
		t.Fatal("actual native MCP result exposed a known credential")
	}
	var envelope struct {
		Structured json.RawMessage `json:"structuredContent"`
	}
	if json.Unmarshal(encoded, &envelope) != nil || len(envelope.Structured) == 0 || json.Unmarshal(envelope.Structured, output) != nil {
		t.Fatal("actual native MCP result omitted structured output")
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
	stderrWant, textWant := "[REDACTED]|\xfe", "[REDACTED]|�"
	if os.Getenv("SSJACK_OWNER_GUARD_BYPASS_CHILD") == "1" {
		want = connectPassword + "|\xff"
		if refreshed {
			want = connectPassword + "|" + nativeGuardAddedCredential + "|\xff"
		}
		stderrWant, textWant = connectPassword+"|\xfe", connectPassword+"|�"
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
