package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const nativeGuardCommand = "ssjack-ci-known-literal-output"
const nativeGuardAddedCredential = "synthetic keeper MCP credential"

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
	if err != nil || bytes.Contains(encoded, []byte(connectPassword)) || bytes.Contains(encoded, []byte(nativeGuardAddedCredential)) {
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
	if first != nil || second != nil || !bytes.Equal(stdout, []byte(want)) || !bytes.Equal(stderr, []byte("[REDACTED]|\xfe")) || out.ExitCode != 23 || out.Error != "" || out.StdoutOffset != int64(len(stdout)) || out.StderrOffset != int64(len(stderr)) {
		t.Fatal("actual native MCP text/base64 capture lost guard coverage or control fields")
	}
	if out.Stdout == "" || out.Stderr != "[REDACTED]|�" {
		t.Fatal("actual native MCP text representation was not guarded")
	}
}
