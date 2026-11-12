package ownerrotationtest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

// rotationAuthorizedScript is the fixed add-key command the production client sends.
const rotationAuthorizedScript = `set -eu
umask 077
IFS= read -r old
IFS= read -r new
oldtype=${old%% *}
oldblob=${old#* }
newtype=${new%% *}
newblob=${new#* }
directory=$HOME/.ssh
file=$directory/authorized_keys
[ -d "$directory" ] && [ ! -L "$directory" ]
[ -f "$file" ] && [ ! -L "$file" ]
lock=$directory/.ssjack-rotate.lock
mkdir "$lock"
trap 'rmdir "$lock"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
awk -v ot="$oldtype" -v ob="$oldblob" -v nt="$newtype" -v nb="$newblob" '
    index($0, ob) { found=1; if ($1 != ot || $2 != ob) bad=1 }
    index($0, nb) { if ($1 != nt || $2 != nb) bad=1 }
    END { if (!found || bad) exit 1 }
' "$file"
chmod 700 "$directory"
chmod 600 "$file"
if ! grep -Fqx -- "$new" "$file"; then
    printf '\n%s\n' "$new" >> "$file"
fi
`

// Child is a process-only entry point. Its roles are supplied only by the
// synthetic test harness, never by application startup or secret inputs.
func Child(t *testing.T, run func(context.Context, []string) (int, error)) {
	role := os.Getenv("SSJACK_OWNER_ROTATION_CHILD")
	switch role {
	case "":
		t.Skip("synthetic owner-rotation process child only")
	case "mcp":
		rotationMCPHarness(t)
		return
	case "cli", "human", "owner":
	default:
		t.Fatal("unknown owner rotation child role")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	code, err := run(ctx, args)
	switch {
	case role == "owner":
		// The parent stops this child at the Add barrier; finishing is itself a failure.
		t.Fatal("owner child outlived its deliberate crash")
	case role == "cli" && os.Getenv("SSJACK_OWNER_ROTATION_EXPECT_REFUSAL") == "1":
		if code == 0 || err == nil {
			t.Fatal("unapproved rotate-key CLI unexpectedly succeeded")
		}
	case code != 0 || err != nil:
		t.Fatal("actual owner rotation CLI child failed")
	}
}

func rotationMCPHarness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	session := rotationHarnessSession(t, ctx)
	target := rotationTarget(t, ctx, session)
	initial := rotationReadDone(t, ctx, session, rotationStart(t, ctx, session, target, "ssjack-ci-owner-rotation-once").JobID)
	if initial.Stdout != "SYNTHETIC-ROTATION-JOB-OK\n" || initial.ExitCode != 0 {
		t.Fatal("initial actual MCP SSH job did not use fixture")
	}
	hold := rotationStart(t, ctx, session, target, "ssjack-ci-owner-rotation-hold")
	fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-OLD-JOB-READY")
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal("keeper-launched MCP child lost its test control input")
		}
		switch strings.TrimSpace(line) {
		case "n":
			out := rotationReadDone(t, ctx, session, rotationStart(t, ctx, session, target, "ssjack-ci-owner-rotation-once").JobID)
			if out.Stdout != "SYNTHETIC-ROTATION-JOB-OK\n" || out.ExitCode != 0 {
				t.Fatal("new-key MCP job failed")
			}
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-NEW-JOB-DONE")
		case "h":
			// Guarded short stdout stays buffered until completion, so liveness here
			// is "not done"; the parent adds the fixture's transport check.
			var out bridge.ReadOutput
			rotationCall(t, ctx, session, "remote_read", map[string]any{"job_id": hold.JobID}, &out)
			if out.Done || out.JobID != hold.JobID {
				t.Fatal("rotation did not retain the old admitted SSH job")
			}
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-OLD-JOB-ALIVE")
		case "o":
			release := rotationStart(t, ctx, session, target, "ssjack-ci-owner-rotation-release")
			if rotationReadDone(t, ctx, session, release.JobID).ExitCode != 0 {
				t.Fatal("new-key MCP release fixture failed")
			}
			out := rotationReadDone(t, ctx, session, hold.JobID)
			if out.ExitCode != 0 || out.Stdout != "SYNTHETIC-ROTATION-HELD\n" {
				t.Fatal("retained old-key SSH job did not finish intact")
			}
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-OLD-JOB-DONE")
		case "q":
			var cancelled remote.CancelOutput
			rotationCall(t, ctx, session, "remote_cancel", map[string]any{"job_id": hold.JobID}, &cancelled)
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-STOPPED")
			return
		default:
			t.Fatal("unexpected rotation MCP fixture command")
		}
	}
}

func rotationHarnessSession(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	connection, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		t.Fatal("rotation harness could not authenticate to actual keeper")
	}
	t.Cleanup(func() { _ = connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server, err := bridge.NewServer(connection).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal("rotation MCP server could not attach")
	}
	t.Cleanup(func() { _ = server.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "owner-rotation-ci-fixture", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal("rotation MCP client could not attach")
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}
func rotationCall(t *testing.T, ctx context.Context, session *mcp.ClientSession, tool string, input, output any) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: input})
	if err != nil || result == nil || result.IsError {
		t.Fatal("authenticated rotation MCP operation failed:", tool)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal("rotation MCP result could not be decoded")
	}
	var envelope struct {
		Structured json.RawMessage `json:"structuredContent"`
	}
	if json.Unmarshal(encoded, &envelope) != nil || len(envelope.Structured) == 0 || json.Unmarshal(envelope.Structured, output) != nil {
		t.Fatal("rotation MCP result omitted typed response")
	}
}
func rotationTarget(t *testing.T, ctx context.Context, session *mcp.ClientSession) string {
	t.Helper()
	var output remote.TargetsOutput
	rotationCall(t, ctx, session, "remote_targets", map[string]any{}, &output)
	if len(output.Targets) != 1 {
		t.Fatal("keeper did not scope one synthetic rotation account")
	}
	return output.Targets[0]
}
func rotationStart(t *testing.T, ctx context.Context, session *mcp.ClientSession, target, command string) remote.StartOutput {
	t.Helper()
	var output remote.StartOutput
	timeout := 90
	if command == "ssjack-ci-owner-rotation-hold" {
		timeout = 600
	}
	rotationCall(t, ctx, session, "remote_exec", map[string]any{"target": target, "command": command, "timeout_seconds": timeout}, &output)
	if output.JobID == "" {
		t.Fatal("actual MCP SSH job omitted operation identity")
	}
	return output
}

// rotationReadUntil polls remote_read, accumulating output, until ready accepts it.
func rotationReadUntil(t *testing.T, ctx context.Context, session *mcp.ClientSession, id string, ready func(bridge.ReadOutput, string) bool) bridge.ReadOutput {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var stdout, stderr strings.Builder
	var stdoutOffset, stderrOffset int64
	for {
		var output bridge.ReadOutput
		rotationCall(t, ctx, session, "remote_read", map[string]any{"job_id": id, "stdout_offset": stdoutOffset, "stderr_offset": stderrOffset}, &output)
		if output.StdoutLost || output.StderrLost || output.JobID != id || output.StdoutOffset < stdoutOffset || output.StderrOffset < stderrOffset {
			t.Fatal("MCP SSH job output was lost or its offsets moved backwards")
		}
		stdout.WriteString(output.Stdout)
		stderr.WriteString(output.Stderr)
		stdoutOffset, stderrOffset = output.StdoutOffset, output.StderrOffset
		if ready(output, stdout.String()) {
			output.Stdout, output.Stderr = stdout.String(), stderr.String()
			return output
		}
		select {
		case <-ctx.Done():
			t.Fatal("MCP SSH job did not reach its expected state before the fixture deadline")
		case <-ticker.C:
		}
	}
}

func rotationReadDone(t *testing.T, ctx context.Context, session *mcp.ClientSession, id string) bridge.ReadOutput {
	t.Helper()
	return rotationReadUntil(t, ctx, session, id, func(output bridge.ReadOutput, _ string) bool {
		return output.Done && !output.StdoutMore && !output.StderrMore
	})
}
