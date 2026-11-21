package ownerrotationtest

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
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
	var trace rotationMCPTrace
	flakediag.OnFailure(t, func() string {
		// Start at column zero on a fresh row; the keeper finds the frame by its delimiters.
		fmt.Fprintf(os.Stdout, "\r\n%s\n", trace.evidence.frame())
		return "MCP operation evidence written to child stdout"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	session := trace.session(t, ctx)
	target := trace.target(t, ctx, session)
	initial := rotationReadDone(t, ctx, session, trace.startJob(t, ctx, session, "exec-initial", target, "ssjack-ci-owner-rotation-once").JobID, &trace, "initial-job")
	if initial.Stdout != "SYNTHETIC-ROTATION-JOB-OK\n" {
		trace.fail(t, "stdout-mismatch", "initial actual MCP SSH job did not use fixture")
	}
	if initial.ExitCode != 0 {
		trace.fail(t, "nonzero-exit", "initial actual MCP SSH job did not use fixture")
	}
	hold := trace.startJob(t, ctx, session, "exec-hold", target, "ssjack-ci-owner-rotation-hold")
	fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-OLD-JOB-READY")
	reader := bufio.NewReader(os.Stdin)
	for {
		trace.beginSingle("control")
		line, err := reader.ReadString('\n')
		if err != nil {
			trace.fail(t, "control-read-error", "keeper-launched MCP child lost its test control input")
		}
		switch strings.TrimSpace(line) {
		case "n":
			out := rotationReadDone(t, ctx, session, trace.startJob(t, ctx, session, "exec-new", target, "ssjack-ci-owner-rotation-once").JobID, &trace, "new-job")
			if out.Stdout != "SYNTHETIC-ROTATION-JOB-OK\n" {
				trace.fail(t, "stdout-mismatch", "new-key MCP job failed")
			}
			if out.ExitCode != 0 {
				trace.fail(t, "nonzero-exit", "new-key MCP job failed")
			}
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-NEW-JOB-DONE")
		case "h":
			// Guarded short stdout stays buffered until completion, so liveness here
			// is "not done"; the parent adds the fixture's transport check.
			trace.begin("old-job-liveness")
			out := trace.read(t, ctx, session, hold.JobID, map[string]any{"job_id": hold.JobID}, 0, 0)
			if out.Done {
				trace.fail(t, "unexpected-done", "rotation did not retain the old admitted SSH job")
			}
			if out.JobID != hold.JobID {
				trace.fail(t, "job-mismatch", "rotation did not retain the old admitted SSH job")
			}
			trace.finish("matched")
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-OLD-JOB-ALIVE")
		case "o":
			release := trace.startJob(t, ctx, session, "exec-release", target, "ssjack-ci-owner-rotation-release")
			if rotationReadDone(t, ctx, session, release.JobID, &trace, "release-job").ExitCode != 0 {
				trace.fail(t, "nonzero-exit", "new-key MCP release fixture failed")
			}
			out := rotationReadDone(t, ctx, session, hold.JobID, &trace, "old-job-finish")
			if out.ExitCode != 0 {
				trace.fail(t, "nonzero-exit", "retained old-key SSH job did not finish intact")
			}
			if out.Stdout != "SYNTHETIC-ROTATION-HELD\n" {
				trace.fail(t, "stdout-mismatch", "retained old-key SSH job did not finish intact")
			}
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-OLD-JOB-DONE")
		case "q":
			var cancelled remote.CancelOutput
			trace.beginSingle("cancel")
			trace.callTool(t, ctx, session, "remote_cancel", map[string]any{"job_id": hold.JobID}, &cancelled)
			trace.finish("matched")
			fmt.Fprintln(os.Stdout, "ACTUAL-ROTATION-MCP-STOPPED")
			return
		default:
			trace.fail(t, "unexpected-command", "unexpected rotation MCP fixture command")
		}
	}
}

func (r *rotationMCPTrace) session(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	r.beginSingle("bootstrap")
	connection, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		r.fail(t, "bootstrap-error", "rotation harness could not authenticate to actual keeper")
	}
	r.finish("matched")
	t.Cleanup(func() { _ = connection.Close() })
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	r.beginSingle("server-connect")
	server, err := bridge.NewServer(connection).Connect(ctx, serverTransport, nil)
	if err != nil {
		r.fail(t, "server-error", "rotation MCP server could not attach")
	}
	r.finish("matched")
	t.Cleanup(func() { _ = server.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "owner-rotation-ci-fixture", Version: "test"}, nil)
	r.beginSingle("client-connect")
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		r.fail(t, "client-error", "rotation MCP client could not attach")
	}
	r.finish("matched")
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func (r *rotationMCPTrace) callTool(t *testing.T, ctx context.Context, session *mcp.ClientSession, tool string, input, output any) {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: input})
	var class string
	switch {
	case err != nil:
		class = "transport-error"
	case result == nil:
		class = "nil-result"
	case result.IsError:
		class = "tool-error"
	}
	if class != "" {
		r.fail(t, class, "authenticated rotation MCP operation failed: "+tool)
	}
	text, err := bridge.ResultText(result)
	if err != nil {
		class = "result-text-error"
	} else if bridge.ParseResult(text, output) != nil {
		class = "parse-error"
	}
	if class != "" {
		r.fail(t, class, "rotation MCP result is not the plain-text contract")
	}
}
func (r *rotationMCPTrace) target(t *testing.T, ctx context.Context, session *mcp.ClientSession) string {
	t.Helper()
	var output remote.TargetsOutput
	r.beginSingle("targets")
	r.callTool(t, ctx, session, "remote_targets", map[string]any{}, &output)
	if len(output.Targets) != 1 {
		r.fail(t, "target-cardinality", "keeper did not scope one synthetic rotation account")
	}
	r.finish("matched")
	return output.Targets[0]
}
func (r *rotationMCPTrace) startJob(t *testing.T, ctx context.Context, session *mcp.ClientSession, operation, target, command string) remote.StartOutput {
	t.Helper()
	var output remote.StartOutput
	timeout := 90
	if command == "ssjack-ci-owner-rotation-hold" {
		timeout = 600
	}
	r.beginSingle(operation)
	r.callTool(t, ctx, session, "remote_exec", map[string]any{"target": target, "command": command, "timeout_seconds": timeout}, &output)
	if output.JobID == "" {
		r.fail(t, "missing-job-id", "actual MCP SSH job omitted operation identity")
	}
	r.finish("matched")
	return output
}

type rotationMCPTrace struct {
	start    time.Time
	evidence rotationMCPEvidence
}

func (r *rotationMCPTrace) begin(operation string) {
	*r = rotationMCPTrace{start: time.Now(), evidence: rotationMCPEvidence{operation: operation}}
}

func (r *rotationMCPTrace) beginSingle(operation string) {
	r.begin(operation)
	r.evidence.attempts = 1
}

func (r *rotationMCPTrace) finish(class string) {
	if !r.start.IsZero() {
		r.evidence.elapsedNS = time.Since(r.start).Nanoseconds()
		r.start = time.Time{}
	}
	r.evidence.class = class
}

func (r *rotationMCPTrace) fail(t *testing.T, class, message string) {
	t.Helper()
	r.finish(class)
	t.Fatal(message)
}

func (r *rotationMCPTrace) read(t *testing.T, ctx context.Context, session *mcp.ClientSession, id string, input map[string]any, stdoutOffset, stderrOffset int64) bridge.ReadOutput {
	t.Helper()
	r.evidence.attempts++
	// A failed attempt invalidates only the latest attempt, not the last parsed read.
	r.evidence.valid = false
	var out bridge.ReadOutput
	r.callTool(t, ctx, session, "remote_read", input, &out)
	r.evidence.valid, r.evidence.observed = true, true
	r.evidence.done, r.evidence.stdoutMore, r.evidence.stderrMore = out.Done, out.StdoutMore, out.StderrMore
	r.evidence.requestedStdout, r.evidence.requestedStderr = stdoutOffset, stderrOffset
	r.evidence.returnedStdout, r.evidence.returnedStderr = out.StdoutOffset, out.StderrOffset
	r.evidence.stdoutLost, r.evidence.stderrLost = out.StdoutLost, out.StderrLost
	r.evidence.sameJob = out.JobID == id
	r.evidence.exitCode = 0
	if out.Done {
		r.evidence.exitCode = out.ExitCode
	}
	return out
}

// rotationReadUntil polls remote_read, accumulating output, until ready accepts it.
func rotationReadUntil(t *testing.T, ctx context.Context, session *mcp.ClientSession, id string, ready func(bridge.ReadOutput, string) bool, trace *rotationMCPTrace, operation string) bridge.ReadOutput {
	t.Helper()
	trace.begin(operation)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var stdout, stderr strings.Builder
	var stdoutOffset, stderrOffset int64
	for {
		output := trace.read(t, ctx, session, id, map[string]any{"job_id": id, "stdout_offset": stdoutOffset, "stderr_offset": stderrOffset}, stdoutOffset, stderrOffset)
		const failure = "MCP SSH job output was lost or its offsets moved backwards"
		switch {
		case output.StdoutLost:
			trace.fail(t, "stdout-lost", failure)
		case output.StderrLost:
			trace.fail(t, "stderr-lost", failure)
		case output.JobID != id:
			trace.fail(t, "job-mismatch", failure)
		case output.StdoutOffset < stdoutOffset:
			trace.fail(t, "stdout-offset-backwards", failure)
		case output.StderrOffset < stderrOffset:
			trace.fail(t, "stderr-offset-backwards", failure)
		}
		stdout.WriteString(output.Stdout)
		stderr.WriteString(output.Stderr)
		stdoutOffset, stderrOffset = output.StdoutOffset, output.StderrOffset
		if ready(output, stdout.String()) {
			output.Stdout, output.Stderr = stdout.String(), stderr.String()
			trace.finish("matched")
			return output
		}
		select {
		case <-ctx.Done():
			trace.fail(t, rotationContextOutcome(ctx.Err()), "MCP SSH job did not reach its expected state before the fixture deadline")
		case <-ticker.C:
		}
	}
}

func rotationReadDone(t *testing.T, ctx context.Context, session *mcp.ClientSession, id string, trace *rotationMCPTrace, operation string) bridge.ReadOutput {
	t.Helper()
	return rotationReadUntil(t, ctx, session, id, func(output bridge.ReadOutput, _ string) bool {
		return output.Done && !output.StdoutMore && !output.StderrMore
	}, trace, operation)
}
