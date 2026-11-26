package mcptasktest

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	execBridgeBudget = 45 * time.Second
	execMaxJobs      = 64        // internal/remote/internal/jobs/jobs.go maxJobs.
	execOutputLimit  = 256 << 10 // internal/remote/internal/jobs/jobs.go outputLimit.
	execChunkLimit   = 32 << 10  // internal/remote/internal/jobs/jobs.go chunkLimit.
)

type execKeeper struct {
	command *remote.Manager
	app     *application.Manager
	mu      sync.Mutex
	ids     []string
	appIDs  []string
}

func (k *execKeeper) Handle(ctx context.Context, request wire.Request) wire.Reply {
	if request.Operation == "session.describe" {
		return broker.Result(broker.Descriptor{
			Protocol: broker.FullProtocol, Mode: broker.ModeFull, Complete: true,
			Tools: []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel", "remote_upload", "remote_download", "transfer_status", "transfer_cancel"},
		}, nil)
	}
	if reply, handled := k.app.Handle(ctx, request); handled {
		if request.Operation == "app_start" && reply.OK {
			var started remote.StartOutput
			if wire.Decode(reply.Data, &started) == nil {
				k.mu.Lock()
				k.appIDs = append(k.appIDs, started.JobID)
				k.mu.Unlock()
			}
		}
		return reply
	}
	reply := k.command.Handle(ctx, request)
	if request.Operation == "start" && reply.OK {
		var started remote.StartOutput
		if wire.Decode(reply.Data, &started) == nil {
			k.mu.Lock()
			k.ids = append(k.ids, started.JobID)
			k.mu.Unlock()
		}
	}
	return reply
}

func startExecBridge(t *testing.T, ctx context.Context, keeper broker.Handler) (*exec.Cmd, *broker.Server, context.CancelFunc) {
	t.Helper()
	serverCtx, closeServer := context.WithCancel(ctx)
	session, token := strings.Repeat("5", 64), strings.Repeat("6", 64)
	server, err := broker.Listen(serverCtx, session, token, 2*time.Minute, keeper)
	if err != nil {
		t.Fatalf("start exec acceptance keeper: %v", err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{"mcpServers":{"ssjack":{"type":"stdio","command":"ssjack","args":["mcp"]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestMCPTaskBridgeChild$")
	command.Dir = root
	command.Env = append(os.Environ(), bridgeGate+"=1", broker.EnvSession+"="+session, broker.EnvToken+"="+token,
		broker.EnvEndpoint+"="+server.Endpoint(), broker.EnvPin+"="+server.Pin())
	command.Stderr = os.Stderr
	t.Cleanup(func() { closeServer(); server.Close() })
	return command, server, closeServer
}

func TestExecApplicationProcess(t *testing.T) {
	if os.Getenv("SSJACK_EXEC_APPLICATION_HELPER") != "1" {
		return
	}
	for _, name := range []string{broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile} {
		if os.Getenv(name) != "" {
			os.Exit(91)
		}
	}
	if len(os.Getenv(apptransport.EnvToken)) != 64 || len(os.Getenv(apptransport.EnvPin)) != 64 {
		os.Exit(92)
	}
	_, _ = io.WriteString(os.Stdout, "application output")
	os.Exit(0)
}

func newExecKeeper(t *testing.T, ctx context.Context, run remote.Runner) *execKeeper {
	t.Helper()
	managerCtx, managerCancel := context.WithCancel(ctx)
	command := remote.NewGuardedManager(managerCtx, []string{"local"}, run, func(context.Context) (*outputguard.Snapshot, error) {
		return outputguard.New(nil)
	})
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	workDir := filepath.Join(root, "work")
	if err := os.MkdirAll(appDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSJACK_EXEC_APPLICATION_HELPER", "1")
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	app, err := application.New(managerCtx, &application.Options{
		Profile: "local-test",
		Apps:    []application.App{{Name: "demo", Directory: appDir, Workdir: workDir, Executable: program, Args: []string{"-test.run=^TestExecApplicationProcess$", "--"}, Observational: []string{"inspect"}}},
		Runner:  func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil },
		Guard:   func(context.Context) (*outputguard.Snapshot, error) { return outputguard.New(nil) },
	})
	if err != nil {
		t.Fatalf("create real application manager: %v", err)
	}
	keeper := &execKeeper{command: command, app: app}
	t.Cleanup(func() { managerCancel(); app.Close(); command.Close() })
	return keeper
}

func TestMCPTaskExecPathOverTheLaunchedBridge(t *testing.T) {
	flakediag.Begin(t)
	ctx, cancel := context.WithTimeout(context.Background(), execBridgeBudget)
	defer cancel()
	runnerStarted := make(chan string, 4)
	lateFinish := make(chan struct{})
	cancelObserved := make(chan struct{}, 1)
	var releaseLate sync.Once
	logbook := &recorder{}
	keeper := newExecKeeper(t, ctx, func(runCtx context.Context, _ string, command string, stdout, stderr io.Writer) (int, error) {
		if strings.Contains(command, "fail") {
			_, _ = io.WriteString(stderr, "runner diagnostic CANARY-EXEC-STDERR-9f3a")
			return -1, errors.New("runner unavailable")
		}
		if strings.Contains(command, "nonzero") {
			return 7, nil
		}
		if strings.Contains(command, "timeout") {
			<-runCtx.Done()
			return -1, runCtx.Err()
		}
		if strings.Contains(command, "binary") {
			chunk := append(bytes.Repeat([]byte("x"), 4096+16), []byte{0xff, 'b', 0xfe}...)
			chunk = append(chunk, bytes.Repeat([]byte("y"), execOutputLimit-19)...)
			_, _ = stdout.Write(chunk)
			return 0, nil
		}
		if strings.Contains(command, "slow") {
			runnerStarted <- command
			<-runCtx.Done()
			return -1, runCtx.Err()
		}
		if strings.Contains(command, "late") {
			runnerStarted <- command
			select {
			case <-runCtx.Done():
				cancelObserved <- struct{}{}
				<-lateFinish
				_, _ = io.WriteString(stdout, "finished after cancel")
				return 0, nil
			case <-lateFinish:
				return -1, errors.New("late runner release")
			}
		}
		if strings.Contains(command, "block") {
			_, _ = io.WriteString(stdout, "before cancel")
			runnerStarted <- command
			<-runCtx.Done()
			return -1, runCtx.Err()
		}
		_, _ = io.WriteString(stdout, "local output")
		return 0, nil
	})
	// Registered after the keeper so it runs before the manager cleanup waits for the late runner.
	t.Cleanup(func() { releaseLate.Do(func() { close(lateFinish) }) })
	command, server, closeServer := startExecBridge(t, ctx, keeper.Handle)
	caps := &mcp.ClientCapabilities{}
	caps.AddExtension(taskExtension, map[string]any{})
	client := mcp.NewClient(&mcp.Implementation{Name: "exec-acceptance", Version: "1"}, &mcp.ClientOptions{Capabilities: caps})
	if err := mcp.AddSendingCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](client, "tasks/get"); err != nil {
		t.Fatal(err)
	}
	if err := mcp.AddSendingCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](client, "tasks/cancel"); err != nil {
		t.Fatal(err)
	}
	transport := &recordingTransport{inner: &mcp.CommandTransport{Command: command}, recorder: logbook}
	session, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: modernVersion})
	if err != nil {
		t.Fatalf("connect declaring client: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	t.Run("remote_exec completes and exposes exact resume bytes", func(t *testing.T) {
		started, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "emit"}})
		if err != nil || started == nil || started.IsError || len(started.Content) != 0 {
			t.Fatalf("remote_exec did not return task handle: %#v (%v)", started, err)
		}
		ids := keeper.commandIDs(t)
		if len(ids) != 1 {
			t.Fatalf("started ids = %v", ids)
		}
		id := ids[0]
		got := waitExecTask(t, ctx, session, id)
		if got.Status != "completed" || got.Result == nil {
			t.Fatalf("remote task result = %#v", got)
		}
		text := requireSingleText(t, "tasks/get", got.Result)
		wantText := fmt.Sprintf("Status: finished · exit code 0\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=yes stderr=no · lost: stdout=no stderr=no · job %s", id)
		if text != wantText {
			t.Fatalf("completed result = %q, want %q", text, wantText)
		}
		stdout, stderr := parseResumeOffsets(t, text)
		read := callReadTool(t, ctx, session, "remote_read", id, stdout, stderr)
		if !strings.Contains(read, "local output") {
			t.Fatalf("remote_read output = %q", read)
		}
	})

	t.Run("app_exec completes through the application manager", func(t *testing.T) {
		started, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "app_exec", Arguments: map[string]any{"application": "demo", "arguments": []string{"inspect"}}})
		if err != nil || started == nil || started.IsError || len(started.Content) != 0 {
			t.Fatalf("app_exec did not return a task handle: %#v (%v)", started, err)
		}
		ids := keeper.appJobIDs()
		if len(ids) != 1 {
			t.Fatalf("app manager started ids %v", ids)
		}
		got := waitExecTask(t, ctx, session, ids[0])
		if got.Status != "completed" || got.Result == nil {
			t.Fatalf("app task = %#v", got)
		}
		text := requireSingleText(t, "tasks/get", got.Result)
		wantText := fmt.Sprintf("Status: finished · exit code 0\nResume: stdout_offset=0 stderr_offset=0 · more: stdout=yes stderr=no · lost: stdout=no stderr=no · job %s", ids[0])
		if text != wantText {
			t.Fatalf("completed result = %q, want %q", text, wantText)
		}
		stdout, stderr := parseResumeOffsets(t, text)
		if stdout != 0 || stderr != 0 {
			t.Fatalf("resume offsets = %d,%d", stdout, stderr)
		}
		read := callReadTool(t, ctx, session, "app_read", ids[0], stdout, stderr)
		if !strings.Contains(read, "application output") {
			t.Fatalf("app_read output = %q", read)
		}
	})

	t.Run("remote_exec nonzero exit completes", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "nonzero"}})
		if err != nil {
			t.Fatal(err)
		}
		ids := keeper.commandIDs(t)
		got := waitExecTask(t, ctx, session, ids[len(ids)-1])
		if got.Status != "completed" || !strings.Contains(requireSingleText(t, "tasks/get", got.Result), "exit code 7") {
			t.Fatalf("nonzero outcome = %#v", got)
		}
	})
	t.Run("invalid UTF-8 output keeps raw byte offsets", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "binary"}})
		if err != nil {
			t.Fatal(err)
		}
		ids := keeper.commandIDs(t)
		id := ids[len(ids)-1]
		// The first 4096 bytes are evicted, so the first retained chunk starts at 4096 (guard.go:138-145;
		// docs/MCP-TASKS-EXEC.md:234-238). Its two invalid bytes render 4 bytes longer than raw, so a
		// rendered-length derivation would resume at 4092 instead.
		const resume = int64(4096)
		got := waitExecTask(t, ctx, session, id)
		text := requireSingleText(t, "tasks/get", got.Result)
		if !strings.Contains(text, fmt.Sprintf("Resume: stdout_offset=%d stderr_offset=0 · more: stdout=yes stderr=no · lost: stdout=yes stderr=no · job %s", resume, id)) {
			t.Fatalf("binary Resume line = %q", text)
		}
		stdout, stderr := parseResumeOffsets(t, text)
		if stdout != resume {
			t.Fatalf("Resume stdout offset=%d want %d", stdout, resume)
		}
		read := callReadTool(t, ctx, session, "remote_read", id, stdout, stderr)
		continuation := append(bytes.Repeat([]byte("x"), 16), []byte{0xff, 'b', 0xfe}...)
		continuation = append(continuation, bytes.Repeat([]byte("y"), execChunkLimit-19)...)
		encoded := base64.StdEncoding.EncodeToString(continuation)
		if !strings.Contains(read, fmt.Sprintf("stdout base64 (bytes %d-%d): %s", resume, resume+execChunkLimit, encoded)) {
			t.Fatalf("binary continuation missing: %q", read)
		}
	})

	t.Run("manager eviction freezes the fixed machinery failure", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "emit"}})
		if err != nil {
			t.Fatal(err)
		}
		ids := keeper.commandIDs(t)
		oldest := ids[len(ids)-1]
		for range execMaxJobs {
			data, encodeErr := wire.Encode(remote.StartInput{Target: "local", Command: "untracked overflow", TimeoutSeconds: 5})
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			reply := keeper.command.Handle(ctx, wire.Request{Operation: "start", Data: data})
			if !reply.OK {
				t.Fatalf("untracked manager start failed: %s", reply.Error)
			}
			var started remote.StartOutput
			if err := wire.Decode(reply.Data, &started); err != nil {
				t.Fatal(err)
			}
			cancelData, err := wire.Encode(remote.JobInput{JobID: started.JobID})
			if err != nil {
				t.Fatal(err)
			}
			if cancelReply := keeper.command.Handle(ctx, wire.Request{Operation: "cancel", Data: cancelData}); !cancelReply.OK {
				t.Fatalf("cancel filler job: %s", cancelReply.Error)
			}
			var final remote.ReadOutput
			done, desc, waitErr := flakediag.WaitForDesc(t, "filler manager job to end", 5*time.Second, func() (string, bool, error) {
				readData, _ := wire.Encode(remote.ReadInput{JobID: started.JobID})
				readReply := keeper.command.Handle(ctx, wire.Request{Operation: "read", Data: readData})
				if !readReply.OK {
					return "read failed", false, errors.New(readReply.Error)
				}
				if err := wire.Decode(readReply.Data, &final); err != nil {
					return "invalid read", false, err
				}
				return fmt.Sprintf("done=%v", final.Done), final.Done, nil
			})
			if !done {
				t.Fatalf("filler did not terminate: %s (%v)", desc, waitErr)
			}
		}
		got, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: oldest})
		if err != nil || got == nil || got.Status != "failed" || got.Error == nil || got.Error.Code != -32603 || got.Error.Message != "the task could not be read" {
			t.Fatalf("evicted task=%#v err=%v", got, err)
		}
		again, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: oldest})
		if err != nil || again == nil || again.Status != got.Status || again.Error == nil || again.Error.Code != got.Error.Code || again.Error.Message != got.Error.Message {
			t.Fatalf("eviction failure did not replay: first=%#v again=%#v err=%v", got, again, err)
		}
	})

	t.Run("remote_exec runner error completes", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "fail"}})
		if err != nil {
			t.Fatal(err)
		}
		ids := keeper.commandIDs(t)
		got := waitExecTask(t, ctx, session, ids[len(ids)-1])
		// closeGuarded normalizes non-context runner errors to ErrJob: internal/remote/internal/jobs/guard.go:49-60.
		if got.Status != "completed" || got.Result == nil || !strings.Contains(requireSingleText(t, "tasks/get", got.Result), "Error: remote operation failed") {
			t.Fatalf("runner error outcome = %#v", got)
		}
	})

	t.Run("remote_exec timeout completes with an error line", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "timeout", "timeout_seconds": 1}})
		if err != nil {
			t.Fatal(err)
		}
		ids := keeper.commandIDs(t)
		got := waitExecTask(t, ctx, session, ids[len(ids)-1])
		text := requireSingleText(t, "tasks/get", got.Result)
		if got.Status != "completed" || !strings.Contains(text, "Error: context deadline exceeded") {
			t.Fatalf("timeout outcome = %#v, text=%q", got, text)
		}
	})

	t.Run("tasks_cancel preserves retained output", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "block"}})
		if err != nil {
			t.Fatal(err)
		}
		waitRunner(t, runnerStarted)
		ids := keeper.commandIDs(t)
		id := ids[len(ids)-1]
		_, err = mcp.CallCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](ctx, session, "tasks/cancel", &taskCancelParams{TaskID: id})
		if err != nil {
			t.Fatal(err)
		}
		got := waitExecTask(t, ctx, session, id)
		if got.Status != "cancelled" || got.StatusMessage != "Cancelled job "+id || got.Result != nil {
			t.Fatalf("cancel result = %#v", got)
		}
		text := callReadTool(t, ctx, session, "remote_read", id, 0, 0)
		if !strings.Contains(text, "before cancel") {
			t.Fatalf("retained cancellation output missing: %q", text)
		}
	})

	t.Run("late runner success after cancellation remains completed", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "late"}})
		if err != nil {
			t.Fatal(err)
		}
		waitRunner(t, runnerStarted)
		ids := keeper.commandIDs(t)
		id := ids[len(ids)-1]
		_, err = mcp.CallCustomMethod[*taskCancelParams, *taskAck, taskCancelParams](ctx, session, "tasks/cancel", &taskCancelParams{TaskID: id})
		if err != nil {
			t.Fatal(err)
		}
		cancelObservedDone, desc, waitErr := flakediag.WaitForDesc(t, "late runner observed cancellation", 5*time.Second, func() (string, bool, error) {
			select {
			case <-cancelObserved:
				return "runner observed cancel", true, nil
			default:
				return "runner still waiting", false, nil
			}
		})
		if !cancelObservedDone {
			t.Fatalf("runner did not observe cancel: %s (%v)", desc, waitErr)
		}
		releaseLate.Do(func() { close(lateFinish) })
		got := waitExecTask(t, ctx, session, id)
		if got.Status != "completed" || !strings.Contains(requireSingleText(t, "tasks/get", got.Result), "exit code 0") {
			t.Fatalf("late success was lost: %#v", got)
		}
	})
	t.Run("keeper session close freezes unfrozen and replays frozen", func(t *testing.T) {
		_, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "slow"}})
		if err != nil {
			t.Fatal(err)
		}
		waitRunner(t, runnerStarted)
		ids := keeper.commandIDs(t)
		slowID := ids[len(ids)-1]

		_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "remote_exec", Arguments: map[string]any{"target": "local", "command": "emit"}})
		if err != nil {
			t.Fatal(err)
		}
		ids = keeper.commandIDs(t)
		emitID := ids[len(ids)-1]
		emitTask := waitExecTask(t, ctx, session, emitID)
		if emitTask.Status != "completed" || emitTask.Result == nil {
			t.Fatalf("emit task before close = %#v", emitTask)
		}
		before := requireSingleText(t, "tasks/get", emitTask.Result)

		closeServer()
		closed, desc, closeErr := flakediag.WaitForDesc(t, "broker keeper session closure", 5*time.Second, func() (string, bool, error) {
			select {
			case <-server.Done():
				return "broker session closed", true, nil
			default:
				return "broker session still open", false, nil
			}
		})
		if !closed {
			t.Fatalf("keeper session did not close: %s (%v)", desc, closeErr)
		}
		slow, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: slowID})
		if err != nil || slow == nil || slow.Status != "failed" || slow.Error == nil || slow.Error.Code != -32603 || slow.Error.Message != "the task could not be read" {
			t.Fatalf("closed-session task=%#v err=%v", slow, err)
		}
		again, err := mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: emitID})
		if err != nil || again == nil || again.Status != "completed" || requireSingleText(t, "tasks/get", again.Result) != before {
			t.Fatalf("frozen task changed after manager close: %#v (%v)", again, err)
		}
	})
	for _, frame := range logbook.since(0) {
		if bytes.Contains(frame, []byte("CANARY-EXEC-STDERR-9f3a")) {
			t.Fatal("runner stderr canary appeared in a task frame")
		}
	}
}

func waitRunner(t *testing.T, started <-chan string) string {
	t.Helper()
	var command string
	done, desc, err := flakediag.WaitForDesc(t, "local runner start", 5*time.Second, func() (string, bool, error) {
		select {
		case command = <-started:
			return "runner started", true, nil
		default:
			return "runner not started", false, nil
		}
	})
	if !done {
		t.Fatalf("runner did not start: %s (%v)", desc, err)
	}
	return command
}

func parseResumeOffsets(t *testing.T, text string) (int64, int64) {
	t.Helper()
	var stdout, stderr int64
	line := ""
	for _, candidate := range strings.Split(text, "\n") {
		if strings.HasPrefix(candidate, "Resume: ") {
			line = strings.TrimPrefix(candidate, "Resume: ")
			break
		}
	}
	if line == "" {
		t.Fatalf("missing Resume line: %q", text)
	}
	if _, err := fmt.Sscanf(line, "stdout_offset=%d stderr_offset=%d", &stdout, &stderr); err != nil {
		t.Fatalf("invalid Resume offsets %q: %v", line, err)
	}
	return stdout, stderr
}

func callReadTool(t *testing.T, ctx context.Context, session *mcp.ClientSession, name, id string, stdout, stderr int64) string {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"job_id": id, "stdout_offset": stdout, "stderr_offset": stderr}})
	if err != nil || result == nil || result.IsError {
		t.Fatalf("%s failed: %#v (%v)", name, result, err)
	}
	return requireSingleText(t, name, result)
}

func waitExecTask(t *testing.T, ctx context.Context, session *mcp.ClientSession, id string) *taskGetResult {
	t.Helper()
	var result *taskGetResult
	done, desc, err := flakediag.WaitForDesc(t, "exec task to complete", 20*time.Second, func() (string, bool, error) {
		var callErr error
		result, callErr = mcp.CallCustomMethod[*taskGetParams, *taskGetResult, taskGetParams](ctx, session, "tasks/get", &taskGetParams{TaskID: id})
		if callErr != nil {
			return "tasks/get failed", false, callErr
		}
		if result == nil {
			return "no task result", false, nil
		}
		return "status=" + result.Status, result.Status == "completed" || result.Status == "failed" || result.Status == "cancelled", nil
	})
	if !done {
		t.Fatalf("task did not complete: %s (%v)", desc, err)
	}
	return result
}

func (k *execKeeper) commandIDs(t *testing.T) []string {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.ids...)
}

func (k *execKeeper) appJobIDs() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.appIDs...)
}
