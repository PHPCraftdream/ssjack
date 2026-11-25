package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	confirm "github.com/PHPCraftdream/ssjack/internal/bridge/internal/confirm"
	tasks "github.com/PHPCraftdream/ssjack/internal/bridge/internal/tasks"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

// ReadOutput is the output of one read as ParseResult recovers it from the
// result text: the text of each stream as shown (invalid UTF-8 replaced), the
// original bytes in base64 when they were not valid UTF-8, and the control
// fields.
type ReadOutput struct {
	JobID        string `json:"job_id"`
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	StdoutBase64 string `json:"stdout_base64,omitempty"`
	StderrBase64 string `json:"stderr_base64,omitempty"`
	StdoutOffset int64  `json:"stdout_offset"`
	StderrOffset int64  `json:"stderr_offset"`
	StdoutLost   bool   `json:"stdout_lost"`
	StderrLost   bool   `json:"stderr_lost"`
	StdoutMore   bool   `json:"stdout_more"`
	StderrMore   bool   `json:"stderr_more"`
	Done         bool   `json:"done"`
	ExitCode     int    `json:"exit_code"`
	Error        string `json:"error,omitempty"`
}

// callPolling sends one polling request. With no wait it is the plain bounded
// call; a positive wait (already validated and clamped to 25 seconds) uses the
// waiting call, whose IPC deadline covers the whole wait and which leaves the
// keeper session open when the request context ends first.
func callPolling(ctx context.Context, client *broker.Client, operation string, wait int, input, output any) error {
	if wait > 0 {
		return client.CallWait(ctx, operation, input, output)
	}
	return client.Call(ctx, operation, input, output)
}

func NewDeclarativeServer() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
}

func NewServer(client *broker.Client) *mcp.Server {
	return NewFullServer(client)
}

func NewRegistryForDescriptor(client *broker.Client, descriptor broker.Descriptor) (*mcp.Server, error) {
	return NewRegistryForDescriptorWithConfirm(client, descriptor, nil)
}

// NewRegistryForDescriptorWithConfirm validates a keeper descriptor and builds
// the corresponding server with an optional elicitation manager.
func NewRegistryForDescriptorWithConfirm(client *broker.Client, descriptor broker.Descriptor, confirmMgr *confirm.Manager) (*mcp.Server, error) {
	if err := broker.ValidateDescriptor(descriptor); err != nil {
		return nil, err
	}
	if descriptor.Mode == broker.ModeDeclarative && (descriptor.Protocol == broker.SyntheticProtocol || descriptor.Protocol == broker.DeliveryProtocol) {
		server := mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
		planDescription := "Plan a fixed synthetic cache metadata update; no secrets or command execution. Returns plain text: 'Plan <plan_id> created', Digest and Expires, Precondition, the effects one per line, and the plan_apply step."
		applyDescription := "Apply a previously issued synthetic metadata plan. Returns plain text: 'Operation <operation_id>: <state>'."
		if descriptor.Protocol == broker.DeliveryProtocol {
			planDescription = "Plan a fixed-scope confidential delivery and report only delivery receipt status; no secret values are returned. Returns plain text: 'Plan <plan_id> created', Digest and Expires, Precondition, the effects one per line, and the plan_apply step."
			applyDescription = "Deliver the authorized confidential value to its fixed protected consumer; reports RECEIVED, WITHHELD, or UNKNOWN and does not claim metadata adoption. Returns plain text: 'Operation <operation_id>: <state>' and a 'Delivery: <status>' line."
		}
		addTextTool(server, &mcp.Tool{Name: "resource_plan", Description: planDescription}, func(ctx context.Context, input declarativeslice.PlanInput) (string, error) {
			if client == nil {
				return "", errors.New("keeper unavailable")
			}
			var out declarativeslice.PlanResult
			if err := client.Call(ctx, "resource_plan", input, &out); err != nil {
				return "", err
			}
			return renderPlan(out), nil
		})
		addTextTool(server, &mcp.Tool{Name: "plan_apply", Description: applyDescription}, func(ctx context.Context, input declarativeslice.ApplyInput) (string, error) {
			if client == nil {
				return "", errors.New("keeper unavailable")
			}
			var out declarativeslice.ApplyResult
			if err := client.Call(ctx, "plan_apply", input, &out); err != nil {
				return "", err
			}
			return renderApply(out), nil
		})
		return server, nil
	}
	if descriptor.Mode == broker.ModeDeclarative {
		return NewDeclarativeServer(), nil
	}
	return NewFullServerWithClockAndConfirm(client, nil, confirmMgr), nil
}

// brokerClassifyDeadline bounds the pre-acceptance classification keeper call;
// the gate holds no keeper connection while the human decides.
const brokerClassifyDeadline = 3 * time.Second

// brokerClassifier asks the keeper's side-effect-free app_classify operation.
// Any failure means "not eligible": app_exec then keeps today's flow.
type brokerClassifier struct{ client *broker.Client }

func (c brokerClassifier) IsNonObservational(tool string, canonicalArgs []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), brokerClassifyDeadline)
	defer cancel()
	var out application.ClassifyOutput
	// The detached call can neither wedge behind a long keeper call past its deadline nor close the connection the accepted retry uses.
	if err := c.client.CallDetached(ctx, "app_classify", json.RawMessage(canonicalArgs), &out); err != nil {
		return false, err
	}
	return out.NonObservational, nil
}

// NewConfirmManager builds the elicitation manager wired to the keeper's
// classification operation. now and random are test seams (nil is real).
func NewConfirmManager(client *broker.Client, now func() time.Time, random io.Reader) *confirm.Manager {
	mgr := confirm.NewManager(now, random)
	mgr.SetClassify(brokerClassifier{client: client})
	return mgr
}

// readTool serves one polling read of a command or application job.
func readTool(client *broker.Client, operation string) func(context.Context, remote.ReadInput) (string, error) {
	return func(ctx context.Context, input remote.ReadInput) (string, error) {
		wait, err := jobwait.Clamp(input.WaitSeconds)
		if err != nil {
			return "", err
		}
		input.WaitSeconds = wait
		var raw remote.ReadOutput
		if err := callPolling(ctx, client, operation, wait, input, &raw); err != nil {
			return "", err
		}
		return renderRead(raw), nil
	}
}

// startTool serves the start of a command or application job.
func startTool[In any](client *broker.Client, operation, reader string) func(context.Context, In) (string, error) {
	return func(ctx context.Context, input In) (string, error) {
		var out remote.StartOutput
		if err := client.Call(ctx, operation, input, &out); err != nil {
			return "", err
		}
		return renderExecStarted(out.JobID, reader), nil
	}
}

// cancelTool serves the cancel of a command or application job.
func cancelTool(client *broker.Client, operation string) func(context.Context, remote.JobInput) (string, error) {
	return func(ctx context.Context, input remote.JobInput) (string, error) {
		var out remote.CancelOutput
		if err := client.Call(ctx, operation, input, &out); err != nil {
			return "", err
		}
		return renderCancelled(input.JobID, out.Cancelled), nil
	}
}

// transferStart starts one transfer job and returns its job id.
func transferStart(ctx context.Context, client *broker.Client, operation string, input transfer.StartInput) (string, error) {
	var out transfer.StartOutput
	if err := client.Call(ctx, operation, input, &out); err != nil {
		return "", err
	}
	tasks.CapturedStart(ctx, out.JobID)
	return out.JobID, nil
}

// transferTool serves the start of an upload or a download.
func transferTool(client *broker.Client, operation string) func(context.Context, transfer.StartInput) (string, error) {
	return func(ctx context.Context, input transfer.StartInput) (string, error) {
		jobID, err := transferStart(ctx, client, operation, input)
		if err != nil {
			return "", err
		}
		return renderTransferStarted(jobID), nil
	}
}

// NewFullServer is the full registry of the remote, application and transfer
// tools, with the MCP tasks extension for the two transfer tools.
func NewFullServer(client *broker.Client) *mcp.Server {
	return NewFullServerWithClock(client, nil)
}

// NewFullServerWithClock is NewFullServer with the task retention clock
// replaced (nil is the real clock), for the in-process acceptance tests.
func NewFullServerWithClock(client *broker.Client, now func() time.Time) *mcp.Server {
	return NewFullServerWithClockAndConfirm(client, now, nil)
}

// NewFullServerWithClockAndConfirm is NewFullServerWithClock with the
// elicitation confirmation manager installed. A nil manager, and a disabled
// one, changes nothing: no middleware is added and no handler of this server
// returns input requests, so the SDK's legacy auto-elicitation cannot fire.
func NewFullServerWithClockAndConfirm(client *broker.Client, now func() time.Time, confirmMgr *confirm.Manager) *mcp.Server {
	capabilities := &mcp.ServerCapabilities{Logging: &mcp.LoggingCapabilities{}}
	capabilities.AddExtension(tasks.Extension, map[string]any{})
	server := mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, &mcp.ServerOptions{Capabilities: capabilities})
	if err := tasks.NewManager(transferTaskTools{client: client}, now).Install(server); err != nil {
		// The three task method names are fixed and none of them shadows a
		// standard method, so registering them cannot fail.
		panic(err)
	}
	if confirmMgr != nil && confirmMgr.Enabled() {
		// After the tasks install, so the gate wraps outside both the tasks
		// interception and the SDK multi-round-trip middleware.
		server.AddReceivingMiddleware(confirmMgr.Middleware)
	}

	addTextTool(server, &mcp.Tool{Name: "remote_targets", Description: "List approved SSH targets without exposing addresses or keys. Returns plain text: a count line, then one '- name' line per target."},
		func(ctx context.Context, _ struct{}) (string, error) {
			var out remote.TargetsOutput
			if err := client.Call(ctx, "targets", struct{}{}, &out); err != nil {
				return "", err
			}
			return renderTargets(out.Targets), nil
		})
	addTextTool(server, &mcp.Tool{Name: "remote_exec", Description: "Start a noninteractive shell command on an approved target. Returns plain text 'Started job <job_id>' and the next step; read output through remote_read (wait_seconds 20 avoids repeated polling). The command has the configured SSH user privileges."},
		startTool[remote.StartInput](client, "start", "remote_read"))
	addTextTool(server, &mcp.Tool{Name: "remote_read", Description: "Read stdout/stderr chunks using returned offsets. Returns plain text: 'Job <id>: running' or 'Job <id>: done (exit code N)'; then each non-empty stream verbatim as 'stdout (bytes A-B):', the raw text and an end marker line '[end of stdout]' (numbered, and named in the label, when the text contains it); a 'stdout base64 (bytes A-B): ...' line carries the original bytes when they are not valid UTF-8 and the block shows them replaced; last 'Next: stdout_offset=N stderr_offset=N · more: stdout=yes|no stderr=yes|no · lost: stdout=yes|no stderr=yes|no'. Pass the Next offsets to the following call; done in the first line indicates command completion; drain remaining output while more is yes; lost yes indicates buffer overflow. Offsets count original bytes. The fields are stable and listed in docs/REMOTE-MCP.md. Optional wait_seconds (integer 0 to 25, default 0; larger counts as 25) blocks while the command runs and no output beyond the given offsets exists, until new output arrives, the command completes or the wait expires, then returns the normal chunk; prefer one call with wait_seconds 20 over repeated immediate reads."},
		readTool(client, "read"))
	addTextTool(server, &mcp.Tool{Name: "remote_cancel", Description: "Cancel an operation and close its SSH connection. Detached remote processes may continue running. Returns plain text: 'Cancelled job <id>', or 'Job <id> had already finished'."},
		cancelTool(client, "cancel"))
	addTextTool(server, &mcp.Tool{Name: "app_list", Description: "List the applications the owner registered at keeper startup with --app, if any. Returns plain text: a count line, then one '- name (profile P)' line per application; an empty list says so and gives a hint."},
		func(ctx context.Context, _ struct{}) (string, error) {
			var out application.ListOutput
			if err := client.Call(ctx, "app_list", struct{}{}, &out); err != nil {
				return "", err
			}
			return renderApps(out), nil
		})
	addTextTool(server, &mcp.Tool{Name: "app_exec", Description: "Start a finite command in a registered application, named as in app_list. Arguments are passed as argv, never through a local shell. Commands the application did not declare observational require confirm=true and applicable harness authorization; the application may refuse commands. Interactive stdin is never available. Returns plain text 'Started job <job_id>' and the next step: read it with app_read."},
		startTool[application.Input](client, "app_start", "app_read"))
	addTextTool(server, &mcp.Tool{Name: "app_read", Description: "Read the registered application operation output using returned offsets; drain both streams until done and no more output remains. Returns the same plain text as remote_read: 'Job <id>: running' or 'Job <id>: done (exit code N)', each non-empty stream verbatim between a 'stdout (bytes A-B):' label and an '[end of stdout]' marker line, a base64 line for bytes that are not valid UTF-8, and 'Next: stdout_offset=N stderr_offset=N · more: ... · lost: ...'; the format is documented in docs/REMOTE-MCP.md. Optional wait_seconds (integer 0 to 25, default 0; larger counts as 25) blocks while the operation runs and no output beyond the given offsets exists, until new output arrives, the operation completes or the wait expires, then returns the normal chunk; prefer one call with wait_seconds 20 over repeated immediate reads."},
		readTool(client, "app_read"))
	addTextTool(server, &mcp.Tool{Name: "app_cancel", Description: "Cancel a registered application operation and revoke its child transport. A detached remote process may continue running. Returns plain text: 'Cancelled job <id>', or 'Job <id> had already finished'."},
		cancelTool(client, "app_cancel"))
	addTextTool(server, &mcp.Tool{Name: "remote_upload", Description: "Copy a file from an owner-registered local transfer root to an absolute POSIX path on an approved target, as a background job. Copy only: the source is never modified. No file content, absolute local path or remote stderr is ever returned. local is relative to the registered root (omit root when exactly one is registered); target must be one of the remote_targets. The remote path is written with the profile's SSH principal. overwrite=true requires confirm=true. Returns plain text 'Started job <job_id>'; follow it with transfer_status (wait_seconds 20 avoids repeated polling) and cancel with transfer_cancel. A single file whose link is slow or drops continues automatically in chunks and is published only after a whole-file SHA-256 check. If the job ends with error_class link_unstable, call remote_upload again with the same arguments to resume from the parts already staged next to the remote destination, also after a keeper restart; transfer_cancel removes those parts instead. While chunking, the remote disk needs about twice the file size. Directories are never chunked. A client that declares the MCP tasks extension (io.modelcontextprotocol/tasks) receives a task with this job id instead and follows it with tasks/get."},
		transferTool(client, "transfer_upload"))
	addTextTool(server, &mcp.Tool{Name: "remote_download", Description: "Copy a file from an approved target into an owner-registered local transfer root, as a background job. Copy only: the source is never modified. No file content, absolute local path or remote stderr is ever returned. local is the root-relative destination (omit root when exactly one is registered); target must be one of the remote_targets. The remote read uses the profile's SSH principal. overwrite=true requires confirm=true. Returns plain text 'Started job <job_id>'; follow it with transfer_status (wait_seconds 20 avoids repeated polling) and cancel with transfer_cancel. A single file whose link is slow or drops continues automatically in chunks and is published only after a whole-file SHA-256 check. If the job ends with error_class link_unstable, call remote_download again with the same arguments to resume from the parts already staged beside the local destination, also after a keeper restart; transfer_cancel removes those parts instead. While chunking, the local disk needs about twice the file size. Directories are never chunked. A client that declares the MCP tasks extension (io.modelcontextprotocol/tasks) receives a task with this job id instead and follows it with tasks/get."},
		transferTool(client, "transfer_download"))
	addTextTool(server, &mcp.Tool{Name: "transfer_status", Description: "Report a bounded, content-free transfer status as plain text: 'Transfer <job_id>: <direction> <kind>, <state>' (state running, done, failed or cancelled), then 'Key: value' lines: Phase, Mode (stream or chunked), Chunks done/total, Chunk size, Attempts, Bytes (never decreases), Files, Dirs, Speed, SHA-256 or Manifest SHA-256 when available and, on failure, 'Failed: <error_class> — <message>' with a fixed message (error_class is refused_path, exists, limit, unsupported_remote, integrity, remote_failed, link_unstable, cancelled or internal). Chunk fields appear only for a single file and only while present; a running chunked job shows live part progress, a directory never carries them; a failed chunked job keeps its verified bytes and counts. link_unstable means the link was too unstable to finish: the staged parts are kept and the same upload or download call resumes. Never contains file content or local paths. The fields are stable and listed in docs/FILE-TRANSFER.md. Optional wait_seconds (integer 0 to 25, default 0; larger counts as 25) blocks while the job is running until it is done, failed or cancelled, or the wait expires, then returns the status; prefer one call with wait_seconds 20 over repeated immediate polling."},
		func(ctx context.Context, input transfer.StatusInput) (string, error) {
			wait, err := jobwait.Clamp(input.WaitSeconds)
			if err != nil {
				return "", err
			}
			input.WaitSeconds = wait
			var out transfer.StatusOutput
			if err := callPolling(ctx, client, "transfer_status", wait, input, &out); err != nil {
				return "", err
			}
			return renderTransferStatus(out), nil
		})
	addTextTool(server, &mcp.Tool{Name: "transfer_cancel", Description: "Cancel a running transfer job and close its SSH session. A chunked file transfer's partial parts are removed, so a cancel gives up resuming; a link failure keeps them. Returns plain text: 'Cancelled job <id>', or 'Job <id> had already finished' for a job that was no longer running."},
		func(ctx context.Context, input transfer.CancelInput) (string, error) {
			var out transfer.CancelOutput
			if err := client.Call(ctx, "transfer_cancel", input, &out); err != nil {
				return "", err
			}
			return renderTransferCancelled(input.JobID, out.Cancelled), nil
		})
	return server
}

// transferTaskTools is the tasks package's view of the transfer tools: their
// keeper operations and the texts and refusal result they already produce.
type transferTaskTools struct{ client *broker.Client }

func (t transferTaskTools) Status(ctx context.Context, input transfer.StatusInput) (transfer.StatusOutput, error) {
	var out transfer.StatusOutput
	input.WaitSeconds = 0
	err := t.client.Call(ctx, "transfer_status", input, &out)
	return out, err
}

func (t transferTaskTools) Cancel(ctx context.Context, input transfer.CancelInput) (transfer.CancelOutput, error) {
	var out transfer.CancelOutput
	err := t.client.Call(ctx, "transfer_cancel", input, &out)
	return out, err
}

func (transferTaskTools) StatusText(out transfer.StatusOutput) string {
	return renderTransferStatus(out)
}
func (transferTaskTools) StatusLine(out transfer.StatusOutput) string { return transferStatusLine(out) }
func (transferTaskTools) CancelledText(jobID string) string {
	return renderTransferCancelled(jobID, true)
}
