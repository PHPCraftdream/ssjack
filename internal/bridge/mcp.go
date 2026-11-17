package bridge

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

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

func readOutput(raw remote.ReadOutput) ReadOutput {
	out := ReadOutput{
		JobID: raw.JobID, Stdout: strings.ToValidUTF8(string(raw.Stdout), "�"), Stderr: strings.ToValidUTF8(string(raw.Stderr), "�"),
		StdoutOffset: raw.StdoutOffset, StderrOffset: raw.StderrOffset,
		StdoutLost: raw.StdoutLost, StderrLost: raw.StderrLost,
		StdoutMore: raw.StdoutMore, StderrMore: raw.StderrMore,
		Done: raw.Done, ExitCode: raw.ExitCode, Error: raw.Error,
	}
	if !utf8.Valid(raw.Stdout) {
		out.StdoutBase64 = base64.StdEncoding.EncodeToString(raw.Stdout)
	}
	if !utf8.Valid(raw.Stderr) {
		out.StderrBase64 = base64.StdEncoding.EncodeToString(raw.Stderr)
	}
	return out
}

func NewDeclarativeServer() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
}

func NewServer(client *broker.Client) *mcp.Server {
	return NewFullServer(client)
}

func NewRegistryForDescriptor(client *broker.Client, descriptor broker.Descriptor) (*mcp.Server, error) {
	if err := broker.ValidateDescriptor(descriptor); err != nil {
		return nil, err
	}
	if descriptor.Mode == broker.ModeDeclarative && (descriptor.Protocol == broker.SyntheticProtocol || descriptor.Protocol == broker.DeliveryProtocol) {
		server := mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
		planDescription := "Plan a fixed synthetic cache metadata update; no secrets or command execution."
		applyDescription := "Apply a previously issued synthetic metadata plan."
		if descriptor.Protocol == broker.DeliveryProtocol {
			planDescription = "Plan a fixed-scope confidential delivery and report only delivery receipt status; no secret values are returned."
			applyDescription = "Deliver the authorized confidential value to its fixed protected consumer; reports RECEIVED, WITHHELD, or UNKNOWN and does not claim metadata adoption."
		}
		mcp.AddTool(server, &mcp.Tool{Name: "resource_plan", Description: planDescription}, func(ctx context.Context, _ *mcp.CallToolRequest, input declarativeslice.PlanInput) (*mcp.CallToolResult, declarativeslice.PlanResult, error) {
			var out declarativeslice.PlanResult
			if client == nil {
				return nil, out, errors.New("keeper unavailable")
			}
			err := client.Call(ctx, "resource_plan", input, &out)
			return nil, out, err
		})
		mcp.AddTool(server, &mcp.Tool{Name: "plan_apply", Description: applyDescription}, func(ctx context.Context, _ *mcp.CallToolRequest, input declarativeslice.ApplyInput) (*mcp.CallToolResult, declarativeslice.ApplyResult, error) {
			var out declarativeslice.ApplyResult
			if client == nil {
				return nil, out, errors.New("keeper unavailable")
			}
			err := client.Call(ctx, "plan_apply", input, &out)
			return nil, out, err
		})
		return server, nil
	}
	if descriptor.Mode == broker.ModeDeclarative {
		return NewDeclarativeServer(), nil
	}
	return NewFullServer(client), nil
}

func NewFullServer(client *broker.Client) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "remote_targets", Description: "List approved SSH targets without exposing addresses or keys."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, remote.TargetsOutput, error) {
			var out remote.TargetsOutput
			err := client.Call(ctx, "targets", struct{}{}, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "remote_exec", Description: "Start a noninteractive shell command on an approved target. Returns job_id; read output through remote_read. The command has the configured SSH user privileges."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.StartInput) (*mcp.CallToolResult, remote.StartOutput, error) {
			var out remote.StartOutput
			err := client.Call(ctx, "start", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "remote_read", Description: "Read stdout/stderr chunks using returned offsets. done indicates command completion; drain remaining output while *_more is true. *_lost indicates buffer overflow. Invalid UTF-8 is replaced and the original chunk is also returned in *_base64. Offsets count original bytes."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
			var raw remote.ReadOutput
			err := client.Call(ctx, "read", input, &raw)
			return nil, readOutput(raw), err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "remote_cancel", Description: "Cancel an operation and close its SSH connection. Detached remote processes may continue running."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.JobInput) (*mcp.CallToolResult, remote.CancelOutput, error) {
			var out remote.CancelOutput
			err := client.Call(ctx, "cancel", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_list", Description: "List the applications the owner registered at keeper startup with --app, if any."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, application.ListOutput, error) {
			var out application.ListOutput
			err := client.Call(ctx, "app_list", struct{}{}, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_exec", Description: "Start a finite command in a registered application, named as in app_list. Arguments are passed as argv, never through a local shell. Commands the application did not declare observational require confirm=true and applicable harness authorization; the application may refuse commands. Interactive stdin is never available. Returns job_id."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input application.Input) (*mcp.CallToolResult, remote.StartOutput, error) {
			var out remote.StartOutput
			err := client.Call(ctx, "app_start", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_read", Description: "Read the registered application operation output using returned offsets; drain both streams until done and no more output remains."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
			var raw remote.ReadOutput
			err := client.Call(ctx, "app_read", input, &raw)
			return nil, readOutput(raw), err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_cancel", Description: "Cancel a registered application operation and revoke its child transport. A detached remote process may continue running."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.JobInput) (*mcp.CallToolResult, remote.CancelOutput, error) {
			var out remote.CancelOutput
			err := client.Call(ctx, "app_cancel", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "remote_upload", Description: "Copy a file from an owner-registered local transfer root to an absolute POSIX path on an approved target, as a background job. Copy only: the source is never modified. No file content, absolute local path or remote stderr is ever returned. local is relative to the registered root (omit root when exactly one is registered); target must be one of the remote_targets. The remote path is written with the profile's SSH principal. overwrite=true requires confirm=true. Returns job_id; poll transfer_status and cancel with transfer_cancel. A single file whose link is slow or drops continues automatically in chunks and is published only after a whole-file SHA-256 check. If the job ends with error_class link_unstable, call remote_upload again with the same arguments to resume from the parts already staged next to the remote destination, also after a keeper restart; transfer_cancel removes those parts instead. While chunking, the remote disk needs about twice the file size. Directories are never chunked."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input transfer.StartInput) (*mcp.CallToolResult, transfer.StartOutput, error) {
			var out transfer.StartOutput
			err := client.Call(ctx, "transfer_upload", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "remote_download", Description: "Copy a file from an approved target into an owner-registered local transfer root, as a background job. Copy only: the source is never modified. No file content, absolute local path or remote stderr is ever returned. local is the root-relative destination (omit root when exactly one is registered); target must be one of the remote_targets. The remote read uses the profile's SSH principal. overwrite=true requires confirm=true. Returns job_id; poll transfer_status and cancel with transfer_cancel. A single file whose link is slow or drops continues automatically in chunks and is published only after a whole-file SHA-256 check. If the job ends with error_class link_unstable, call remote_download again with the same arguments to resume from the parts already staged beside the local destination, also after a keeper restart; transfer_cancel removes those parts instead. While chunking, the local disk needs about twice the file size. Directories are never chunked."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input transfer.StartInput) (*mcp.CallToolResult, transfer.StartOutput, error) {
			var out transfer.StartOutput
			err := client.Call(ctx, "transfer_download", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "transfer_status", Description: "Report a bounded, content-free transfer status: state (running, done, failed, cancelled), phase, direction, kind, file/dir counts, bytes (never decreases), sha256 or manifest_sha256 when available, and error_class (refused_path, exists, limit, unsupported_remote, integrity, remote_failed, link_unstable, cancelled, internal) with a fixed message. For a single file it also reports mode (stream or chunked), chunk_bytes, chunks_done, chunks_total, attempts and bytes_per_second, each omitted while absent; a running chunked job shows live part progress, and a directory never carries them. A failed chunked job keeps its verified bytes and counts. link_unstable means the link was too unstable to finish: the staged parts are kept and the same upload or download call resumes. Never contains file content or local paths."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input transfer.StatusInput) (*mcp.CallToolResult, transfer.StatusOutput, error) {
			var out transfer.StatusOutput
			err := client.Call(ctx, "transfer_status", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "transfer_cancel", Description: "Cancel a running transfer job and close its SSH session. A chunked file transfer's partial parts are removed, so a cancel gives up resuming; a link failure keeps them. Cancelling an already finished job reports cancelled=false."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input transfer.CancelInput) (*mcp.CallToolResult, transfer.CancelOutput, error) {
			var out transfer.CancelOutput
			err := client.Call(ctx, "transfer_cancel", input, &out)
			return nil, out, err
		})
	return server
}
