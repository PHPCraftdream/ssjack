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
	if descriptor.Mode == broker.ModeDeclarative && descriptor.Protocol == broker.SyntheticProtocol {
		server := mcp.NewServer(&mcp.Implementation{Name: "ssjack", Version: buildinfo.Version}, nil)
		mcp.AddTool(server, &mcp.Tool{Name: "resource_plan", Description: "Plan a fixed synthetic cache metadata update; no secrets or command execution."}, func(ctx context.Context, _ *mcp.CallToolRequest, input declarativeslice.PlanInput) (*mcp.CallToolResult, declarativeslice.PlanResult, error) {
			var out declarativeslice.PlanResult
			if client == nil {
				return nil, out, errors.New("keeper unavailable")
			}
			err := client.Call(ctx, "resource_plan", input, &out)
			return nil, out, err
		})
		mcp.AddTool(server, &mcp.Tool{Name: "plan_apply", Description: "Apply a previously issued synthetic metadata plan."}, func(ctx context.Context, _ *mcp.CallToolRequest, input declarativeslice.ApplyInput) (*mcp.CallToolResult, declarativeslice.ApplyResult, error) {
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
	mcp.AddTool(server, &mcp.Tool{Name: "app_list", Description: "List the human-registered local Clawwright deployment, if enabled."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, application.ListOutput, error) {
			var out application.ListOutput
			err := client.Call(ctx, "app_list", struct{}{}, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_exec", Description: "Start a finite command in the registered Clawwright deployment. Arguments are passed as argv, never through a local shell. Mutating operations require confirm=true and applicable harness authorization. Returns job_id."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input application.Input) (*mcp.CallToolResult, remote.StartOutput, error) {
			var out remote.StartOutput
			err := client.Call(ctx, "app_start", input, &out)
			return nil, out, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_read", Description: "Read the registered Clawwright operation output using returned offsets; drain both streams until done and no more output remains."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
			var raw remote.ReadOutput
			err := client.Call(ctx, "app_read", input, &raw)
			return nil, readOutput(raw), err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "app_cancel", Description: "Cancel a Clawwright operation and revoke its child transport. A detached remote process may continue running."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input remote.JobInput) (*mcp.CallToolResult, remote.CancelOutput, error) {
			var out remote.CancelOutput
			err := client.Call(ctx, "app_cancel", input, &out)
			return nil, out, err
		})
	return server
}
