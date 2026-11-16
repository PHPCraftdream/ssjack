package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/mcpstart"
)

func runHook(args []string) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: ssjack hook pre|post|failure")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, hooks.MaxInput+1))
	if err != nil {
		return 1, errors.New("failed to read hook event")
	}
	output, err := hooks.Run(args[0], input)
	if err != nil {
		return 1, err
	}
	if _, err := fmt.Fprintln(os.Stdout, string(output)); err != nil {
		return 1, err
	}
	return 0, nil
}

func runMCP(ctx context.Context) (int, error) {
	// Read before the bootstrap environment is consumed; the log holds no secret.
	life := lifelog.New(os.Getenv(lifelog.Env), "mcp", os.Getenv(broker.EnvSession))
	life.Event("start", "ppid", strconv.Itoa(os.Getppid()))
	code, stage, err := serveMCP(ctx, life)
	life.Event("exit", "code", strconv.Itoa(code), "stage", stage, "context", lifelog.Cause(ctx.Err()))
	return code, err
}

// serveMCP also names the stage it stopped at, for the lifecycle log only.
func serveMCP(ctx context.Context, life *lifelog.Log) (int, string, error) {
	bootstrap, descriptors, err := mcpstart.ReadEnvironment()
	if err != nil {
		return 1, "bootstrap-environment", err
	}
	defer func() { bootstrap.Token = "" }()
	client, err := broker.ConnectBootstrap(ctx, bootstrap)
	bootstrap.Token = ""
	if err != nil {
		stage := "attach-parameters"
		switch {
		case errors.Is(err, broker.ErrDial):
			stage = "attach-dial"
		case errors.Is(err, broker.ErrAuth):
			stage = "attach-send"
		case errors.Is(err, broker.ErrRejected):
			stage = "attach-rejected"
		}
		return 1, stage, errors.New("MCP session attachment failed")
	}
	defer client.Close()
	client.SetTrace(life.Event)
	life.Event("attached")
	descriptor, err := broker.Describe(ctx, client)
	if err != nil {
		return 1, "describe", errors.New("keeper descriptor unavailable or invalid; refusing MCP startup")
	}
	server, err := bridge.NewRegistryForDescriptor(client, descriptor)
	if err != nil {
		return 1, "registry", errors.New("keeper descriptor unavailable or invalid; refusing MCP startup")
	}
	configureMCPStdioServer(server)
	connCtx, cancel := context.WithCancel(ctx)
	registration := startRemoteMCPRegistration(connCtx, descriptors, server)
	life.Event("serving")
	runErr := server.Run(connCtx, newMCPStdioTransport(os.Stdin, os.Stdout))
	life.Event("stdio-end", "cause", stdioCause(runErr))
	cancel()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), remoteMCPRegistrationBudget)
	cleanupErr := registration.Close(cleanupCtx)
	cleanupCancel()
	if cleanupErr != nil {
		return 1, "cleanup", errors.New("MCP bridge cleanup did not complete")
	}
	if runErr != nil {
		return 1, "stdio", errors.New("MCP bridge session failed")
	}
	return 0, "stdio-closed", nil
}

// stdioCause names the bridge's own stdio refusals, which the generic classes
// would all record as other.
func stdioCause(err error) string {
	switch {
	case errors.Is(err, errMCPStdioBatchUnsupported):
		return "unsupported-batch"
	case errors.Is(err, errMCPStdioMessageLimit), errors.Is(err, errMCPStdioMessageCountLimit):
		return "stdio-limit"
	case errors.Is(err, errMCPStdioInvalidMessage):
		return "invalid-message"
	case errors.Is(err, errMCPStdioUnsupportedMethod):
		return "unsupported-message"
	case errors.Is(err, errMCPStdioConcurrentRead):
		return "concurrent-read"
	case errors.Is(err, errMCPStdioWriteTimeout):
		return "stdio-write-timeout"
	}
	return lifelog.Cause(err)
}
