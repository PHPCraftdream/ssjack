package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
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
	bootstrap, descriptors, err := mcpstart.ReadEnvironment()
	if err != nil {
		return 1, err
	}
	defer func() { bootstrap.Token = "" }()
	client, err := broker.ConnectBootstrap(ctx, bootstrap)
	bootstrap.Token = ""
	if err != nil {
		return 1, errors.New("MCP session attachment failed")
	}
	defer client.Close()
	descriptor, err := broker.Describe(ctx, client)
	if err != nil {
		return 1, errors.New("keeper descriptor unavailable or invalid; refusing MCP startup")
	}
	server, err := bridge.NewRegistryForDescriptor(client, descriptor)
	if err != nil {
		return 1, errors.New("keeper descriptor unavailable or invalid; refusing MCP startup")
	}
	connCtx, cancel := context.WithCancel(ctx)
	registration := startRemoteMCPRegistration(connCtx, descriptors, server)
	runErr := server.Run(connCtx, newMCPStdioTransport(os.Stdin, os.Stdout))
	cancel()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), remoteMCPRegistrationBudget)
	cleanupErr := registration.Close(cleanupCtx)
	cleanupCancel()
	if cleanupErr != nil {
		return 1, errors.New("MCP bridge cleanup did not complete")
	}
	if runErr != nil {
		return 1, errors.New("MCP bridge session failed")
	}
	return 0, nil
}
