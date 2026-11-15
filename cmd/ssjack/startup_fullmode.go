package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type fullModeOptions struct {
	vaultPath, profile                                                        string
	clawwrightDirectory, clawwrightEntry, clawwrightContainer, clawwrightUser string
	transferRoots                                                             []string
	transferMaxBytes                                                          int64
	transferMaxEntries                                                        int
	noOutputFilter, named                                                     bool
	ttl                                                                       time.Duration
}

type fullModeSession struct {
	handler       broker.Handler
	remoteMCP     string
	prepareOutput launch.OutputSetup
}

// startFullMode unlocks the profile and builds the keeper handler. The
// returned cleanup is never nil and must be deferred even when err is set: it
// releases whatever was acquired so far, in reverse order.
func startFullMode(ctx context.Context, opts fullModeOptions) (fullModeSession, func(*int, *error), error) {
	var cleanups []func(*int, *error)
	cleanup := func(code *int, result *error) {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i](code, result)
		}
	}
	var session fullModeSession
	applicationOptions, err := registeredClawwright(opts.clawwrightDirectory, opts.clawwrightEntry, opts.clawwrightContainer, opts.clawwrightUser, opts.profile, nil)
	if err != nil {
		return session, cleanup, err
	}
	transfers, err := prepareTransfer(opts.vaultPath, opts.transferRoots, opts.transferMaxBytes, opts.transferMaxEntries)
	if err != nil {
		return session, cleanup, err
	}
	credentials, err := cliLoadAgentCredentials(ctx, opts.vaultPath, opts.profile)
	if credentials != nil {
		cleanups = append(cleanups, func(code *int, result *error) { finishAgentCredentials(credentials, code, result) })
	}
	if err != nil {
		return session, cleanup, err
	}
	if credentials == nil {
		return session, cleanup, errors.New("credential session is unavailable")
	}
	sshSetup, streamRunner, targets, guard := credentials.sshSetup(), credentials.stream, credentials.targets, credentials.guard
	guard, err = selectOutputGuard(guard, opts.noOutputFilter, os.Stderr)
	if err != nil {
		return session, cleanup, err
	}
	guard, session.remoteMCP, err = prepareRemoteMCPChannels(ctx, credentials, guard, opts.ttl)
	if err != nil {
		return session, cleanup, errors.New("remote MCP channel setup failed")
	}
	guard, session.prepareOutput = prepareMCPBootstrapOutput(ctx, guard, credentials.mcpBridge)
	if opts.named {
		if err := bindNamedApplication(applicationOptions, targets); err != nil {
			return session, cleanup, err
		}
	}
	manager := sshSetup.manager(ctx, targets, guard, opts.noOutputFilter)
	cleanups = append(cleanups, func(*int, *error) { manager.Close() })
	if applicationOptions != nil {
		applicationOptions.Runner, applicationOptions.Guard = streamRunner, guard
	}
	applicationManager, err := application.New(ctx, applicationOptions)
	if err != nil {
		return session, cleanup, err
	}
	cleanups = append(cleanups, func(*int, *error) { applicationManager.Close() })
	transferManager, err := newTransferManager(transfers, targets, streamRunner)
	if err != nil {
		return session, cleanup, err
	}
	cleanups = append(cleanups, func(*int, *error) { transferManager.Close() })
	session.handler = func(ctx context.Context, request wire.Request) wire.Reply {
		if reply, handled := applicationManager.Handle(ctx, request); handled {
			return reply
		}
		if reply, handled := transferManager.Handle(ctx, request); handled {
			return reply
		}
		return manager.Handle(ctx, request)
	}
	return session, cleanup, nil
}
