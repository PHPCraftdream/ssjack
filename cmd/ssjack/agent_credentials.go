package main

import (
	"context"
	"errors"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpbridge"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshlive"
)

type ownerSession interface {
	Close(context.Context) error
}

type ownerService interface {
	Close(context.Context) error
	Done() <-chan struct{}
}

type agentCredentials struct {
	runner  remote.Runner
	guard   remote.GuardProvider
	stream  remote.StreamRunner
	targets []string
	owner   ownerSession
	service ownerService
	capture *mcpgrant.Capture
	// While a bridge runtime is active, launch cleanup ownership is exercised
	// through the bridge's close callback; mcpLaunch stays set only so the
	// merged output guard keeps resolving.
	mcpBridge     *mcpbridge.Runtime
	mcpLaunch     *mcpgrant.Launch
	mcpLaunchUsed bool
	channels      *mcpchannel.ChannelSet
	ssh           *sshlive.Runtime
}

type agentSSHSetup struct {
	runner  remote.Runner
	runtime *sshlive.Runtime
}

func (credentials *agentCredentials) sshSetup() agentSSHSetup {
	return agentSSHSetup{runner: credentials.runner, runtime: credentials.ssh}
}

func (setup agentSSHSetup) manager(ctx context.Context, targets []string, guard remote.GuardProvider, noOutputFilter bool) *remote.Manager {
	if setup.runtime == nil {
		return remote.NewGuardedManager(ctx, targets, setup.runner, guard)
	}
	return remote.NewAdmittedManager(ctx, targets, func(admitCtx context.Context, target, command string) (remote.AdmittedOperation, error) {
		if guard == nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		extra, err := guard(admitCtx)
		if err != nil || extra == nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		operation, err := setup.runtime.Admit(admitCtx, target, command)
		if err != nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		if noOutputFilter {
			// Keep mandatory upstream masks while bypassing known-literal filtering.
			operation.Guard = extra
			return operation, nil
		}
		merged, err := outputguard.Union(operation.Guard, extra)
		if err != nil {
			return remote.AdmittedOperation{}, remote.ErrAdmission
		}
		operation.Guard = merged
		return operation, nil
	})
}

func (credentials *agentCredentials) WithMCPLaunch(use func(*mcpgrant.Launch) error) error {
	if credentials == nil || use == nil || credentials.mcpLaunch == nil || credentials.mcpLaunchUsed {
		return errors.New("remote MCP launch is unavailable")
	}
	credentials.mcpLaunchUsed = true
	return use(credentials.mcpLaunch)
}

func fixedOutputGuard(snapshot *outputguard.Snapshot) remote.GuardProvider {
	return func(ctx context.Context) (*outputguard.Snapshot, error) {
		if snapshot == nil || ctx == nil || ctx.Err() != nil {
			return nil, outputguard.ErrGuard
		}
		return snapshot, nil
	}
}

var errOwnerShutdown = errors.New("owner session could not close safely; inspect database persistence and pending recovery before retrying")

func finishAgentCredentials(credentials *agentCredentials, code *int, result *error) {
	if credentials == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	failed := false
	if credentials.channels != nil {
		if credentials.channels.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		credentials.channels = nil
	}
	if credentials.mcpBridge != nil {
		if credentials.mcpBridge.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		// Bridge close already joined the SDK sessions and closed the launch;
		// clearing both prevents double close.
		credentials.mcpBridge, credentials.mcpLaunch = nil, nil
	}
	if credentials.mcpLaunch != nil {
		if credentials.mcpLaunch.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		credentials.mcpLaunch = nil
	}
	if credentials.capture != nil {
		if credentials.capture.Close(ctx) != nil {
			*code, *result = 1, errOwnerShutdown
			return
		}
		credentials.capture = nil
	}
	if credentials.service != nil {
		failed = credentials.service.Close(ctx) != nil || failed
		select {
		case <-credentials.service.Done():
		default:
			*code, *result = 1, errOwnerShutdown
			return // Parent key and role must outlive unfinished peers.
		}
	}
	if credentials.owner != nil && credentials.owner.Close(ctx) != nil {
		failed = true
	}
	if failed {
		*code, *result = 1, errOwnerShutdown
	}
}
