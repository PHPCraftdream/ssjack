package main

import (
	"context"
	"errors"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
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
	// mcpLaunch remains owned here for cleanup; launch access is one-shot.
	mcpLaunch     *mcpgrant.Launch
	mcpLaunchUsed bool
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
