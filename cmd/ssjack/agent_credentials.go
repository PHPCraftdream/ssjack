package main

import (
	"context"
	"errors"
	"time"

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
	stream  remote.StreamRunner
	targets []string
	owner   ownerSession
	service ownerService
}

var errOwnerShutdown = errors.New("owner session could not close safely; inspect database persistence and pending recovery before retrying")

func finishAgentCredentials(credentials *agentCredentials, code *int, result *error) {
	if credentials == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	failed := false
	if credentials.service != nil {
		failed = credentials.service.Close(ctx) != nil
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
