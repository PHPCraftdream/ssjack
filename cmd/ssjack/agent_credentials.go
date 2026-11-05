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

type agentCredentials struct {
	runner  remote.Runner
	stream  remote.StreamRunner
	targets []string
	owner   ownerSession
}

var errOwnerShutdown = errors.New("owner session could not close safely; inspect database persistence and pending recovery before retrying")

func finishAgentCredentials(credentials *agentCredentials, code *int, result *error) {
	if credentials == nil || credentials.owner == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := credentials.owner.Close(ctx); err != nil {
		*code, *result = 1, errOwnerShutdown
	}
}
