//go:build linux && amd64

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerresource"
	"github.com/PHPCraftdream/ssjack/internal/ownerservice"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// runOwnedTextAdapter consumes the already unlocked, linked version-2 vault.
func runOwnedTextAdapter(ctx context.Context, path string, loaded *vault.Vault, request ownerresource.TextRequest, command []string) (code int, result error) {
	if len(command) == 0 {
		return 1, errors.New("text adapter requires an explicit harness")
	}
	owner, err := ownerdb.Adopt(ctx, path, loaded)
	if err != nil {
		return 1, err
	}
	credentials := &agentCredentials{owner: owner}
	defer finishAgentCredentials(credentials, &code, &result)
	service, err := ownerservice.Start(ctx, owner)
	if err != nil {
		return 1, err
	}
	credentials.service = service
	consumer, err := owner.ServeText(ctx, request)
	if err != nil {
		return 1, errors.New("linked text-adapter grant validation failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if consumer.Close(cleanup) != nil {
			code, result = 1, errOwnerShutdown
		}
	}()
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Env = apptransport.Environment(os.Environ(), consumer.Bootstrap())
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = child.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}
