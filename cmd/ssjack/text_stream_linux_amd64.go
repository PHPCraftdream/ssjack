//go:build linux && amd64

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func loadCLITextGrant(id string, streaming bool) (declarativeauthority.TextAdapterGrant, error) {
	if streaming {
		return declarativeauthority.LoadTextStream(id, os.Geteuid(), time.Now())
	}
	return declarativeauthority.LoadTextAdapter(id, os.Geteuid(), time.Now())
}

func runTextStreamHarness(ctx context.Context, installation *appstorecrypto.Installation, mode, grantID, profile, credential string, runner remote.StreamRunner, command []string) (int, error) {
	if len(command) == 0 {
		return 1, errors.New("streaming text adapter requires an explicit harness")
	}
	construct := appstorecrypto.NewTextStreamAdapter
	if mode == "reverse-copy-stream-v2" {
		construct = appstorecrypto.NewReverseTextStreamAdapter
	} else if mode != "hydrate-stream-v2" {
		return 1, errors.New("invalid streaming text-adapter direction")
	}
	adapter, err := construct(ctx, installation, grantID, profile, credential, runner)
	if err != nil {
		return 1, errors.New("streaming text-adapter grant validation failed")
	}
	defer adapter.Close()
	var server *apptransport.Server
	if mode == "reverse-copy-stream-v2" {
		server, err = apptransport.ListenWithReverseTextStreamAdapter(ctx, profile, runner, adapter)
	} else {
		server, err = apptransport.ListenWithTextStreamAdapter(ctx, profile, runner, adapter)
	}
	if err != nil {
		return 1, err
	}
	defer server.Close()
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Env = apptransport.Environment(os.Environ(), server.Bootstrap())
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func revokeTextStreamAdapter(_ context.Context, args []string) (int, error) {
	if os.Geteuid() != 0 {
		return 1, errors.New("streaming text-adapter revocation requires root")
	}
	if rejectAppstoreBrokerEnv() != nil {
		return 1, errors.New("revocation is unavailable in broker sessions")
	}
	if len(args) != 1 {
		return 1, errors.New("usage: ssjack text-adapter revoke-stream GRANT_ID")
	}
	if err := declarativeauthority.RevokeTextStream(args[0]); err != nil {
		return 1, err
	}
	return 0, nil
}
