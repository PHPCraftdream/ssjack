package remote

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
)

// Check authenticates and opens a session without requesting a command or PTY.
func Check(ctx context.Context, address string, config *ssh.ClientConfig) error {
	if config == nil || config.HostKeyCallback == nil || config.User == "" || len(config.Auth) == 0 {
		return errors.New("connection check requires verified credentials")
	}
	client, closeClient, err := connectSSH(ctx, address, config)
	if err != nil {
		return err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return sshStageError(ctx, "failed to open the SSH verification session")
	}
	defer session.Close()
	return ctx.Err()
}
