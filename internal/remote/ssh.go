package remote

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

func sshStageError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}

func connectSSH(ctx context.Context, address string, config *ssh.ClientConfig) (*ssh.Client, func(), error) {
	prepared, signed, err := sshauth.ForConnection(config)
	if err != nil {
		return nil, nil, err
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, sshStageError(ctx, "failed to connect to the SSH target")
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, prepared)
	if err != nil {
		stop()
		conn.Close()
		return nil, nil, sshStageError(ctx, "SSH authentication or host key verification failed")
	}
	if !signed() {
		stop()
		sshConn.Close()
		conn.Close()
		return nil, nil, errors.New("SSH authentication did not use the selected private key; refusing unverified identity")
	}
	conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, channels, requests)
	return client, func() { stop(); client.Close() }, nil
}

func NewCredentialRunner(name, address string, config *ssh.ClientConfig) (Runner, error) {
	if name == "" || address == "" || config == nil || config.HostKeyCallback == nil || config.User == "" || len(config.Auth) == 0 {
		return nil, errors.New("credentials require a name, address, user, authentication, and verified host keys")
	}
	return func(ctx context.Context, target, command string, stdout, stderr io.Writer) (int, error) {
		if target != name {
			return -1, errors.New("unapproved credential name")
		}
		return runSSH(ctx, address, config, command, stdout, stderr)
	}, nil
}

func runSSH(ctx context.Context, address string, config *ssh.ClientConfig, command string, stdout, stderr io.Writer) (int, error) {
	client, closeClient, err := connectSSH(ctx, address, config)
	if err != nil {
		return -1, err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return -1, sshStageError(ctx, "failed to open an SSH session")
	}
	defer session.Close()
	session.Stdout, session.Stderr = stdout, stderr
	if err := session.Run(command); err != nil {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			return exit.ExitStatus(), nil
		}
		return -1, errors.New("SSH command did not terminate normally")
	}
	return 0, nil
}
