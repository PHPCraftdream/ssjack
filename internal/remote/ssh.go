package remote

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func runSSH(ctx context.Context, address string, config *ssh.ClientConfig, command string, stdout, stderr io.Writer) (int, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return -1, errors.New("failed to connect to the SSH target")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return -1, errors.New("SSH authentication or host key verification failed")
	}
	conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return -1, errors.New("failed to open an SSH session")
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
