package remote

import (
	"context"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
)

type WindowSize struct {
	Width  int
	Height int
}

func (s WindowSize) valid() bool {
	return s.Width > 0 && s.Width <= 65535 && s.Height > 0 && s.Height <= 65535
}

type ShellOptions struct {
	Address string
	Config  *ssh.ClientConfig
	Term    string
	Size    WindowSize
	Resize  <-chan WindowSize
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Ready   func() error
}

func Shell(ctx context.Context, opts ShellOptions) (int, error) {
	if opts.Config == nil || opts.Config.HostKeyCallback == nil || !opts.Size.valid() ||
		opts.Term == "" || len(opts.Term) > 64 {
		return -1, errors.New("interactive SSH requires verified host keys, terminal dimensions, and a terminal type")
	}
	for _, c := range opts.Term {
		if c < 33 || c > 126 {
			return -1, errors.New("invalid terminal type")
		}
	}
	client, closeClient, err := connectSSH(ctx, opts.Address, opts.Config)
	if err != nil {
		return -1, err
	}
	defer closeClient()
	session, err := client.NewSession()
	if err != nil {
		return -1, sshStageError(ctx, "failed to open an interactive SSH session")
	}
	defer session.Close()
	session.Stdin, session.Stdout, session.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	if err := session.RequestPty(opts.Term, opts.Size.Height, opts.Size.Width, ssh.TerminalModes{
		ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400,
	}); err != nil {
		return -1, sshStageError(ctx, "server refused the interactive SSH terminal")
	}
	if opts.Ready != nil {
		if err := opts.Ready(); err != nil {
			return -1, err
		}
	}
	if err := session.Shell(); err != nil {
		return -1, sshStageError(ctx, "server refused the SSH shell")
	}
	done := make(chan struct{})
	resizeDone := make(chan struct{})
	go func() {
		defer close(resizeDone)
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case size, ok := <-opts.Resize:
				if !ok {
					return
				}
				if !size.valid() {
					continue
				}
				if err := session.WindowChange(size.Height, size.Width); err != nil {
					return
				}
			}
		}
	}()
	err = session.Wait()
	close(done)
	// Unblock a resize write before joining its goroutine.
	client.Close()
	<-resizeDone
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			return exit.ExitStatus(), nil
		}
		return -1, errors.New("SSH shell did not terminate normally")
	}
	return 0, nil
}
