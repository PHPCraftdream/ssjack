package remote

import (
	"context"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

type WindowSize struct {
	Width  int
	Height int
}

func (s WindowSize) valid() bool {
	return s.Width > 0 && s.Width <= 65535 && s.Height > 0 && s.Height <= 65535
}

// ErrInputNotReleased means the stdin consumer could not be stopped after the
// session ended, so a Read on ShellOptions.Stdin may still be in flight. The
// caller must stop using that input and treat the terminal as unusable. On this
// error BOTH a Read and the Cancel call may still be running on the input, so
// the caller must neither Close it nor start another reader on that terminal;
// the abandoned goroutines end at process exit.
var ErrInputNotReleased = errors.New("terminal input could not be released after the SSH session")

// inputReleaseTimeout bounds the wait for the stdin pump; tests shorten it.
var inputReleaseTimeout = 2 * time.Second

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
	// Stdin stays unset: x/crypto would start an unjoined io.Copy from it. Our
	// own pump (below) starts only once the shell runs and is joined.
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return -1, errors.New("failed to open the interactive SSH input")
	}
	session.Stdout, session.Stderr = opts.Stdout, opts.Stderr
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
	pumpDone := make(chan struct{})
	if opts.Stdin == nil {
		_ = stdinPipe.Close()
		close(pumpDone)
	} else {
		go func() {
			defer close(pumpDone)
			// EOF sends channel EOF; other errors (e.g. writes after remote
			// exit) just end the pump.
			if _, err := io.Copy(stdinPipe, opts.Stdin); err == nil {
				_ = stdinPipe.Close()
			}
		}()
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
	waitErr := session.Wait()
	close(done)
	// Unblock a resize write before joining its goroutine.
	client.Close()
	<-resizeDone
	released := releaseInput(opts.Stdin, pumpDone)
	code, err := shellOutcome(ctx, waitErr)
	if !released {
		err = errors.Join(err, ErrInputNotReleased)
	}
	return code, err
}

// releaseInput cancels a cancelable input and waits for the pump to finish.
// Cancel itself can block (cancelreader on Windows may wait on a signal that a
// failed overlapped read never sends), so it runs in its own goroutine and ONE
// timer bounds the whole cancel+join. Released means Cancel returned AND the
// pump joined; Cancel's result is ignored. On timeout (false) both a Read and
// the Cancel call may still be running, so the caller must not Close the input
// or start another reader on it.
func releaseInput(in io.Reader, pumpDone <-chan struct{}) bool {
	// The timer starts first so nothing below can outlast the bound.
	timer := time.NewTimer(inputReleaseTimeout)
	defer timer.Stop()
	cancelDone := make(chan struct{})
	if c, ok := in.(interface{ Cancel() bool }); ok {
		go func() {
			defer close(cancelDone)
			c.Cancel()
		}()
	} else {
		close(cancelDone)
	}
	for cancelDone != nil || pumpDone != nil {
		select {
		case <-cancelDone:
			cancelDone = nil
		case <-pumpDone:
			pumpDone = nil
		case <-timer.C:
			return false
		}
	}
	return true
}

func shellOutcome(ctx context.Context, err error) (int, error) {
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
