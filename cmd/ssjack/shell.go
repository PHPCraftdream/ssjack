package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func runVaultShell(ctx context.Context, path, name string) (int, error) {
	if err := validateCredentialSelection(name); err != nil {
		return 1, err
	}
	inputFD, outputFD := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	if !term.IsTerminal(inputFD) || !term.IsTerminal(outputFD) {
		return 1, errors.New("interactive SSH requires terminal input and output")
	}
	config, address, _, err := readVaultCredential(ctx, path, name, "human")
	if err != nil {
		return 1, err
	}
	return runShell(ctx, config, address)
}

// runShell hands the real terminal to one SSH session. Callers must own the
// terminal exclusively, e.g. after a Bubble Tea program has exited.
func runShell(ctx context.Context, config *ssh.ClientConfig, address string) (code int, err error) {
	if config == nil || address == "" {
		return 1, errors.New("interactive SSH requires a client configuration and address")
	}
	inputFD, outputFD := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	width, height, err := term.GetSize(outputFD)
	if err != nil {
		return 1, errors.New("failed to read terminal dimensions")
	}
	size := remote.WindowSize{Width: width, Height: height}
	terminalType := os.Getenv("TERM")
	if terminalType == "" {
		terminalType = "xterm-256color"
	}
	// cancelreader on Windows changes the console input mode inside NewReader,
	// before MakeRaw captures its state, so the true pre-handoff mode must be
	// captured before the reader exists. Registered first, this restore runs
	// last: after the raw restore and the conditional Close below. It only sets
	// the mode on the stdin handle (no close), so it is safe when the reader is
	// deliberately leaked; on Unix it is an idempotent restore.
	original, err := term.GetState(inputFD)
	if err != nil {
		return 1, errors.New("failed to read terminal input settings")
	}
	defer func() {
		if restoreErr := term.Restore(inputFD, original); restoreErr != nil && err == nil {
			code, err = 1, errors.New("failed to restore terminal input settings")
		}
	}()
	// remote.Shell owns the stdin pump and cancels and joins it when the session
	// ends. Order on exit: raw-mode restore, then Close only when no Read or
	// Cancel can still be in flight (otherwise the reader is left to process
	// exit), then the restore of the state captured above.
	input, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return 1, errors.New("failed to prepare cancellable terminal input")
	}
	inputStuck := false
	defer func() {
		if !inputStuck {
			_ = input.Close()
		}
	}()
	resizeCtx, cancel := context.WithCancel(ctx)
	resize, stopped := watchTerminalSize(resizeCtx, outputFD, size)
	defer func() { cancel(); <-stopped }()
	return withRawTerminal(func() (func() error, error) {
		restoreOutput, err := prepareTerminalOutput(outputFD)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare terminal output: %w", err)
		}
		state, err := term.MakeRaw(inputFD)
		if err != nil {
			return nil, errors.Join(errors.New("failed to enter raw terminal mode"), restoreOutput())
		}
		return func() error { return errors.Join(term.Restore(inputFD, state), restoreOutput()) }, nil
	}, func(ready func() error) (int, error) {
		code, err := remote.Shell(ctx, remote.ShellOptions{
			Address: address, Config: config, Term: terminalType, Size: size,
			Resize: resize, Stdin: input, Stdout: os.Stdout, Stderr: os.Stderr, Ready: ready,
		})
		inputStuck = errors.Is(err, remote.ErrInputNotReleased)
		if code < 0 {
			code = 1
		}
		return code, err
	})
}

func withRawTerminal(enter func() (func() error, error), run func(func() error) (int, error)) (code int, err error) {
	var restore func() error
	defer func() {
		if restore != nil {
			if restoreErr := restore(); restoreErr != nil {
				code = 1
				err = errors.Join(err, fmt.Errorf("failed to restore terminal: %w", restoreErr))
			}
		}
	}()
	return run(func() error {
		if restore != nil {
			return errors.New("terminal is already in raw mode")
		}
		var enterErr error
		restore, enterErr = enter()
		return enterErr
	})
}

func watchTerminalSize(ctx context.Context, fd int, previous remote.WindowSize) (<-chan remote.WindowSize, <-chan struct{}) {
	updates := make(chan remote.WindowSize, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer close(updates)
		// Polling also supports Windows consoles without SIGWINCH.
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				width, height, err := term.GetSize(fd)
				current := remote.WindowSize{Width: width, Height: height}
				if err != nil || width <= 0 || height <= 0 || current == previous {
					continue
				}
				select {
				case updates <- current:
					previous = current
				default:
				}
			}
		}
	}()
	return updates, stopped
}
