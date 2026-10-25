package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"storagehost/internal/remote"
	"storagehost/internal/vault"
)

func runVaultShell(ctx context.Context, path, name string) (int, error) {
	if err := vault.ValidateName(name); err != nil {
		return 1, err
	}
	inputFD, outputFD := int(os.Stdin.Fd()), int(os.Stdout.Fd())
	if !term.IsTerminal(inputFD) || !term.IsTerminal(outputFD) {
		return 1, errors.New("interactive SSH requires terminal input and output")
	}
	config, address, _, err := readVaultCredential(path, name, "human")
	if err != nil {
		return 1, err
	}
	width, height, err := term.GetSize(outputFD)
	if err != nil {
		return 1, errors.New("failed to read terminal dimensions")
	}
	size := remote.WindowSize{Width: width, Height: height}
	terminalType := os.Getenv("TERM")
	if terminalType == "" {
		terminalType = "xterm-256color"
	}
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
			Resize: resize, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Ready: ready,
		})
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
