//go:build linux || darwin

package ownerterminal

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

func start(ctx context.Context, spec Command) (*Terminal, error) {
	if spec.UnixBridge == "" {
		return nil, ErrTerminal
	}
	args := append([]string{"-I", spec.UnixBridge, spec.Executable}, spec.Args...)
	command := exec.Command("python3", args...)
	command.Dir, command.Env = spec.Directory, spec.Environment
	inputRead, input, err := os.Pipe()
	if err != nil {
		return nil, ErrTerminal
	}
	defer inputRead.Close()
	output, outputWrite, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return nil, ErrTerminal
	}
	defer outputWrite.Close()
	command.Stdin, command.Stdout, command.Stderr = inputRead, outputWrite, outputWrite
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, ErrTerminal
	}
	t := &Terminal{Input: input, Output: output, done: make(chan struct{}), watch: make(chan struct{})}
	t.stop = func() { _ = command.Process.Signal(syscall.SIGTERM) }
	go func() {
		if command.Wait() != nil {
			t.err = ErrTerminal
		}
		close(t.done)
	}()
	t.observe(ctx)
	return t, nil
}
