package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const outputFilterWarning = "WARNING: MCP known-literal output filtering is DISABLED for this launch. Encryption, grants and application bootstrap-token masking remain enabled. Human SSH sessions are always unfiltered.\n"

func requireOutputFilterTerminal() error {
	if rejectAppstoreBrokerEnv() != nil || !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return errors.New("--no-output-filter requires a trusted input/warning terminal outside broker sessions")
	}
	return nil
}

func selectOutputGuard(provider remote.GuardProvider, disabled bool, warning io.Writer) (remote.GuardProvider, error) {
	if !disabled {
		return provider, nil
	}
	// An explicit owner startup choice, never a failed-construction fallback.
	snapshot, err := outputguard.New(nil)
	if err != nil {
		return nil, outputguard.ErrGuard
	}
	if warning == nil {
		return nil, errors.New("MCP output-filter warning could not be displayed")
	}
	n, err := io.WriteString(warning, outputFilterWarning)
	if err != nil || n != len(outputFilterWarning) {
		return nil, errors.New("MCP output-filter warning could not be displayed")
	}
	return fixedOutputGuard(snapshot), nil
}
