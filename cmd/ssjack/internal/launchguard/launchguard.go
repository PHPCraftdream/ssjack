// Package launchguard holds the shared launch-time output-filter gate
// declarations so external remote acceptance can exercise the exact
// production functions rather than copies.
package launchguard

import (
	"errors"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/appstore"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const Warning = "WARNING: MCP known-literal output filtering is DISABLED for this launch. Encryption, grants and application bootstrap-token masking remain enabled. Human SSH sessions are always unfiltered.\n"

func RequireTerminal() error {
	if appstore.RejectBrokerEnv() != nil || !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return errors.New("--no-output-filter requires a trusted input/warning terminal outside broker sessions")
	}
	return nil
}

func Select(provider remote.GuardProvider, disabled bool, warning io.Writer) (remote.GuardProvider, error) {
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
	n, err := io.WriteString(warning, Warning)
	if err != nil || n != len(Warning) {
		return nil, errors.New("MCP output-filter warning could not be displayed")
	}
	return agent.FixedOutputGuard(snapshot), nil
}
