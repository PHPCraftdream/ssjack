package shell

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func TestOwnerProtocolVersionMismatchMessage(t *testing.T) {
	err := ownerControlOpenError()
	if err == nil || err.Error() != ownerControlMessage || !strings.Contains(err.Error(), "may run a different ssjack protocol version") || !strings.Contains(err.Error(), "Restart keeper and client from the same build") {
		t.Fatalf("owner-control message=%v", err)
	}
}

func TestShellOutcomeFailsClosedOnlyWhenInputNotReleased(t *testing.T) {
	for _, err := range []error{
		remote.ErrInputNotReleased,
		errors.Join(context.Canceled, remote.ErrInputNotReleased),
	} {
		if resume, fatal := shellOutcome(1, err); resume || fatal == nil {
			t.Fatal("unreleased terminal input must not resume the picker")
		}
	}
	for _, tc := range []struct {
		code int
		err  error
	}{{0, nil}, {7, nil}, {1, errors.New("ordinary failure")}, {1, context.Canceled}} {
		if resume, fatal := shellOutcome(tc.code, tc.err); !resume || fatal != nil {
			t.Fatal("ordinary shell outcome must resume the picker")
		}
	}
}

func TestSharedShellRejectsMissingConfigurationWithoutTerminal(t *testing.T) {
	if code, err := runShell(context.Background(), nil, "example.test:22"); code != 1 || err == nil {
		t.Fatal("shared shell accepted a missing client configuration")
	}
	if code, err := runShell(context.Background(), &ssh.ClientConfig{}, ""); code != 1 || err == nil {
		t.Fatal("shared shell accepted an empty address")
	}
}

func TestRawTerminalRestoration(t *testing.T) {
	for _, shellFails := range []bool{false, true} {
		entered, restored := 0, 0
		failure := errors.New("shell failed")
		code, err := withRawTerminal(func() (func() error, error) {
			entered++
			return func() error { restored++; return nil }, nil
		}, func(ready func() error) (int, error) {
			if err := ready(); err != nil {
				return 1, err
			}
			if shellFails {
				return 1, failure
			}
			return 0, nil
		})
		if entered != 1 || restored != 1 || (shellFails && (code != 1 || !errors.Is(err, failure))) || (!shellFails && (code != 0 || err != nil)) {
			t.Fatalf("terminal lifecycle: entered=%d restored=%d code=%d err=%v", entered, restored, code, err)
		}
	}
}

func TestRawTerminalIsNotEnteredBeforeSSHReady(t *testing.T) {
	entered := false
	_, _ = withRawTerminal(func() (func() error, error) {
		entered = true
		return func() error { return nil }, nil
	}, func(_ func() error) (int, error) {
		return 1, errors.New("host rejected")
	})
	if entered {
		t.Fatal("terminal changed before host authentication and PTY acceptance")
	}
}

func TestRawTerminalEnterAndRestoreErrors(t *testing.T) {
	failure := errors.New("terminal failure")
	if _, err := withRawTerminal(func() (func() error, error) {
		return nil, failure
	}, func(ready func() error) (int, error) {
		return 1, ready()
	}); !errors.Is(err, failure) {
		t.Fatal("raw terminal setup error was lost")
	}
	if code, err := withRawTerminal(func() (func() error, error) {
		return func() error { return failure }, nil
	}, func(ready func() error) (int, error) {
		return 0, ready()
	}); code != 1 || !errors.Is(err, failure) {
		t.Fatal("terminal restoration error was lost")
	}
}
