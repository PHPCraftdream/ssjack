package ownerrotatecli

import (
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var errRotationArguments = errors.New("invalid rotate-key command; use ssjack help owner rotate-key")

type rotationCommand struct {
	Server  string
	Account string
	Recover bool
	Cancel  bool
	Archive bool
}

// parseRotationCommand accepts selectors only; approvals and secret material are never arguments.
func parseRotationCommand(args []string, globalServer, globalAccount string) (rotationCommand, error) {
	if len(args) == 0 || args[0] != "rotate-key" || (globalServer != "" && vault.ValidateName(globalServer) != nil) || (globalAccount != "" && vault.ValidateName(globalAccount) != nil) {
		return rotationCommand{}, errRotationArguments
	}
	command := rotationCommand{Server: globalServer, Account: globalAccount}
	hasGlobalSelector := globalServer != "" || globalAccount != ""
	seen := map[string]bool{"server": globalServer != "", "account": globalAccount != ""}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--recover" || arg == "--cancel-prepared" || arg == "--archive-completed" {
			switch arg {
			case "--recover":
				if command.Recover {
					return rotationCommand{}, errRotationArguments
				}
				command.Recover = true
			case "--cancel-prepared":
				if command.Cancel {
					return rotationCommand{}, errRotationArguments
				}
				command.Cancel = true
			case "--archive-completed":
				if command.Archive {
					return rotationCommand{}, errRotationArguments
				}
				command.Archive = true
			}
			continue
		}
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			return rotationCommand{}, errRotationArguments
		}
		name, value, assigned := strings.Cut(arg[2:], "=")
		if name != "server" && name != "account" || seen[name] || hasGlobalSelector {
			return rotationCommand{}, errRotationArguments
		}
		seen[name] = true
		if !assigned {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return rotationCommand{}, errRotationArguments
			}
			value = args[i]
		}
		if value == "" || strings.ContainsAny(value, "\x00\r\n\x1b") || vault.ValidateName(value) != nil {
			return rotationCommand{}, errRotationArguments
		}
		if name == "server" {
			command.Server = value
		} else {
			command.Account = value
		}
	}
	if command.Server == "" || command.Account == "" || command.Cancel && !command.Recover || command.Archive && (command.Recover || command.Cancel) {
		return rotationCommand{}, errRotationArguments
	}
	return command, nil
}

func rotationConfirmation(info rotationDisplay) string {
	return "ROTATE " + info.ServerID + " " + info.Account + " revision=" + strconv.FormatUint(info.Revision, 10) + " operation=" + info.OperationID
}

func recoveryConfirmation(info rotationDisplay) string {
	return "VERIFY-ONLY " + info.ServerID + " " + info.Account + " revision=" + strconv.FormatUint(info.Revision, 10) + " operation=" + info.OperationID
}

func cancellationConfirmation(info rotationDisplay) string {
	return "CANCEL-PREPARED " + info.ServerID + " " + info.Account + " revision=" + strconv.FormatUint(info.Revision, 10) + " operation=" + info.OperationID
}

func archiveConfirmation(info rotationDisplay) string {
	return "ARCHIVE " + info.ServerID + " " + info.Account + " revision=" + strconv.FormatUint(info.Revision, 10) + " operation=" + info.OperationID
}

func rotationConsent(read func(string) ([]byte, error), prompt, expected string) error {
	value, err := read(prompt)
	if err != nil {
		return err
	}
	defer clear(value)
	if subtle.ConstantTimeCompare(value, []byte(expected)) != 1 {
		return errors.New("rotation confirmation did not match; no approval was recorded")
	}
	return nil
}
