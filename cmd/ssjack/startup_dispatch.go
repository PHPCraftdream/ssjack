package main

import (
	"context"
	"errors"
	"flag"
)

func handledStartup(code int, err error) (int, bool, error) {
	return code, true, err
}

// dispatchStartupCommand runs a built-in subcommand. handled is false when
// command is not a built-in, so the caller launches it as a harness.
func dispatchStartupCommand(ctx context.Context, flags *flag.FlagSet, vaultPath, server, account, profile string, command []string) (int, bool, error) {
	switch command[0] {
	case "owner":
		return handledStartup(runOwnerCommand(ctx, flags, vaultPath, server, account, command[1:]))
	case "text-adapter":
		return handledStartup(runTextAdapterCommand(ctx, vaultPath, profile, command[1:]))
	case "ssh":
		if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack [-p PROFILE] ssh")
		}
		return handledStartup(runVaultShell(ctx, vaultPath, profile))
	case "vault":
		return handledStartup(runVaultMaintenance(ctx, vaultPath, profile, command[1:]))
	case "list":
		if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack list")
		}
		return handledStartup(runVaultCommand(ctx, vaultPath, command))
	case "add":
		args := []string{"add", profile}
		if len(command) == 2 && command[1] == "--generate-key" {
			args = append(args, "--generate-key")
		} else if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack [-p PROFILE] add [--generate-key]")
		}
		return handledStartup(runVaultCommand(ctx, vaultPath, args))
	case "show", "edit", "remove":
		if len(command) != 1 {
			return 1, true, errors.New("select a profile with -p PROFILE before the command")
		}
		return handledStartup(runVaultCommand(ctx, vaultPath, []string{command[0], profile}))
	case "key":
		if len(command) == 2 && command[1] == "public" {
			return handledStartup(runVaultCommand(ctx, vaultPath, []string{"public", profile}))
		}
		if len(command) == 3 && (command[1] == "import" || command[1] == "export") {
			return handledStartup(runVaultCommand(ctx, vaultPath, []string{command[1], profile, command[2]}))
		}
		return 1, true, errors.New("usage: ssjack [-p PROFILE] key public | import FILE | export FILE")
	case "policy":
		return handledStartup(runPolicy(ctx, vaultPath, profile, command[1:]))
	case "doctor":
		if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack doctor")
		}
		return handledStartup(runSafetyCommand(ctx, vaultPath, command))
	case "check", "rotate":
		if len(command) != 1 {
			return 1, true, errors.New("select a profile with -p PROFILE before the command")
		}
		return handledStartup(runSafetyCommand(ctx, vaultPath, []string{command[0], profile}))
	case "hostkey":
		if len(command) == 2 && command[1] == "show" {
			return handledStartup(runSafetyCommand(ctx, vaultPath, []string{"hostkey", "show", profile}))
		}
		if len(command) == 3 && command[1] == "replace" {
			return handledStartup(runSafetyCommand(ctx, vaultPath, []string{"hostkey", "replace", profile, command[2]}))
		}
		return 1, true, errors.New("usage: ssjack [-p PROFILE] hostkey show | replace FILE")
	}
	return 0, false, nil
}
