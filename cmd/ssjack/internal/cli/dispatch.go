package cli

import (
	"context"
	"errors"
	"flag"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/ownercmd"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/shell"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/textadapter"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/vaultcmd"
	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func startupSelection(flags *flag.FlagSet, profile, server, account string) (string, bool, error) {
	serverSupplied, accountSupplied, profileSupplied := false, false, false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			serverSupplied = true
		case "account":
			accountSupplied = true
		case "profile", "p":
			profileSupplied = true
		}
	})
	if !serverSupplied {
		if accountSupplied {
			return "", false, errors.New("--account requires --server")
		}
		return profile, false, nil
	}
	if profileSupplied {
		return "", false, errors.New("--server conflicts with --profile/-p")
	}
	if err := vault.ValidateName(server); err != nil {
		return "", false, err
	}
	if accountSupplied {
		if err := vault.ValidateName(account); err != nil {
			return "", false, err
		}
		return "@" + server + "/" + account, true, nil
	}
	return "@" + server, true, nil
}

func bindNamedApplication(options *application.Options, targets []string) error {
	if len(targets) != 1 {
		return errors.New("named selection did not resolve exactly one credential")
	}
	if err := vault.ValidateName(targets[0]); err != nil {
		return err
	}
	if options != nil {
		options.Profile = targets[0]
	}
	return nil
}

func namedCommandAllowed(command []string) bool {
	if len(command) == 0 {
		return true
	}
	if command[0] == "text-adapter" && len(command) > 1 {
		switch command[1] {
		case "register", "register-reverse", "revoke", "register-stream", "register-reverse-stream", "revoke-stream":
			return false
		}
	}
	switch command[0] {
	case "vault", "list", "add", "show", "edit", "remove", "key", "policy", "doctor", "hostkey", "appstore", "mcp", "declarative", "hook", "install-hooks":
		return false
	}
	return true
}

func handledStartup(code int, err error) (int, bool, error) {
	return code, true, err
}

// dispatchStartupCommand runs a built-in subcommand. handled is false when
// command is not a built-in, so the caller launches it as a harness.
func dispatchStartupCommand(ctx context.Context, flags *flag.FlagSet, vaultPath, server, account, profile string, command []string) (int, bool, error) {
	switch command[0] {
	case "owner":
		return handledStartup(ownercmd.Run(ctx, flags, vaultPath, server, account, command[1:]))
	case "text-adapter":
		return handledStartup(textadapter.Run(ctx, vaultPath, profile, command[1:]))
	case "ssh":
		if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack [-p PROFILE] ssh")
		}
		return handledStartup(shell.RunVaultShell(ctx, vaultPath, profile))
	case "vault":
		return handledStartup(vaultcmd.RunVaultMaintenance(ctx, vaultPath, profile, command[1:]))
	case "list":
		if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack list")
		}
		return handledStartup(vaultcmd.RunVaultCommand(ctx, vaultPath, command))
	case "add":
		args := []string{"add", profile}
		if len(command) == 2 && command[1] == "--generate-key" {
			args = append(args, "--generate-key")
		} else if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack [-p PROFILE] add [--generate-key]")
		}
		return handledStartup(vaultcmd.RunVaultCommand(ctx, vaultPath, args))
	case "show", "edit", "remove":
		if len(command) != 1 {
			return 1, true, errors.New("select a profile with -p PROFILE before the command")
		}
		return handledStartup(vaultcmd.RunVaultCommand(ctx, vaultPath, []string{command[0], profile}))
	case "key":
		if len(command) == 2 && command[1] == "public" {
			return handledStartup(vaultcmd.RunVaultCommand(ctx, vaultPath, []string{"public", profile}))
		}
		if len(command) == 3 && (command[1] == "import" || command[1] == "export") {
			return handledStartup(vaultcmd.RunVaultCommand(ctx, vaultPath, []string{command[1], profile, command[2]}))
		}
		return 1, true, errors.New("usage: ssjack [-p PROFILE] key public | import FILE | export FILE")
	case "policy":
		return handledStartup(vaultcmd.RunPolicy(ctx, vaultPath, profile, command[1:]))
	case "doctor":
		if len(command) != 1 {
			return 1, true, errors.New("usage: ssjack doctor")
		}
		return handledStartup(vaultcmd.RunSafetyCommand(ctx, vaultPath, command))
	case "check", "rotate":
		if len(command) != 1 {
			return 1, true, errors.New("select a profile with -p PROFILE before the command")
		}
		return handledStartup(vaultcmd.RunSafetyCommand(ctx, vaultPath, []string{command[0], profile}))
	case "hostkey":
		if len(command) == 2 && command[1] == "show" {
			return handledStartup(vaultcmd.RunSafetyCommand(ctx, vaultPath, []string{"hostkey", "show", profile}))
		}
		if len(command) == 3 && command[1] == "replace" {
			return handledStartup(vaultcmd.RunSafetyCommand(ctx, vaultPath, []string{"hostkey", "replace", profile, command[2]}))
		}
		return 1, true, errors.New("usage: ssjack [-p PROFILE] hostkey show | replace FILE")
	}
	return 0, false, nil
}
