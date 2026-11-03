package main

import (
	"errors"
	"flag"
	"strings"

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

func parseCredentialSelection(name string) (server, account string, named bool, err error) {
	if !strings.HasPrefix(name, "@") {
		return "", "", false, vault.ValidateName(name)
	}
	parts := strings.Split(name[1:], "/")
	if len(parts) > 2 {
		return "", "", true, errors.New("invalid internal named selection")
	}
	if err := vault.ValidateName(parts[0]); err != nil {
		return "", "", true, err
	}
	if len(parts) == 2 {
		if err := vault.ValidateName(parts[1]); err != nil {
			return "", "", true, err
		}
		account = parts[1]
	}
	return parts[0], account, true, nil
}

func validateCredentialSelection(name string) error {
	_, _, _, err := parseCredentialSelection(name)
	return err
}

func resolveNamedCredential(v *vault.Vault, server, account string) (string, error) {
	if v.Version != 2 {
		return "", errors.New("named server selection requires explicit vault migrate-directory")
	}
	id, err := v.ServerID(server)
	if err != nil {
		return "", errors.New("selected named server does not exist")
	}
	if account == "" {
		accounts := v.Servers[id].Accounts
		if len(accounts) != 1 {
			return "", errors.New("server has multiple SSH accounts; specify --account NAME or use --interactive")
		}
		for name := range accounts {
			account = name
		}
	}
	profile, err := v.AccountProfile(id, account)
	if err != nil {
		return "", errors.New("selected named SSH account does not exist")
	}
	return profile, nil
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
		case "register", "register-reverse", "revoke", "register-stream", "revoke-stream":
			return false
		}
	}
	switch command[0] {
	case "vault", "list", "add", "show", "edit", "remove", "key", "policy", "doctor", "hostkey", "appstore", "mcp", "declarative", "hook", "install-hooks":
		return false
	}
	return true
}
