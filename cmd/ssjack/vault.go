package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/keyfile"
	"storagehost/internal/vault"
)

func validateVaultArgs(args []string) error {
	if len(args) == 1 && (args[0] == "init" || args[0] == "list" || args[0] == "passwd") {
		return nil
	}
	if len(args) == 2 {
		switch args[0] {
		case "add", "edit", "show", "remove", "public":
			return vault.ValidateName(args[1])
		}
	}
	if len(args) == 3 && args[0] == "add" && args[2] == "--generate-key" {
		return vault.ValidateName(args[1])
	}
	if len(args) == 3 && (args[0] == "import" || args[0] == "export") && args[2] != "" {
		return vault.ValidateName(args[1])
	}
	return errors.New("usage: ssjack [--vault <file>] vault init|list|passwd|add <name> [--generate-key]|edit <name>|show <name>|remove <name>|public <name>|import <name> <file>|export <name> <file>")
}

func runVaultCommand(ctx context.Context, path string, args []string) (int, error) {
	if err := validateVaultArgs(args); err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if args[0] == "init" {
		return runInitProfile(ctx, path, "main")
	}
	secret, err := readSecret("Vault secret: ")
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	v, err := vault.Load(path, secret)
	if err != nil {
		return 1, err
	}
	defer v.Close()
	if args[0] == "list" {
		var names []string
		for name := range v.Targets {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintln(os.Stdout, name)
		}
		return 0, nil
	}
	if args[0] == "passwd" {
		newSecret, err := confirmedSecret()
		if err != nil {
			return 1, err
		}
		defer clear(newSecret)
		if err := ctx.Err(); err != nil {
			return 1, err
		}
		if err := vault.SaveContext(ctx, path, v, newSecret); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stderr, "Vault secret changed. Other copies retain their previous protection.")
		return 0, nil
	}
	var generatedPublic []byte
	name := args[1]
	target, exists := v.Targets[name]
	if args[0] != "add" && !exists {
		return 1, errors.New("target does not exist")
	}
	switch args[0] {
	case "show":
		if err := writeProfileSummary(os.Stdout, name, target); err != nil {
			return 1, err
		}
		return 0, nil
	case "public":
		public, err := keyfile.PublicSSH(target.PrivateKey)
		if err != nil {
			return 1, err
		}
		if _, err := os.Stdout.Write(public); err != nil {
			return 1, err
		}
		return 0, nil
	case "export":
		if err := exportVaultKey(ctx, args[2], target.PrivateKey, secret); err != nil {
			return 1, err
		}
		return 0, nil
	case "import":
		private, err := readImportedPrivate(args[2])
		if err != nil {
			return 1, err
		}
		defer clear(private)
		if err := v.ReplaceKey(name, private); err != nil {
			return 1, err
		}
	case "add", "edit":
		if args[0] == "add" && exists {
			return 1, errors.New("target already exists; use vault edit")
		}
		var generatedPrivate []byte
		if args[0] == "add" && len(args) == 3 {
			if err := ctx.Err(); err != nil {
				return 1, err
			}
			generatedPublic, generatedPrivate, err = v.GenerateIdentity()
			if err != nil {
				return 1, err
			}
			defer clear(generatedPrivate)
		}
		updated, err := editVaultTargetWithPrivate(target, exists, generatedPrivate)
		if err != nil {
			return 1, err
		}
		clear(target.PrivateKey)
		v.Targets[name] = updated
	case "remove":
		confirmation, err := readSecret("Type the target name to confirm removal: ")
		if err != nil {
			return 1, err
		}
		confirmed := string(confirmation) == name
		clear(confirmation)
		if !confirmed {
			return 1, errors.New("removal cancelled")
		}
		clear(target.PrivateKey)
		delete(v.Targets, name)
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if err := saveProfileWithInstructions(ctx, func() error { return vault.SaveUnlocked(ctx, path, v) }, os.Stdout, generatedPublic); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Encrypted vault updated. Imported source files were not changed or removed.")
	return 0, nil
}

func credentialField(prompt, previous string, editing bool) (string, error) {
	if editing {
		prompt += " (Enter to keep)"
	}
	value, err := readTerminalInput(prompt+": ", editing)
	if err != nil {
		return "", err
	}
	defer clear(value)
	if len(value) == 0 && editing {
		return previous, nil
	}
	return strings.TrimSpace(string(value)), nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("input file exceeds its limit or could not be read")
	}
	return data, nil
}

func editVaultTarget(target vault.Target, editing bool) (vault.Target, error) {
	return editVaultTargetWithPrivate(target, editing, nil)
}

func editVaultTargetWithPrivate(target vault.Target, editing bool, generated []byte) (vault.Target, error) {
	fmt.Fprintln(os.Stderr, "Credential fields are entered without echo. The server public key must already be verified through a trusted channel.")
	var err error
	target.Address, err = credentialField("SSH address (host:port)", target.Address, editing)
	if err != nil {
		return vault.Target{}, err
	}
	target.User, err = credentialField("SSH user", target.User, editing)
	if err != nil {
		return vault.Target{}, err
	}
	imported := append([]byte(nil), generated...)
	defer func() { clear(imported) }()
	if len(generated) == 0 {
		keyPath, err := credentialField("SSH private key file (OpenSSH, PEM, or ssjack)", "", editing)
		if err != nil {
			return vault.Target{}, err
		}
		if keyPath != "" {
			imported, err = readImportedPrivate(keyPath)
			if err != nil {
				return vault.Target{}, err
			}
		}
	}
	hostPath, err := credentialField("Verified server public key file (.pub)", "", editing)
	if err != nil {
		return vault.Target{}, err
	}
	if hostPath != "" {
		data, err := readBoundedFile(hostPath, 16384)
		if err != nil {
			return vault.Target{}, err
		}
		key, err := vault.ParseHostKey(data)
		clear(data)
		if err != nil {
			return vault.Target{}, err
		}
		target.HostKeys = []string{string(ssh.MarshalAuthorizedKey(key))}
	}
	if imported != nil {
		target.PrivateKey = imported
	}
	usage, err := readTerminalInput("Usage both/human/agent (Enter keeps current or defaults to both): ", true)
	if err != nil {
		return vault.Target{}, err
	}
	if len(usage) != 0 {
		target.Usage = string(usage)
	}
	clear(usage)
	if err := target.Validate(); err != nil {
		return vault.Target{}, err
	}
	target.PrivateKey = append([]byte(nil), target.PrivateKey...)
	return target, nil
}
