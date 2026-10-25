package main

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/remote"
	"storagehost/internal/vault"
)

func chooseCredential(v *vault.Vault, name string, choose func([]string) (string, error)) (string, error) {
	if name == "" {
		var names []string
		for candidate := range v.Targets {
			names = append(names, candidate)
		}
		sort.Strings(names)
		if len(names) == 0 {
			return "", errors.New("vault has no credentials; add a record with ssjack vault add <name>")
		}
		if len(names) == 1 {
			name = names[0]
		} else {
			var err error
			name, err = choose(names)
			if err != nil {
				return "", err
			}
		}
	}
	if err := vault.ValidateName(name); err != nil {
		return "", err
	}
	if _, exists := v.Targets[name]; !exists {
		return "", errors.New("named credentials do not exist in the vault")
	}
	return name, nil
}

func readVaultCredential(path, name, usage string) (*ssh.ClientConfig, string, string, error) {
	if name != "" {
		if err := vault.ValidateName(name); err != nil {
			return nil, "", "", err
		}
	}
	secret, err := readSecret("Vault secret: ")
	if err != nil {
		return nil, "", "", err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return nil, "", "", err
	}
	defer v.Close()
	name, err = chooseCredential(v, name, func(names []string) (string, error) {
		fmt.Fprintln(os.Stderr, "Available credentials:")
		for _, candidate := range names {
			fmt.Fprintln(os.Stderr, " ", candidate)
		}
		return credentialField("Credential name", "", false)
	})
	if err != nil {
		return nil, "", "", err
	}
	target := v.Targets[name]
	if usage != "" {
		if err := target.RequireUsage(usage); err != nil {
			return nil, "", "", err
		}
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", "", err
	}
	fmt.Fprintln(os.Stderr, "Using credentials:", name)
	return config, target.Address, name, nil
}

func loadAgentCredentials(path, name, legacyConfig string) (remote.Runner, []string, error) {
	if legacyConfig == "" {
		config, address, selected, err := readVaultCredential(path, name, "agent")
		if err != nil {
			return nil, nil, err
		}
		runner, err := remote.NewCredentialRunner(selected, address, config)
		return runner, []string{selected}, err
	}
	if name != "" {
		return nil, nil, errors.New("named run credentials and legacy --config cannot be combined")
	}
	config, err := remote.LoadConfig(legacyConfig)
	if err != nil {
		return nil, nil, err
	}
	secret, err := readSecret("Legacy SSH key passphrase: ")
	if err != nil {
		return nil, nil, err
	}
	signers, err := remote.Unlock(config, secret)
	clear(secret)
	if err != nil {
		return nil, nil, err
	}
	runner, err := remote.NewSSHRunner(config, signers)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for candidate := range config.Targets {
		names = append(names, candidate)
	}
	sort.Strings(names)
	return runner, names, nil
}
