package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/remote"
	"storagehost/internal/vault"
)

func chooseCredential(v *vault.Vault, name string) (string, error) {
	if name == "" {
		name = "main"
	}
	if err := vault.ValidateName(name); err != nil {
		return "", err
	}
	if _, exists := v.Targets[name]; !exists {
		return "", errors.New("selected profile does not exist; create it with ssjack -p NAME add")
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
	name, err = chooseCredential(v, name)
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

func loadAgentCredentials(path, name string) (remote.Runner, []string, error) {
	config, address, selected, err := readVaultCredential(path, name, "agent")
	if err != nil {
		return nil, nil, err
	}
	runner, err := remote.NewCredentialRunner(selected, address, config)
	return runner, []string{selected}, err
}
