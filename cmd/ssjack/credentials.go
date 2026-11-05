package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func chooseCredential(v *vault.Vault, name string) (string, error) {
	if name == "" {
		name = "main"
	}
	server, account, named, err := parseCredentialSelection(name)
	if err != nil {
		return "", err
	}
	if named {
		return resolveNamedCredential(v, server, account)
	}
	if _, exists := v.Targets[name]; !exists {
		return "", errors.New("selected profile does not exist; create it with ssjack -p NAME add")
	}
	return name, nil
}

func readVaultCredential(ctx context.Context, path, name, usage string) (*ssh.ClientConfig, string, string, error) {
	v, config, address, selected, err := openVaultCredential(ctx, path, name, usage)
	if err != nil {
		return nil, "", "", err
	}
	v.Close()
	return config, address, selected, nil
}

func openVaultCredential(ctx context.Context, path, name, usage string) (_ *vault.Vault, _ *ssh.ClientConfig, _ string, _ string, err error) {
	if name != "" {
		if err := validateCredentialSelection(name); err != nil {
			return nil, nil, "", "", err
		}
	}
	secret, err := readVaultPassword(ctx, "Vault secret: ")
	if err != nil {
		return nil, nil, "", "", err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return nil, nil, "", "", err
	}
	defer func() {
		if err != nil {
			v.Close()
		}
	}()
	name, err = chooseCredential(v, name)
	if err != nil {
		return nil, nil, "", "", err
	}
	target := v.Targets[name]
	if usage != "" {
		if err := target.RequireUsage(usage); err != nil {
			return nil, nil, "", "", err
		}
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, nil, "", "", err
	}
	fmt.Fprintln(os.Stderr, "Using credentials:", name)
	return v, config, target.Address, name, nil
}

func loadAgentCredentials(ctx context.Context, path, name string) (*agentCredentials, error) {
	v, config, address, selected, err := openVaultCredential(ctx, path, name, "agent")
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			v.Close()
		}
	}()
	runner, err := remote.NewCredentialRunner(selected, address, config)
	if err != nil {
		return nil, err
	}
	stream, err := remote.NewCredentialStreamRunner(selected, address, config)
	if err != nil {
		return nil, err
	}
	credentials := &agentCredentials{runner: runner, stream: stream, targets: []string{selected}}
	if v.Version == 2 {
		owner, err := ownerdb.Adopt(ctx, path, v)
		if err != nil {
			return nil, err
		}
		credentials.owner, adopted = owner, true
	}
	return credentials, nil
}
