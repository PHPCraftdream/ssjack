package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func policyList(values []string) string {
	if len(values) == 0 {
		return "<safe compiled defaults>"
	}
	return strings.Join(values, ",")
}

func runPolicy(ctx context.Context, path, profile string, args []string) (int, error) {
	if len(args) != 1 || (args[0] != "show" && args[0] != "edit") {
		return 1, errors.New("usage: ssjack [-p PROFILE] policy show|edit")
	}
	v, secret, err := openManagedVault(path)
	if err != nil {
		return 1, err
	}
	defer clear(secret)
	defer v.Close()
	target, exists := v.Targets[profile]
	if !exists {
		return 1, errors.New("selected profile does not exist")
	}
	if args[0] == "show" {
		fmt.Fprintln(os.Stdout, "Host keys:", policyList(target.SSHPolicy.HostKeys))
		fmt.Fprintln(os.Stdout, "Key exchanges:", policyList(target.SSHPolicy.KeyExchanges))
		fmt.Fprintln(os.Stdout, "Ciphers:", policyList(target.SSHPolicy.Ciphers))
		fmt.Fprintln(os.Stdout, "MACs:", policyList(target.SSHPolicy.MACs))
		return 0, nil
	}
	supported := ssh.SupportedAlgorithms()
	policy := target.SSHPolicy
	fields := []struct {
		name    string
		value   *[]string
		allowed []string
	}{
		{"Host keys", &policy.HostKeys, supported.HostKeys},
		{"Key exchanges", &policy.KeyExchanges, supported.KeyExchanges},
		{"Ciphers", &policy.Ciphers, supported.Ciphers},
		{"MACs", &policy.MACs, supported.MACs},
	}
	fmt.Fprintln(os.Stderr, "Only supported safe SSH algorithms are accepted. Enter keeps the value; type default to reset it. Input is hidden; no policy values are passed in argv.")
	for _, field := range fields {
		fmt.Fprintln(os.Stderr, field.name, "supported:", strings.Join(field.allowed, ","))
		input, err := readTerminalInput(field.name+" preferences: ", true)
		if err != nil {
			return 1, err
		}
		text := strings.TrimSpace(string(input))
		clear(input)
		if text == "" {
			continue
		}
		if text == "default" {
			*field.value = nil
			continue
		}
		values := strings.Split(text, ",")
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		*field.value = values
	}
	if err := v.ReplacePolicy(profile, policy); err != nil {
		return 1, err
	}
	if err := confirmValue("Type the profile name to save this encrypted policy: ", profile); err != nil {
		return 1, err
	}
	if err := vault.SaveUnlocked(ctx, path, v); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Saved SSH algorithm preferences inside the encrypted profile. Server pins and private key were not changed.")
	return 0, nil
}
