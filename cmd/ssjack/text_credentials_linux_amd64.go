//go:build linux && amd64

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// credentialIdentity hashes stable public credential identity, never vault bytes.
func credentialIdentity(profile string, target vault.Target) (string, error) {
	if target.Proxy != nil {
		return "", errors.New("proxied credentials require a private owner binding")
	}
	key, err := ssh.ParsePrivateKey(target.PrivateKey)
	if err != nil {
		return "", errors.New("invalid credential key")
	}
	pins := append([]string(nil), target.HostKeys...)
	for i := range pins {
		for j := i + 1; j < len(pins); j++ {
			if pins[j] < pins[i] {
				pins[i], pins[j] = pins[j], pins[i]
			}
		}
	}
	identity := struct {
		Profile  string   `json:"profile"`
		Address  string   `json:"address"`
		User     string   `json:"user"`
		HostKeys []string `json:"host_keys"`
		Signer   string   `json:"ssh_signer_fingerprint"`
	}{profile, target.Address, target.User, pins, ssh.FingerprintSHA256(key.PublicKey())}
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", errors.New("cannot encode credential identity")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", errors.New("cannot canonicalize credential identity")
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func readVaultTextCredential(ctx context.Context, path, profile string) (remote.StreamRunner, string, string, error) {
	v, runner, selected, digest, err := openVaultTextCredential(ctx, path, profile)
	if err != nil {
		return nil, "", "", err
	}
	v.Close()
	return runner, selected, digest, nil
}

func openVaultTextCredential(ctx context.Context, path, profile string) (*vault.Vault, remote.StreamRunner, string, string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, nil, "", "", errors.New("text-adapter credentials require a trusted input terminal")
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
	runner, selected, digest, err := textCredentialFromVault(v, profile)
	if err != nil {
		v.Close()
		return nil, nil, "", "", err
	}
	return v, runner, selected, digest, nil
}

func textCredentialFromVault(v *vault.Vault, profile string) (remote.StreamRunner, string, string, error) {
	selected, err := chooseCredential(v, profile)
	if err != nil {
		return nil, "", "", err
	}
	target := v.Targets[selected]
	if err = target.RequireUsage("agent"); err != nil {
		return nil, "", "", err
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", "", err
	}
	var digest string
	if target.Proxy != nil {
		digest, err = v.ProxyCredentialIdentity(selected)
	} else if len(target.Password) != 0 {
		digest, err = v.PasswordCredentialIdentity(selected)
	} else {
		digest, err = credentialIdentity(selected, target)
	}
	if err != nil {
		return nil, "", "", err
	}
	runner, err := remote.NewCredentialStreamRunner(selected, target.Address, config)
	if err != nil {
		return nil, "", "", err
	}
	return runner, selected, digest, nil
}
