package credential

import (
	"errors"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func ChooseCredential(v *vault.Vault, name string) (string, error) {
	if name == "" {
		name = "main"
	}
	server, account, named, err := ParseCredentialSelection(name)
	if err != nil {
		return "", err
	}
	if named {
		return ResolveNamedCredential(v, server, account)
	}
	if _, exists := v.Targets[name]; !exists {
		return "", errors.New("selected profile does not exist; create it with ssjack -p NAME add")
	}
	return name, nil
}

func ParseCredentialSelection(name string) (server, account string, named bool, err error) {
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

func ValidateCredentialSelection(name string) error {
	_, _, _, err := ParseCredentialSelection(name)
	return err
}

func ResolveNamedCredential(v *vault.Vault, server, account string) (string, error) {
	if v.Version != 2 {
		return "", errors.New("named server selection requires directory payload schema v2")
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
