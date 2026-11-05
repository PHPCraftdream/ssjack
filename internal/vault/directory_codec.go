package vault

import (
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

func directoryRecords(v *Vault) (map[string]any, map[string]any) {
	servers, secrets := make(map[string]any), make(map[string]any)
	for id, server := range v.Servers {
		accounts := make(map[string]any)
		for name, profile := range server.Accounts {
			accounts[name] = profile
		}
		servers[id] = map[string]any{"name": server.Name, "accounts": accounts}
	}
	for id, secret := range v.Secrets {
		secrets[id] = map[string]any{"name": secret.Name, "server_id": secret.ServerID, "ref": secret.Ref}
	}
	return servers, secrets
}

func validateDirectoryFields(root map[string]any) error {
	for key := range root {
		switch key {
		case "version", "targets", "servers", "secrets", "owner_store", "remote_mcp":
		default:
			return errors.New("unknown vault field")
		}
	}
	if value, exists := root["owner_store"]; exists {
		if err := validateOwnerStoreFields(value); err != nil {
			return err
		}
	}
	if value, exists := root["remote_mcp"]; exists {
		if err := mcpdirectory.ValidateFields(value); err != nil {
			return err
		}
	}
	if len(root) == 2 {
		return nil
	}
	servers, ok := root["servers"].(map[string]any)
	if !ok || len(servers) > 64 {
		return errors.New("invalid servers directory")
	}
	secrets, ok := root["secrets"].(map[string]any)
	if !ok || len(secrets) > 128 {
		return errors.New("invalid secrets directory")
	}
	for _, value := range servers {
		server, ok := value.(map[string]any)
		if !ok || len(server) != 2 || server["name"] == nil {
			return errors.New("invalid server fields")
		}
		accounts, ok := server["accounts"].(map[string]any)
		if !ok || len(accounts) == 0 || len(accounts) > 64 {
			return errors.New("invalid account fields")
		}
		for _, profile := range accounts {
			if _, ok := profile.(string); !ok {
				return errors.New("invalid account profile")
			}
		}
	}
	for _, value := range secrets {
		secret, ok := value.(map[string]any)
		if !ok || len(secret) != 3 {
			return errors.New("invalid named secret fields")
		}
		for _, field := range []string{"name", "server_id", "ref"} {
			if _, ok := secret[field].(string); !ok {
				return errors.New("invalid named secret field type")
			}
		}
	}
	return nil
}
