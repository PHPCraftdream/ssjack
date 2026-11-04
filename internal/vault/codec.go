package vault

import (
	"errors"
	"fmt"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func marshal(v *Vault) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	records := make(map[string]any, len(v.Targets))
	for name, target := range v.Targets {
		record := map[string]any{"address": target.Address, "user": target.User, "private_key": target.PrivateKey, "host_keys": target.HostKeys}
		if !target.SSHPolicy.Empty() {
			record["ssh_policy"] = target.SSHPolicy
		}
		if target.Usage != "" {
			record["usage"] = target.Usage
		}
		if len(target.Password) != 0 {
			record["password"] = target.Password
		}
		if route := target.Proxy; route != nil {
			proxy := map[string]any{"type": route.Type, "address": route.Address}
			if route.Username != "" {
				proxy["username"], proxy["password"] = route.Username, route.Password
			}
			record["proxy"] = proxy
		}
		records[name] = record
	}
	root := map[string]any{"version": v.Version, "targets": records}
	if v.Version == 2 {
		servers, secrets := directoryRecords(v)
		root["servers"], root["secrets"] = servers, secrets
		if v.OwnerStore != nil {
			root["owner_store"] = ownerStoreRecord(v.OwnerStore)
		}
	}
	body, err := pure.EmitCanonical(root)
	if err != nil {
		return nil, err
	}
	if len(body) > keyfile.MaxPlaintext {
		return nil, errors.New("vault exceeds the 64 KiB plaintext limit")
	}
	return []byte(body), nil
}

func unmarshal(data []byte) (*Vault, error) {
	if len(data) > keyfile.MaxPlaintext {
		return nil, errors.New("vault exceeds the 64 KiB plaintext limit")
	}
	value, err := pure.LoadsStrict(string(data))
	if err != nil {
		return nil, errors.New("invalid vault Ktav")
	}
	root, ok := value.(map[string]any)
	if !ok || (len(root) != 2 && len(root) != 4 && len(root) != 5) || root["version"] == nil {
		return nil, errors.New("invalid vault fields")
	}
	if err := validateDirectoryFields(root); err != nil {
		return nil, err
	}
	targets, ok := root["targets"].(map[string]any)
	if !ok || len(targets) > 64 {
		return nil, errors.New("invalid vault targets")
	}
	for _, value := range targets {
		target, ok := value.(map[string]any)
		if !ok || len(target) < 4 || len(target) > 8 {
			return nil, errors.New("invalid vault target fields")
		}
		for field := range target {
			switch field {
			case "address", "user", "private_key", "password", "host_keys", "usage", "ssh_policy", "proxy":
			default:
				return nil, errors.New("unknown vault target field")
			}
		}
		if value, exists := target["proxy"]; exists {
			if len(root) == 2 || validateProxyFields(value) != nil {
				return nil, errors.New("invalid proxy fields or database version")
			}
		}
		if value, exists := target["ssh_policy"]; exists {
			policy, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid SSH policy")
			}
			for field := range policy {
				switch field {
				case "host_keys", "key_exchanges", "ciphers", "macs":
				default:
					return nil, errors.New("unknown SSH policy field")
				}
			}
		}
		if _, exists := target["password"]; exists && len(root) == 2 {
			return nil, errors.New("password field requires database version 2")
		}
		for _, field := range []string{"address", "user", "private_key", "host_keys"} {
			if _, exists := target[field]; !exists {
				return nil, fmt.Errorf("missing vault target field %q", field)
			}
		}
	}
	var v Vault
	if err := pure.LoadsInto(string(data), &v); err != nil {
		v.Close()
		return nil, errors.New("invalid vault values")
	}
	if err := v.validate(); err != nil {
		v.Close()
		return nil, err
	}
	return &v, nil
}
