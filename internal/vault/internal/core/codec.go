package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

func Marshal(v *Vault) ([]byte, error) {
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
		if v.RemoteMCP != nil {
			root["remote_mcp"] = v.RemoteMCP.Record()
		}
		if v.Rotation != nil {
			root["rotation"] = rotationRecord(v.Rotation)
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

func Unmarshal(data []byte) (*Vault, error) {
	if len(data) > keyfile.MaxPlaintext {
		return nil, errors.New("vault exceeds the 64 KiB plaintext limit")
	}
	value, err := pure.LoadsStrict(string(data))
	if err != nil {
		return nil, errors.New("invalid vault Ktav")
	}
	root, ok := value.(map[string]any)
	if !ok || (len(root) != 2 && len(root) != 4 && len(root) != 5 && len(root) != 6 && len(root) != 7) || root["version"] == nil {
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

func rotationRecord(j *RotationJournal) map[string]any {
	original := rotationTargetRecord(j.Original)
	newPrivate, newPublic, oldPublic := j.NewPrivate, j.NewPublic, j.OldPublic
	if j.Phase == RotationCancelled || j.Phase == RotationArchived {
		original, newPrivate, newPublic, oldPublic = map[string]any{}, nil, nil, nil
	}
	return map[string]any{
		"id": j.ID, "plan_id": j.PlanID, "base_revision": j.BaseRevision,
		"phase": j.Phase, "server_id": j.ServerID, "account": j.Account,
		"profile": j.Profile, "original": original,
		"new_private": newPrivate, "new_public": newPublic,
		"old_public": oldPublic, "commit_revision": j.CommitRevision,
		"commit_digest": j.CommitDigest, "recovery_path": j.RecoveryPath,
		"recovery_digest": j.RecoveryDigest,
	}
}

func rotationTargetRecord(target Target) map[string]any {
	record := map[string]any{
		"address": target.Address, "user": target.User,
		"private_key": target.PrivateKey, "host_keys": target.HostKeys,
	}
	if !target.SSHPolicy.Empty() {
		record["ssh_policy"] = map[string]any{
			"host_keys":     target.SSHPolicy.HostKeys,
			"key_exchanges": target.SSHPolicy.KeyExchanges,
			"ciphers":       target.SSHPolicy.Ciphers,
			"macs":          target.SSHPolicy.MACs,
		}
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
	return record
}

func validateRotationRecord(value any) error {
	journal, ok := value.(map[string]any)
	if !ok || len(journal) != 15 {
		return errors.New("invalid pending key rotation fields")
	}
	for _, field := range []string{"id", "plan_id", "base_revision", "phase", "server_id", "account", "profile", "original", "new_private", "new_public", "old_public", "commit_revision", "commit_digest", "recovery_path", "recovery_digest"} {
		if _, exists := journal[field]; !exists {
			return errors.New("missing pending key rotation field")
		}
	}
	for _, field := range []string{"id", "phase", "server_id", "account", "profile", "commit_digest", "recovery_path", "recovery_digest"} {
		if _, ok := journal[field].(string); !ok {
			return errors.New("invalid key rotation text field")
		}
	}
	for _, field := range []string{"plan_id", "base_revision", "commit_revision"} {
		if !rotationInteger(journal[field]) {
			return errors.New("invalid key rotation revision or plan id")
		}
	}
	for _, field := range []string{"new_private", "new_public", "old_public"} {
		if raw := journal[field]; raw != nil {
			switch raw.(type) {
			case string, []byte:
			default:
				return errors.New("invalid key rotation key material")
			}
		}
	}
	target, ok := journal["original"].(map[string]any)
	if !ok {
		return errors.New("invalid key rotation target")
	}
	if journal["phase"] == RotationCancelled || journal["phase"] == RotationArchived {
		if len(target) != 0 {
			return errors.New("terminal key rotation has a target")
		}
		for _, field := range []string{"new_private", "new_public", "old_public"} {
			if len(rotationBytes(journal[field])) != 0 {
				return errors.New("terminal key rotation retains key material")
			}
		}
		return nil
	}
	if len(target) < 4 || len(target) > 8 {
		return errors.New("invalid key rotation target")
	}
	for key := range target {
		switch key {
		case "address", "user", "private_key", "password", "host_keys", "usage", "ssh_policy", "proxy":
		default:
			return errors.New("unknown key rotation target field")
		}
	}
	for _, key := range []string{"address", "user", "private_key", "host_keys"} {
		if _, exists := target[key]; !exists {
			return errors.New("incomplete key rotation target")
		}
	}
	for _, field := range []string{"address", "user"} {
		if _, ok := target[field].(string); !ok {
			return errors.New("invalid key rotation target text")
		}
	}
	if raw := target["private_key"]; raw != nil {
		switch raw.(type) {
		case string, []byte:
		default:
			return errors.New("invalid key rotation target key")
		}
	}
	if raw := target["host_keys"]; raw != nil {
		values, ok := raw.([]any)
		if !ok || !rotationStringArray(values) {
			return errors.New("invalid key rotation host keys")
		}
	}
	if raw, exists := target["password"]; exists && raw != nil {
		switch raw.(type) {
		case string, []byte:
		default:
			return errors.New("invalid key rotation password")
		}
	}
	if raw, exists := target["usage"]; exists {
		if _, ok := raw.(string); !ok {
			return errors.New("invalid key rotation usage")
		}
	}
	if policy, exists := target["ssh_policy"]; exists {
		fields, ok := policy.(map[string]any)
		if !ok {
			return errors.New("invalid rotation SSH policy")
		}
		for key, raw := range fields {
			switch key {
			case "host_keys", "key_exchanges", "ciphers", "macs":
				if !rotationStringArrayValue(raw) {
					return errors.New("invalid rotation SSH policy list")
				}
			default:
				return errors.New("unknown rotation SSH policy field")
			}
		}
	}
	if proxy, exists := target["proxy"]; exists {
		if err := validateProxyFields(proxy); err != nil {
			return sshproxy.ErrConfig
		}
	}
	return nil
}

func rotationBytes(value any) []byte {
	switch bytes := value.(type) {
	case string:
		return []byte(bytes)
	case []byte:
		return bytes
	default:
		return nil
	}
}

func rotationInteger(value any) bool {
	switch number := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case *big.Int:
		return number != nil
	case big.Int:
		return true
	default:
		return false
	}
}

func rotationStringArray(values []any) bool {
	for _, value := range values {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	return true
}

func rotationStringArrayValue(value any) bool {
	if value == nil {
		return true
	}
	values, ok := value.([]any)
	return ok && rotationStringArray(values)
}

func validateDirectoryFields(root map[string]any) error {
	for key := range root {
		switch key {
		case "version", "targets", "servers", "secrets", "owner_store", "remote_mcp", "rotation":
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
	if value, exists := root["rotation"]; exists {
		if err := validateRotationRecord(value); err != nil {
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

func validateProxyFields(value any) error {
	fields, ok := value.(map[string]any)
	if !ok || (len(fields) != 2 && len(fields) != 4) {
		return sshproxy.ErrConfig
	}
	for field := range fields {
		switch field {
		case "type", "address", "username", "password":
		default:
			return sshproxy.ErrConfig
		}
	}
	if fields["type"] == nil || fields["address"] == nil {
		return sshproxy.ErrConfig
	}
	_, user := fields["username"]
	_, password := fields["password"]
	if user != password || (user && (fields["username"] == nil || fields["password"] == nil)) {
		return sshproxy.ErrConfig
	}
	return nil
}

func ownerStoreRecord(owner *OwnerStore) map[string]any {
	var pending any
	if owner.Pending != nil {
		p := owner.Pending
		versions := make(map[string]any)
		for object, version := range p.Versions {
			versions[object] = version
		}
		c := p.Change
		change := map[string]any{"action": c.Action, "alias_id": c.AliasID, "name": c.Name, "server_id": c.ServerID, "object_id": c.ObjectID, "previous_ref": c.PreviousReference, "media_type": c.MediaType, "value": c.Value}
		pending = map[string]any{"id": p.ID, "phase": p.Phase, "transaction_id": p.TransactionID, "snapshot_id": p.SnapshotID, "previous_state_hash": p.PreviousStateHash, "versions": versions, "change": change}
	}
	return map[string]any{"directory": owner.Directory, "store_id": owner.StoreID, "master": owner.Master, "pending": pending}
}

func ownerFields(value any, fields ...string) (map[string]any, error) {
	record, ok := value.(map[string]any)
	if !ok || len(record) != len(fields) {
		return nil, errors.New("invalid closed owner-store fields")
	}
	for _, field := range fields {
		if _, exists := record[field]; !exists {
			return nil, errors.New("missing owner-store field")
		}
	}
	return record, nil
}

func ownerStringFields(record map[string]any, fields ...string) error {
	for _, field := range fields {
		if _, ok := record[field].(string); !ok {
			return errors.New("invalid owner-store string field")
		}
	}
	return nil
}

func validateOwnerStoreFields(value any) error {
	owner, err := ownerFields(value, "directory", "store_id", "master", "pending")
	if err != nil {
		return err
	}
	if err := ownerStringFields(owner, "directory", "store_id"); err != nil {
		return err
	}
	if owner["master"] == nil {
		return errors.New("owner-store unlock material is missing")
	}
	if owner["pending"] == nil {
		return nil
	}
	pending, err := ownerFields(owner["pending"], "id", "phase", "transaction_id", "snapshot_id", "previous_state_hash", "versions", "change")
	if err != nil {
		return err
	}
	if err := ownerStringFields(pending, "id", "phase", "transaction_id", "snapshot_id", "previous_state_hash"); err != nil {
		return err
	}
	versions, ok := pending["versions"].(map[string]any)
	if !ok || len(versions) > 128 {
		return errors.New("invalid owner-store version set")
	}
	for _, version := range versions {
		if _, ok := version.(string); !ok {
			return errors.New("invalid owner-store version value")
		}
	}
	change, err := ownerFields(pending["change"], "action", "alias_id", "name", "server_id", "object_id", "previous_ref", "media_type", "value")
	if err != nil {
		return err
	}
	return ownerStringFields(change, "action", "alias_id", "name", "server_id", "object_id", "previous_ref", "media_type")
}
