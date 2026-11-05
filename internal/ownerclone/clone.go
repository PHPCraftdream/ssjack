// Package ownerclone copies caller-owned owner state without reading a database.
package ownerclone

import "github.com/PHPCraftdream/ssjack/internal/vault"

func Link(link *vault.OwnerStore) *vault.OwnerStore {
	if link == nil {
		return nil
	}
	copy := *link
	copy.Master = append([]byte(nil), link.Master...)
	copy.Pending = Intent(link.Pending)
	return &copy
}

func ClearLink(link *vault.OwnerStore) {
	if link != nil {
		clear(link.Master)
		if link.Pending != nil {
			clear(link.Pending.Change.Value)
		}
	}
}

func Intent(pending *vault.OwnerIntent) *vault.OwnerIntent {
	if pending == nil {
		return nil
	}
	copy := *pending
	copy.Change.Value = append([]byte{}, pending.Change.Value...)
	copy.Versions = make(map[string]string, len(pending.Versions))
	for object, version := range pending.Versions {
		copy.Versions[object] = version
	}
	return &copy
}

func Preview(p vault.ImportPreview) vault.ImportPreview {
	out := vault.ImportPreview{Encrypted: p.Encrypted, Servers: make([]vault.ImportServer, 0, len(p.Servers)), Secrets: append([]vault.ImportSecret{}, p.Secrets...), Conflicts: append([]vault.ImportConflict{}, p.Conflicts...)}
	for _, server := range p.Servers {
		server.Fingerprints = append([]string{}, server.Fingerprints...)
		server.Accounts = append([]vault.ImportAccount(nil), server.Accounts...)
		out.Servers = append(out.Servers, server)
	}
	return out
}
