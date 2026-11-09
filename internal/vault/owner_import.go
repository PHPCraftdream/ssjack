package vault

import (
	"bytes"
	"errors"
	"sort"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

// ErrImportInvalid is deliberately generic: it never carries archive content.
var ErrImportInvalid = errors.New("owner archive database is invalid for import")

const maxImportValue = 16384

type ImportAccount struct {
	Name, User, Authentication, Usage string
}

type ImportServer struct {
	ID, Name, Address string
	Fingerprints      []string
	Accounts          []ImportAccount
	Proxy             sshproxy.Metadata
}

// ImportSecret describes one value by metadata and length only.
type ImportSecret struct {
	AliasID, Name, ServerID, ServerName string
	Length                              int
}

type ImportPreview struct {
	Encrypted bool
	Servers   []ImportServer
	Secrets   []ImportSecret
	RemoteMCP mcpdirectory.Metadata
	// Conflicts holds only archive-intrinsic problems (value-unsupported);
	// Session.ImportConflicts returns the complete set including these.
	Conflicts []ImportConflict
}

type importSecret struct {
	aliasID, name, serverID string
	value                   []byte
	supported               bool
}

// OwnerImport privately owns copied credentials and secret values. It has no
// generic getters; only the narrow methods below expose anything.
type OwnerImport struct {
	encrypted bool
	servers   map[string]Server
	targets   map[string]Target
	remoteMCP *mcpdirectory.Directory
	secrets   []importSecret // preview order
	closed    bool
}

// importableValue: the owner store delivers and records values as text, so
// bytes outside valid UTF-8 or containing NUL fit under no media label.
func importableValue(value []byte) bool {
	return utf8.Valid(value) && bytes.IndexByte(value, 0) < 0
}

// ParseOwnerImport deep-copies everything it needs; the caller still closes
// opened. Archived secret refs are intentionally dropped.
func ParseOwnerImport(opened *ownerarchive.Opened) (*OwnerImport, error) {
	if opened == nil {
		return nil, ErrImportInvalid
	}
	parsed, err := unmarshal(opened.Database())
	if err != nil {
		return nil, ErrImportInvalid
	}
	defer parsed.Close()
	ids := opened.SecretIDs()
	if parsed.Version != 2 || parsed.OwnerStore != nil || len(ids) != len(parsed.Secrets) {
		return nil, ErrImportInvalid
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, bound := parsed.Secrets[id]; !bound || seen[id] {
			return nil, ErrImportInvalid
		}
		seen[id] = true
	}
	result := &OwnerImport{encrypted: opened.Encrypted(), servers: make(map[string]Server, len(parsed.Servers)), targets: make(map[string]Target, len(parsed.Targets))}
	for id, server := range parsed.Servers {
		accounts := make(map[string]string, len(server.Accounts))
		for name, profile := range server.Accounts {
			accounts[name] = profile
		}
		result.servers[id] = Server{Name: server.Name, Accounts: accounts}
	}
	for id, target := range parsed.Targets {
		result.targets[id] = ownTarget(target)
	}
	if parsed.RemoteMCP != nil {
		result.remoteMCP, err = remapImportedMCP(parsed.RemoteMCP, result.targets)
		if err != nil {
			result.Close()
			return nil, ErrImportInvalid
		}
	}
	for _, id := range ids {
		value, exists := opened.Value(id)
		if !exists || len(value) > maxImportValue {
			result.Close()
			return nil, ErrImportInvalid
		}
		binding := parsed.Secrets[id]
		result.secrets = append(result.secrets, importSecret{aliasID: id, name: binding.Name, serverID: binding.ServerID, value: append([]byte{}, value...), supported: importableValue(value)})
	}
	sort.Slice(result.secrets, func(a, b int) bool {
		x, y := result.secrets[a], result.secrets[b]
		if (x.serverID == "") != (y.serverID == "") {
			return x.serverID == ""
		}
		if xs, ys := result.servers[x.serverID].Name, result.servers[y.serverID].Name; xs != ys {
			return xs < ys
		}
		return x.name < y.name
	})
	return result, nil
}

func (i *OwnerImport) live() bool { return i != nil && !i.closed }

// Preview returns owned display data: no credential or value bytes.
func (i *OwnerImport) Preview() ImportPreview {
	preview := ImportPreview{Servers: []ImportServer{}, Secrets: []ImportSecret{}, Conflicts: []ImportConflict{}}
	if !i.live() {
		return preview
	}
	preview.Encrypted = i.encrypted
	if i.remoteMCP != nil {
		preview.RemoteMCP = i.remoteMCP.Metadata()
	}
	for id, server := range i.servers {
		entry := ImportServer{ID: id, Name: server.Name, Fingerprints: []string{}}
		for name, profile := range server.Accounts {
			target := i.targets[profile]
			if entry.Address == "" {
				entry.Address = target.Address
				entry.Proxy = target.Proxy.Metadata()
				for _, encoded := range target.HostKeys {
					if key, err := ParseHostKey([]byte(encoded)); err == nil {
						entry.Fingerprints = append(entry.Fingerprints, ssh.FingerprintSHA256(key))
					}
				}
				sort.Strings(entry.Fingerprints)
			}
			authentication := "key"
			if len(target.Password) != 0 {
				authentication = "password"
			}
			entry.Accounts = append(entry.Accounts, ImportAccount{Name: name, User: target.User, Authentication: authentication, Usage: target.EffectiveUsage()})
		}
		sort.Slice(entry.Accounts, func(a, b int) bool { return entry.Accounts[a].Name < entry.Accounts[b].Name })
		preview.Servers = append(preview.Servers, entry)
	}
	sort.Slice(preview.Servers, func(a, b int) bool { return preview.Servers[a].Name < preview.Servers[b].Name })
	for _, secret := range i.secrets {
		preview.Secrets = append(preview.Secrets, ImportSecret{AliasID: secret.aliasID, Name: secret.name, ServerID: secret.serverID, ServerName: i.servers[secret.serverID].Name, Length: len(secret.value)})
	}
	preview.Conflicts = append(preview.Conflicts, i.valueConflicts()...)
	return preview
}

func (i *OwnerImport) valueConflicts() []ImportConflict {
	var result []ImportConflict
	for _, secret := range i.secrets {
		if !secret.supported {
			result = append(result, ImportConflict{Kind: ConflictValueUnsupported, Subject: secret.name})
		}
	}
	return result
}

func (i *OwnerImport) SecretCount() int {
	if !i.live() {
		return 0
	}
	return len(i.secrets)
}

// SecretChange is only for the private owner coordinator: it hands out a COPY
// of the value inside the returned change, which the caller must clear.
func (i *OwnerImport) SecretChange(index int) (OwnerChange, error) {
	if !i.live() || index < 0 || index >= len(i.secrets) || !i.secrets[index].supported {
		return OwnerChange{}, ErrImportInvalid
	}
	secret := i.secrets[index]
	return OwnerChange{Action: "add", AliasID: secret.aliasID, Name: secret.name, ServerID: secret.serverID, MediaType: "text/plain", Value: append([]byte{}, secret.value...)}, nil
}

// Close is idempotent and nil-safe.
func (i *OwnerImport) Close() {
	if i == nil || i.closed {
		return
	}
	for id, target := range i.targets {
		clear(target.PrivateKey)
		clear(target.Password)
		target.Proxy.Clear()
		delete(i.targets, id)
	}
	for _, secret := range i.secrets {
		clear(secret.value)
	}
	i.remoteMCP.Clear()
	i.remoteMCP = nil
	i.secrets, i.servers, i.closed = nil, nil, true
}
