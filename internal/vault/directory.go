package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

// Server IDs survive renames; accounts refer to existing credential records.
type Server struct {
	Name     string            `json:"name"`
	Accounts map[string]string `json:"accounts"`
}

// SecretBinding names exact metadata, not secret values or access permissions.
type SecretBinding struct {
	Name     string `json:"name"`
	ServerID string `json:"server_id"`
	Ref      string `json:"ref"`
}

func directoryID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	if id == ([16]byte{}) {
		return "", errors.New("invalid generated directory identity")
	}
	return hex.EncodeToString(id[:]), nil
}

func validDirectoryID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id && !bytes.Equal(decoded, make([]byte, 16))
}

func (v *Vault) validateDirectory() error {
	if v.Servers == nil || v.Secrets == nil || len(v.Servers) > 64 || len(v.Secrets) > 128 {
		return errors.New("invalid vault directory bounds")
	}
	names, credentials := make(map[string]bool), make(map[string]bool)
	for id, server := range v.Servers {
		if !validDirectoryID(id) || ValidateName(server.Name) != nil || names[server.Name] || len(server.Accounts) == 0 || len(server.Accounts) > 64 {
			return errors.New("invalid or duplicate server")
		}
		names[server.Name] = true
		var first *Target
		for name, profile := range server.Accounts {
			target, exists := v.Targets[profile]
			if ValidateName(name) != nil || !exists || credentials[profile] {
				return errors.New("invalid or multiply assigned server account")
			}
			credentials[profile] = true
			if first != nil && (first.Address != target.Address || !sameHostKeys(first.HostKeys, target.HostKeys) || !sshproxy.Equal(first.Proxy, target.Proxy)) {
				return errors.New("server accounts must share address, verified host keys and proxy settings")
			}
			copy := target
			first = &copy
		}
	}
	if len(credentials) != len(v.Targets) {
		return errors.New("unassigned credential record")
	}
	scopedNames := make(map[string]bool)
	for id, secret := range v.Secrets {
		if !validDirectoryID(id) || ValidateName(secret.Name) != nil {
			return errors.New("invalid named secret")
		}
		if secret.ServerID != "" {
			if _, exists := v.Servers[secret.ServerID]; !exists {
				return errors.New("secret refers to an unknown server")
			}
		}
		key := secret.ServerID + "/" + secret.Name
		if scopedNames[key] {
			return errors.New("duplicate secret name in scope")
		}
		scopedNames[key] = true
		reference, err := appstoreplaceholder.Parse([]byte(secret.Ref))
		if err != nil {
			return errors.New("invalid named secret reference")
		}
		canonical, err := appstoreplaceholder.Encode(reference)
		if err != nil || string(canonical) != secret.Ref {
			return errors.New("named secret reference must be canonical")
		}
	}
	return nil
}

func sameHostKeys(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// NewDirectory creates an empty current-schema database.
func NewDirectory() *Vault {
	return &Vault{Version: 2, Targets: make(map[string]Target), Servers: make(map[string]Server), Secrets: make(map[string]SecretBinding)}
}

// InitializeDirectory installs the first account in an empty database.
func (v *Vault) InitializeDirectory(name string, target Target) error {
	if err := v.validate(); err != nil {
		return err
	}
	if len(v.Targets) != 0 || len(v.Servers) != 0 || len(v.Secrets) != 0 || v.OwnerStore != nil || v.RemoteMCP != nil {
		return errors.New("directory initialization requires an empty database")
	}
	id, err := directoryID()
	if err != nil {
		return err
	}
	candidate := NewDirectory()
	candidate.Targets[name] = ownTarget(target)
	candidate.Servers[id] = Server{Name: name, Accounts: map[string]string{"main": name}}
	if err := candidate.validate(); err != nil {
		candidate.Close()
		return err
	}
	v.Version, v.Targets, v.Servers, v.Secrets = candidate.Version, candidate.Targets, candidate.Servers, candidate.Secrets
	return nil
}

func (v *Vault) ServerID(name string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	for id, server := range v.Servers {
		if server.Name == name {
			return id, nil
		}
	}
	return "", errors.New("server does not exist")
}

// AccountProfile returns a credential name, never credential bytes.
func (v *Vault) AccountProfile(serverID, account string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	server, exists := v.Servers[serverID]
	if !exists {
		return "", errors.New("server does not exist")
	}
	profile, exists := server.Accounts[account]
	if !exists {
		return "", errors.New("server account does not exist")
	}
	return profile, nil
}

// NamedReference uses an explicit scope; local names never shadow global names.
func (v *Vault) NamedReference(serverID, name string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	if serverID != "" {
		if _, exists := v.Servers[serverID]; !exists {
			return "", errors.New("server does not exist")
		}
	}
	for _, secret := range v.Secrets {
		if secret.ServerID == serverID && secret.Name == name {
			return secret.Ref, nil
		}
	}
	return "", errors.New("named secret does not exist in selected scope")
}
