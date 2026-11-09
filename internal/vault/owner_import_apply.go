package vault

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

// ErrImportConflict is fixed text; conflict details come from ImportConflicts.
var ErrImportConflict = errors.New("owner import conflicts with the destination database")

// ErrImportChanged is fixed text: the imported directory no longer matches.
var ErrImportChanged = errors.New("imported directory changed")

const (
	ConflictServerID         = "server-id"
	ConflictServerName       = "server-name"
	ConflictAccountID        = "account-id"
	ConflictSecretID         = "secret-id"
	ConflictSecretName       = "secret-name"
	ConflictServerLimit      = "server-limit"
	ConflictAccountLimit     = "account-limit"
	ConflictSecretLimit      = "secret-limit"
	ConflictPendingIntent    = "pending-intent"
	ConflictDirectoryVersion = "directory-version"
	ConflictUnlinkedStore    = "unlinked-store"
	ConflictValueUnsupported = "value-unsupported"
	ConflictMCPServerID      = "mcp-server-id"
	ConflictMCPServerName    = "mcp-server-name"
	ConflictMCPServerURL     = "mcp-server-url"
	ConflictMCPServerLimit   = "mcp-server-limit"
	ConflictMCPAccountID     = "mcp-account-id"
	ConflictMCPAccountName   = "mcp-account-name"
	ConflictMCPAccountLimit  = "mcp-account-limit"
	ConflictMCPLast          = "mcp-last-context"
	ConflictMCPLastLimit     = "mcp-last-context-limit"
)

// ImportConflict is metadata only: Subject is a name or fixed text, never a value.
type ImportConflict struct {
	Kind, Subject string
}

// importConflicts is the single rule set used by preview and by Apply.
func importConflicts(state *Vault, i *OwnerImport) []ImportConflict {
	result := []ImportConflict{}
	result = append(result, i.valueConflicts()...)
	if state.Version != 2 {
		return append(result, ImportConflict{Kind: ConflictDirectoryVersion, Subject: "version 2 directory required"})
	}
	if state.OwnerStore != nil && state.OwnerStore.Pending != nil {
		result = append(result, ImportConflict{Kind: ConflictPendingIntent, Subject: "pending owner intent"})
	}
	if len(i.secrets) > 0 && state.OwnerStore == nil {
		result = append(result, ImportConflict{Kind: ConflictUnlinkedStore, Subject: "owner store is not linked"})
	}
	if len(state.Servers)+len(i.servers) > 64 {
		result = append(result, ImportConflict{Kind: ConflictServerLimit, Subject: "64 servers"})
	}
	if len(state.Targets)+len(i.targets) > 64 {
		result = append(result, ImportConflict{Kind: ConflictAccountLimit, Subject: "64 accounts"})
	}
	if len(state.Secrets)+len(i.secrets) > 128 {
		result = append(result, ImportConflict{Kind: ConflictSecretLimit, Subject: "128 secrets"})
	}
	if i.remoteMCP != nil {
		destination := state.RemoteMCP
		if destination == nil {
			destination = mcpdirectory.New()
		}
		if len(destination.Servers)+len(i.remoteMCP.Servers) > mcpdirectory.MaxServers {
			result = append(result, ImportConflict{Kind: ConflictMCPServerLimit, Subject: "32 remote MCP servers"})
		}
		if len(destination.Accounts)+len(i.remoteMCP.Accounts) > mcpdirectory.MaxAccounts {
			result = append(result, ImportConflict{Kind: ConflictMCPAccountLimit, Subject: "64 remote MCP accounts"})
		}
		if len(destination.Last)+len(i.remoteMCP.Last) > 64 {
			result = append(result, ImportConflict{Kind: ConflictMCPLastLimit, Subject: "64 remote MCP contexts"})
		}
		serverNames, serverURLs := make(map[string]bool), make(map[string]bool)
		for _, server := range destination.Servers {
			serverNames[server.Name], serverURLs[server.URL] = true, true
		}
		for id, server := range i.remoteMCP.Servers {
			if _, exists := destination.Servers[id]; exists {
				result = append(result, ImportConflict{Kind: ConflictMCPServerID, Subject: server.Name})
			}
			if serverNames[server.Name] {
				result = append(result, ImportConflict{Kind: ConflictMCPServerName, Subject: server.Name})
			}
			if serverURLs[server.URL] {
				result = append(result, ImportConflict{Kind: ConflictMCPServerURL, Subject: server.Name})
			}
			serverNames[server.Name] = true
		}
		accountNames := make(map[string]bool, len(destination.Accounts))
		for _, account := range destination.Accounts {
			accountNames[account.ServerID+"/"+account.Name] = true
		}
		for id, account := range i.remoteMCP.Accounts {
			if _, exists := destination.Accounts[id]; exists {
				result = append(result, ImportConflict{Kind: ConflictMCPAccountID, Subject: account.Name})
			}
			key := account.ServerID + "/" + account.Name
			if accountNames[key] {
				result = append(result, ImportConflict{Kind: ConflictMCPAccountName, Subject: account.Name})
			}
			accountNames[key] = true
		}
		for profile := range i.remoteMCP.Last {
			if _, exists := destination.Last[profile]; exists {
				result = append(result, ImportConflict{Kind: ConflictMCPLast, Subject: profile})
			}
		}
	}
	names := make(map[string]bool, len(state.Servers))
	for _, server := range state.Servers {
		names[server.Name] = true
	}
	for id, server := range i.servers {
		if _, exists := state.Servers[id]; exists {
			result = append(result, ImportConflict{Kind: ConflictServerID, Subject: server.Name})
		}
		if names[server.Name] {
			result = append(result, ImportConflict{Kind: ConflictServerName, Subject: server.Name})
		}
		for account, profile := range server.Accounts {
			if _, exists := state.Targets[profile]; exists {
				result = append(result, ImportConflict{Kind: ConflictAccountID, Subject: server.Name + "/" + account})
			}
		}
	}
	scoped := make(map[string]bool, len(state.Secrets))
	for _, binding := range state.Secrets {
		scoped[binding.ServerID+"/"+binding.Name] = true
	}
	for _, secret := range i.secrets {
		if _, exists := state.Secrets[secret.aliasID]; exists {
			result = append(result, ImportConflict{Kind: ConflictSecretID, Subject: secret.name})
		}
		if scoped[secret.serverID+"/"+secret.name] {
			result = append(result, ImportConflict{Kind: ConflictSecretName, Subject: secret.name})
		}
	}
	sort.Slice(result, func(a, b int) bool {
		if result[a].Kind != result[b].Kind {
			return result[a].Kind < result[b].Kind
		}
		return result[a].Subject < result[b].Subject
	})
	return result
}

// ImportConflicts is advisory for previews; an empty slice means importable now.
func (s *Session) ImportConflicts(i *OwnerImport) ([]ImportConflict, error) {
	if s == nil || !i.live() {
		return nil, ErrImportInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil {
		return nil, errors.New("database session is closed")
	}
	return importConflicts(s.state, i), nil
}

// sameImportTarget compares every Target field; nil and empty lists are equal.
func sameImportTarget(a, b Target) bool {
	return a.Address == b.Address && a.User == b.User && a.Usage == b.Usage && sshproxy.Equal(a.Proxy, b.Proxy) &&
		bytes.Equal(a.PrivateKey, b.PrivateKey) && bytes.Equal(a.Password, b.Password) &&
		slices.Equal(a.HostKeys, b.HostKeys) && slices.Equal(a.SSHPolicy.HostKeys, b.SSHPolicy.HostKeys) &&
		slices.Equal(a.SSHPolicy.KeyExchanges, b.SSHPolicy.KeyExchanges) &&
		slices.Equal(a.SSHPolicy.Ciphers, b.SSHPolicy.Ciphers) && slices.Equal(a.SSHPolicy.MACs, b.SSHPolicy.MACs)
}

// VerifyOwnerImportDirectory proves the destination still holds exactly the
// servers, accounts and credentials this import published, so a resumed
// import cannot report success over directory edits made after a failure.
func (s *Session) VerifyOwnerImportDirectory(i *OwnerImport) error {
	if s == nil || !i.live() {
		return ErrImportInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state == nil {
		return errors.New("database session is closed")
	}
	if s.state.Version != 2 {
		return ErrImportChanged
	}
	for id, server := range i.servers {
		current, exists := s.state.Servers[id]
		if !exists || current.Name != server.Name || !maps.Equal(current.Accounts, server.Accounts) {
			return ErrImportChanged
		}
	}
	for id, target := range i.targets {
		current, exists := s.state.Targets[id]
		if !exists || !sameImportTarget(current, target) {
			return ErrImportChanged
		}
	}
	if i.remoteMCP != nil {
		if s.state.RemoteMCP == nil || !sameImportedMCP(s.state.RemoteMCP, i.remoteMCP) {
			return ErrImportChanged
		}
	}
	return nil
}

func sameImportedMCP(current, expected *mcpdirectory.Directory) bool {
	if current == nil || expected == nil {
		return false
	}
	for id, server := range expected.Servers {
		if got, exists := current.Servers[id]; !exists || got != server {
			return false
		}
	}
	for id, account := range expected.Accounts {
		if got, exists := current.Accounts[id]; !exists || !sameMCPAccount(got, account) {
			return false
		}
	}
	for profile, selected := range expected.Last {
		if got, exists := current.Last[profile]; !exists || !slices.Equal(got, selected) {
			return false
		}
	}
	return true
}

func sameMCPAccount(a, b mcpdirectory.Account) bool {
	if a.ServerID != b.ServerID || a.Name != b.Name || a.Enabled != b.Enabled || a.Revision != b.Revision || a.Auth.Kind != b.Auth.Kind || a.Auth.Username != b.Auth.Username || !bytes.Equal(a.Auth.Secret, b.Auth.Secret) || len(a.Headers) != len(b.Headers) {
		return false
	}
	for index := range a.Headers {
		if a.Headers[index].Name != b.Headers[index].Name || !bytes.Equal(a.Headers[index].Value, b.Headers[index].Value) {
			return false
		}
	}
	return true
}

// ApplyOwnerImportDirectory merges servers and credentials in one Apply. It
// never touches secrets or the owner store: values are published later through
// the owner path, which assigns fresh references.
func (s *Session) ApplyOwnerImportDirectory(i *OwnerImport) error {
	if s == nil || !i.live() {
		return ErrImportInvalid
	}
	if len(i.servers) == 0 && i.remoteMCP == nil {
		conflicts, err := s.ImportConflicts(i)
		if err != nil {
			return err
		}
		if len(conflicts) != 0 {
			return ErrImportConflict
		}
		return nil
	}
	return s.Apply(func(candidate *Vault) error {
		// Authoritative re-check against the state Apply is about to replace.
		if len(importConflicts(candidate, i)) != 0 {
			return ErrImportConflict
		}
		for id, server := range i.servers {
			accounts := make(map[string]string, len(server.Accounts))
			for name, profile := range server.Accounts {
				accounts[name] = profile
			}
			candidate.Servers[id] = Server{Name: server.Name, Accounts: accounts}
		}
		for id, target := range i.targets {
			candidate.Targets[id] = ownTarget(target)
		}
		if i.remoteMCP != nil {
			if candidate.RemoteMCP == nil {
				candidate.RemoteMCP = mcpdirectory.New()
			}
			for id, server := range i.remoteMCP.Servers {
				candidate.RemoteMCP.Servers[id] = server
			}
			for id, account := range i.remoteMCP.Accounts {
				candidate.RemoteMCP.Accounts[id] = ownMCPAccount(account)
			}
			for profile, selected := range i.remoteMCP.Last {
				candidate.RemoteMCP.Last[profile] = append([]mcpdirectory.Binding{}, selected...)
			}
		}
		return nil
	})
}
