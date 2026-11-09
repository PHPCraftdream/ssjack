package vault

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
)

type ExportSelection struct {
	Servers       map[string][]string
	GlobalSecrets bool
	RemoteMCP     []mcpdirectory.Binding
}

// Validate checks selection shape without revealing record contents.
func (s ExportSelection) Validate() error {
	if len(s.RemoteMCP) > mcpdirectory.MaxAccounts {
		return errors.New("invalid remote MCP export selection")
	}
	seen := make(map[string]bool, len(s.RemoteMCP))
	servers := make(map[string]bool, len(s.RemoteMCP))
	for _, binding := range s.RemoteMCP {
		if !validDirectoryID(binding.ServerID) || !validDirectoryID(binding.AccountID) || binding.ServerRevision == 0 || binding.AccountRevision == 0 || seen[binding.AccountID] {
			return errors.New("invalid remote MCP export selection")
		}
		seen[binding.AccountID] = true
		servers[binding.ServerID] = true
	}
	if len(servers) > mcpdirectory.MaxServers {
		return errors.New("invalid remote MCP export selection")
	}
	return nil
}

type OwnerExportPlan struct {
	source   *Session
	revision uint64
	archive  *ownerarchive.Archive
	bindings map[string]SecretBinding
	closed   bool
}

func (s *Session) PrepareOwnerExport(selection ExportSelection) (*OwnerExportPlan, error) {
	if s == nil {
		return nil, errors.New("owner export requires an authenticated session")
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.state == nil || s.state.Version != 2 || s.saveErr != nil || s.saved != s.revision || (s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil) {
		return nil, errors.New("save or reconcile the owner database before exporting")
	}
	if len(selection.Servers) == 0 && !selection.GlobalSecrets && len(selection.RemoteMCP) == 0 {
		return nil, errors.New("select an explicit owner export scope")
	}
	selected := &Vault{Version: 2, Targets: make(map[string]Target), Servers: make(map[string]Server), Secrets: make(map[string]SecretBinding)}
	defer selected.Close()
	for id, names := range selection.Servers {
		server, exists := s.state.Servers[id]
		if !exists || len(names) == 0 {
			return nil, errors.New("selected export server or account does not exist")
		}
		copy := Server{Name: server.Name, Accounts: make(map[string]string)}
		for _, name := range names {
			profile, exists := server.Accounts[name]
			if _, duplicate := copy.Accounts[name]; !exists || duplicate {
				return nil, errors.New("selected export account is missing or duplicated")
			}
			copy.Accounts[name] = profile
			selected.Targets[profile] = ownTarget(s.state.Targets[profile])
		}
		selected.Servers[id] = copy
	}
	if len(selection.RemoteMCP) != 0 {
		selected.RemoteMCP = mcpdirectory.New()
		if s.state.RemoteMCP == nil || s.state.RemoteMCP.Validate() != nil {
			return nil, errors.New("selected remote MCP record does not exist or changed")
		}
		chosen := make(map[string]mcpdirectory.Binding, len(selection.RemoteMCP))
		for _, binding := range selection.RemoteMCP {
			account, exists := s.state.RemoteMCP.Accounts[binding.AccountID]
			server, serverExists := s.state.RemoteMCP.Servers[binding.ServerID]
			if !exists || !serverExists || account.ServerID != binding.ServerID || server.Revision != binding.ServerRevision || account.Revision != binding.AccountRevision {
				return nil, errors.New("selected remote MCP record does not exist or changed")
			}
			selected.RemoteMCP.Servers[binding.ServerID] = server
			selected.RemoteMCP.Accounts[binding.AccountID] = ownMCPAccount(account)
			chosen[binding.AccountID] = binding
		}
		for profile := range selected.Targets {
			previous, remembered := s.state.RemoteMCP.Last[profile]
			if !remembered {
				continue
			}
			selected.RemoteMCP.Last[profile] = make([]mcpdirectory.Binding, 0, len(previous))
			for _, binding := range previous {
				if current, ok := chosen[binding.AccountID]; ok && current == binding {
					account := s.state.RemoteMCP.Accounts[binding.AccountID]
					server := s.state.RemoteMCP.Servers[binding.ServerID]
					if server.Enabled && account.Enabled {
						selected.RemoteMCP.Last[profile] = append(selected.RemoteMCP.Last[profile], current)
					}
				}
			}
		}
		if err := selected.RemoteMCP.Validate(); err != nil {
			return nil, errors.New("selected remote MCP records are invalid")
		}
	}
	for id, binding := range s.state.Secrets {
		_, server := selection.Servers[binding.ServerID]
		if server || (selection.GlobalSecrets && binding.ServerID == "") {
			selected.Secrets[id] = binding
		}
	}
	encoded, err := marshal(selected)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	archive, err := ownerarchive.New(encoded)
	if err != nil {
		return nil, err
	}
	bindings := make(map[string]SecretBinding, len(selected.Secrets))
	for id, binding := range selected.Secrets {
		bindings[id] = binding
	}
	return &OwnerExportPlan{source: s, revision: s.revision, archive: archive, bindings: bindings}, nil
}

func remapImportedMCP(source *mcpdirectory.Directory, targets map[string]Target) (*mcpdirectory.Directory, error) {
	if source == nil || source.Validate() != nil {
		return nil, ErrImportInvalid
	}
	result := mcpdirectory.New()
	serverIDs := make(map[string]string, len(source.Servers))
	accountIDs := make(map[string]string, len(source.Accounts))
	oldServers, oldAccounts := make(map[string]bool, len(source.Servers)), make(map[string]bool, len(source.Accounts))
	for id := range source.Servers {
		oldServers[id] = true
	}
	for id := range source.Accounts {
		oldAccounts[id] = true
	}
	for oldID, server := range source.Servers {
		var newID string
		var err error
		for attempts := 0; attempts < 8; attempts++ {
			newID, err = result.AddServer(server.Name, server.URL)
			if err != nil || !oldServers[newID] {
				break
			}
			if removeErr := result.RemoveServer(newID); removeErr != nil {
				result.Clear()
				return nil, ErrImportInvalid
			}
		}
		if err != nil || oldServers[newID] {
			result.Clear()
			return nil, ErrImportInvalid
		}
		copy := result.Servers[newID]
		copy.Enabled = server.Enabled
		result.Servers[newID] = copy
		serverIDs[oldID] = newID
	}
	for oldID, account := range source.Accounts {
		account.ServerID = serverIDs[account.ServerID]
		account.Revision = 1
		var newID string
		var err error
		for attempts := 0; attempts < 8; attempts++ {
			newID, err = result.AddAccount(account)
			if err != nil || !oldAccounts[newID] {
				break
			}
			if removeErr := result.RemoveAccount(newID); removeErr != nil {
				result.Clear()
				return nil, ErrImportInvalid
			}
		}
		if err != nil || oldAccounts[newID] {
			result.Clear()
			return nil, ErrImportInvalid
		}
		copy := result.Accounts[newID]
		copy.Enabled = account.Enabled
		result.Accounts[newID] = copy
		accountIDs[oldID] = newID
	}
	for profile, previous := range source.Last {
		if _, selected := targets[profile]; !selected {
			continue
		}
		kept := make([]mcpdirectory.Binding, 0, len(previous))
		for _, binding := range previous {
			server, serverOK := source.Servers[binding.ServerID]
			account, accountOK := source.Accounts[binding.AccountID]
			if !serverOK || !accountOK || !server.Enabled || !account.Enabled || account.ServerID != binding.ServerID || server.Revision != binding.ServerRevision || account.Revision != binding.AccountRevision {
				continue
			}
			kept = append(kept, mcpdirectory.Binding{ServerID: serverIDs[binding.ServerID], AccountID: accountIDs[binding.AccountID], ServerRevision: 1, AccountRevision: 1})
		}
		result.Last[profile] = kept
	}
	if result.Validate() != nil {
		result.Clear()
		return nil, ErrImportInvalid
	}
	return result, nil
}

func ownMCPAccount(account mcpdirectory.Account) mcpdirectory.Account {
	account.Auth.Secret = append([]byte{}, account.Auth.Secret...)
	headers := make([]mcpdirectory.Header, len(account.Headers))
	for index, header := range account.Headers {
		headers[index] = mcpdirectory.Header{Name: header.Name, Value: append([]byte{}, header.Value...)}
	}
	account.Headers = headers
	return account
}

func (p *OwnerExportPlan) Bindings() map[string]SecretBinding {
	result := make(map[string]SecretBinding)
	if p == nil || p.closed {
		return result
	}
	for id, binding := range p.bindings {
		result[id] = binding
	}
	return result
}

func (p *OwnerExportPlan) Add(alias string, reference appstoreref.Ref, value []byte) error {
	if p == nil || p.closed || p.archive == nil {
		return ownerarchive.ErrArchive
	}
	return p.archive.Add(alias, reference, value)
}

func (p *OwnerExportPlan) WriteEncrypted(ctx context.Context, destination string) error {
	return p.write(ctx, destination, "", true)
}

func (p *OwnerExportPlan) WritePlaintext(ctx context.Context, destination, confirmation string) error {
	return p.write(ctx, destination, confirmation, false)
}

func (p *OwnerExportPlan) write(ctx context.Context, destination, confirmation string, encrypted bool) error {
	if p == nil || p.closed || p.source == nil || p.archive == nil {
		return ownerarchive.ErrArchive
	}
	s := p.source
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.revision != p.revision || s.saved != p.revision || s.saveErr != nil {
		return errors.New("owner database changed after export selection")
	}
	if encrypted {
		if s.exportKey == nil {
			return errors.New("owner export requires the authenticated cached sealing key")
		}
		return p.archive.WriteEncrypted(ctx, destination, s.exportKey)
	}
	return p.archive.WritePlaintext(ctx, destination, confirmation)
}

func (p *OwnerExportPlan) Close() {
	if p == nil || p.closed {
		return
	}
	p.archive.Close()
	clear(p.bindings)
	p.closed = true
}
