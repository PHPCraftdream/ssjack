package session

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"sort"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
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
		if !core.ValidDirectoryID(binding.ServerID) || !core.ValidDirectoryID(binding.AccountID) || binding.ServerRevision == 0 || binding.AccountRevision == 0 || seen[binding.AccountID] {
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
			selected.Targets[profile] = record.OwnTarget(s.state.Targets[profile])
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
	encoded, err := core.Marshal(selected)
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
	parsed, err := core.Unmarshal(opened.Database())
	if err != nil {
		return nil, ErrImportInvalid
	}
	defer parsed.Close()
	ids := opened.SecretIDs()
	if parsed.Version != 2 || parsed.OwnerStore != nil || parsed.Approvals != nil || len(ids) != len(parsed.Secrets) {
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
		result.targets[id] = record.OwnTarget(target)
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
					if key, err := record.ParseHostKey([]byte(encoded)); err == nil {
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
		if !exists || !record.SameTarget(current, target) {
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
			candidate.Targets[id] = record.OwnTarget(target)
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
