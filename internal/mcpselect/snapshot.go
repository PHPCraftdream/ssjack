package mcpselect

import (
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

// New owns a display snapshot. It neither persists a choice nor mints a grant.
func New(profile string, revision uint64, metadata mcpdirectory.Metadata) (*Model, error) {
	if len(profile) == 0 || len(profile) > 64 || len(metadata.Servers) > mcpdirectory.MaxServers || len(metadata.Accounts) > mcpdirectory.MaxAccounts || len(metadata.Last[profile]) > mcpdirectory.MaxSelections {
		return nil, ErrSelection
	}
	servers := make(map[string]mcpdirectory.ServerMetadata, len(metadata.Servers))
	for _, server := range metadata.Servers {
		if server.ID == "" || len(server.ID) > 64 || server.Revision == 0 || len(server.Name) == 0 || len(server.Name) > 64 || len(server.URL) == 0 || len(server.URL) > 2048 {
			return nil, ErrSelection
		}
		if _, exists := servers[server.ID]; exists {
			return nil, ErrSelection
		}
		servers[server.ID] = server
	}
	seen := make(map[string]bool, len(metadata.Accounts))
	model := &Model{profile: profile, revision: revision}
	for _, account := range metadata.Accounts {
		server, exists := servers[account.ServerID]
		if !exists || account.ID == "" || len(account.ID) > 64 || seen[account.ID] || account.Revision == 0 || len(account.Name) == 0 || len(account.Name) > 64 {
			return nil, ErrSelection
		}
		seen[account.ID] = true
		binding := mcpdirectory.Binding{ServerID: server.ID, AccountID: account.ID, ServerRevision: server.Revision, AccountRevision: account.Revision}
		entry := item{binding: binding, server: server.Name, account: account.Name, endpoint: server.URL, enabled: server.Enabled && account.Enabled}
		for _, previous := range metadata.Last[profile] {
			if previous == binding && entry.enabled {
				entry.checked = true
			}
		}
		model.items = append(model.items, entry)
	}
	sort.Slice(model.items, func(i, j int) bool {
		a, b := model.items[i], model.items[j]
		if a.server != b.server {
			return a.server < b.server
		}
		if a.account != b.account {
			return a.account < b.account
		}
		return a.binding.AccountID < b.binding.AccountID
	})
	model.valid = true
	return model, nil
}
