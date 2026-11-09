// Package ownercommand describes explicit owner actions without holding secrets.
package ownercommand

// Spec maps public options to the existing owner form labels.
type Spec struct {
	Action  string
	Scope   string
	Options map[string]string
}

func Specs() []Spec {
	account := func() map[string]string {
		return map[string]string{"account": "Account name", "login": "SSH login", "auth": "Authentication", "key-file": "Credential", "usage": "Usage"}
	}
	server := account()
	server["name"], server["address"], server["host-keys"] = "Server name", "Address", "Host keys"
	return []Spec{
		{"add-server", "database", server},
		{"rename-server", "server", map[string]string{"name": "Server name"}},
		{"edit-server", "server", map[string]string{"address": "Address", "host-keys": "Replacement host keys"}},
		{"add-account", "server", account()},
		{"edit-account", "account", account()},
		{"edit-proxy", "server", map[string]string{"type": "Proxy type", "address": "Proxy address", "login": "Proxy login"}},
		{"add-secret", "secrets", map[string]string{"name": "Secret name"}},
		{"edit-secret", "secret", nil},
		{"remove-secret", "secret", nil},
		{"export", "export", map[string]string{"destination": "Destination", "format": "Format", "mcp-accounts": "MCP accounts"}},
		{"import", "database", map[string]string{"file": "Archive file"}},
		{"link", "database", map[string]string{"directory": "Store directory"}},
		{"pending", "database", map[string]string{"action": "Action"}},
		{"add-mcp-server", "mcp-directory", map[string]string{"name": "MCP server name", "url": "HTTPS endpoint"}},
		{"edit-mcp-server", "mcp-server", map[string]string{"name": "MCP server name", "url": "HTTPS endpoint", "enabled": "Enabled"}},
		{"remove-mcp-server", "mcp-server", nil},
		{"add-mcp-account", "mcp-server", mcpAccountOptions()},
		{"edit-mcp-account", "mcp-account", mcpAccountOptions()},
		{"rename-mcp-account", "mcp-account", map[string]string{"name": "MCP account name"}},
		{"remove-mcp-account", "mcp-account", nil},
		{"edit-mcp-header", "mcp-account", map[string]string{"header": "Header name", "header-action": "Header action"}},
	}
}

func mcpAccountOptions() map[string]string {
	return map[string]string{"account": "MCP account name", "enabled": "Enabled", "auth": "MCP authentication", "login": "MCP username", "credential-action": "Credential action"}
}

func Lookup(action string) (Spec, bool) {
	for _, spec := range Specs() {
		if spec.Action == action {
			return spec, true
		}
	}
	return Spec{}, false
}

// Request contains metadata only. Secret values and confirmations have no options.
type Request struct {
	Action, Server, Account, Secret, Scope string
	Fields                                 map[string]string
}
