package ownermcp

import (
	"strconv"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

type Field struct {
	Label, Help, Value string
	Limit              int
	Secret             bool
}

func Fields(action, serverID, accountID string, metadata mcpdirectory.Metadata) []Field {
	var server mcpdirectory.ServerMetadata
	var account mcpdirectory.AccountMetadata
	for _, s := range metadata.Servers {
		if s.ID == serverID {
			server = s
		}
	}
	for _, a := range metadata.Accounts {
		if a.ID == accountID && a.ServerID == serverID {
			account = a
		}
	}
	field := func(label, help, value string, limit int) Field {
		return Field{Label: label, Help: help, Value: value, Limit: limit}
	}
	switch action {
	case "add-mcp-server":
		return []Field{field("MCP server name", "Unique ASCII name, 1–64 characters.", "", 64), field("HTTPS endpoint", "Fixed HTTPS URL; no userinfo, query or fragment. No network request is made.", "", 2048)}
	case "edit-mcp-server":
		if server.ID == "" {
			return nil
		}
		return []Field{field("MCP server name", "Display renames preserve stable identity.", server.Name, 64), field("HTTPS endpoint", "Changing the endpoint invalidates remembered selection; active sessions do not adopt it.", server.URL, 2048), field("Enabled", "true or false.", strconv.FormatBool(server.Enabled), 5)}
	case "remove-mcp-server", "remove-mcp-account":
		if server.ID == "" || (action == "remove-mcp-account" && account.ID == "") {
			return nil
		}
		return []Field{field("Confirmation", "Type REMOVE. Server removal also removes its accounts and remembered bindings.", "", 16)}
	case "rename-mcp-account":
		if account.ID == "" {
			return nil
		}
		return []Field{field("MCP account name", "Display rename only; stable identity and remembered selection are preserved.", account.Name, 64)}
	case "add-mcp-account", "edit-mcp-account":
		if server.ID == "" || (action == "edit-mcp-account" && account.ID == "") {
			return nil
		}
		name, enabled, auth, username, decision := "main", "true", "none", "", "clear"
		if action == "edit-mcp-account" {
			name, enabled, auth, username, decision = account.Name, strconv.FormatBool(account.Enabled), account.Authentication, account.Username, "keep"
		}
		return []Field{
			field("MCP account name", "For an existing account, use Rename to change only its display name.", name, 64),
			field("Enabled", "true or false. Changes invalidate remembered selection.", enabled, 5),
			field("MCP authentication", "none, bearer or basic. Additional credential headers are edited separately.", auth, 16),
			field("MCP username", "Basic only; empty for none or bearer.", username, 256),
			field("Credential action", "keep: unchanged authentication and username; replace: enter a new secret; clear: none with no username or secret.", decision, 8),
			{Label: "MCP credential", Help: "Hidden token/password. Empty only for explicit keep or clear.", Limit: 8192, Secret: true},
		}
	case "edit-mcp-header":
		if account.ID == "" {
			return nil
		}
		return []Field{
			field("Header name", "Canonical custom credential header, e.g. X-Api-Key. Reserved HTTP/MCP headers are forbidden.", "", 128),
			field("Header action", "replace or clear. Other headers and the primary credential are preserved.", "replace", 8),
			{Label: "Header credential", Help: "Hidden new value for replace; empty for clear. At most four custom headers.", Limit: 8192, Secret: true},
		}
	}
	return nil
}

func Select(metadata mcpdirectory.Metadata, serverName, accountName string, needsAccount bool) (string, string, error) {
	for _, s := range metadata.Servers {
		if s.Name != serverName {
			continue
		}
		if !needsAccount {
			return s.ID, "", nil
		}
		for _, a := range metadata.Accounts {
			if a.ServerID == s.ID && a.Name == accountName {
				return s.ID, a.ID, nil
			}
		}
	}
	return "", "", mcpdirectory.ErrMissing
}
