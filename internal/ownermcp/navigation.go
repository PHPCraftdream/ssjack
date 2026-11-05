package ownermcp

import (
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

type Item struct {
	Label, Action, Scope, ServerID, AccountID string
}

func Items(scope, serverID, accountID string, metadata mcpdirectory.Metadata) []Item {
	switch scope {
	case "mcp-directory":
		result := []Item{{Label: "[Add MCP server]", Action: "add-mcp-server"}}
		for _, s := range metadata.Servers {
			result = append(result, Item{Label: s.Name, Scope: "mcp-server", ServerID: s.ID})
		}
		return result
	case "mcp-server":
		result := []Item{{Label: "[Edit MCP server]", Action: "edit-mcp-server"}, {Label: "[Remove MCP server]", Action: "remove-mcp-server"}, {Label: "[Add MCP account]", Action: "add-mcp-account"}}
		for _, a := range metadata.Accounts {
			if a.ServerID == serverID {
				result = append(result, Item{Label: a.Name, Scope: "mcp-account", ServerID: serverID, AccountID: a.ID})
			}
		}
		return result
	case "mcp-account":
		return []Item{{Label: "[Edit MCP account]", Action: "edit-mcp-account"}, {Label: "[Rename MCP account]", Action: "rename-mcp-account"}, {Label: "[Edit MCP credential header]", Action: "edit-mcp-header"}, {Label: "[Remove MCP account]", Action: "remove-mcp-account"}}
	}
	return nil
}

func Describe(serverID, accountID string, metadata mcpdirectory.Metadata) string {
	label := "Remote MCP directory — private credentials hidden; opening forms makes no network requests"
	for _, s := range metadata.Servers {
		if s.ID == serverID {
			label += "\nMCP server " + strconv.Quote(s.Name) + " / " + strconv.Quote(s.URL) + " / enabled=" + strconv.FormatBool(s.Enabled)
		}
	}
	for _, a := range metadata.Accounts {
		if a.ID == accountID && a.ServerID == serverID {
			label += "\nMCP account " + strconv.Quote(a.Name) + " / " + strconv.Quote(a.Authentication) + " / username " + strconv.Quote(a.Username) + " / enabled=" + strconv.FormatBool(a.Enabled) + " / credential-set=" + strconv.FormatBool(a.CredentialSet)
			label += "\nCredential headers: " + strconv.Quote(strings.Join(a.HeaderNames, ", ")) + " (values hidden)"
		}
	}
	return label
}
