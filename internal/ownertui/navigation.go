// Package ownertui implements the explicit trusted-terminal owner editor.
package ownertui

import (
	"sort"
	"strconv"

	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type screen int

const (
	databaseScreen screen = iota
	serversScreen
	serverScreen
	accountScreen
	secretsScreen
	secretScreen
	formScreen
	confirmScreen
	importScreen
)

type location struct {
	screen  screen
	server  string
	account string
	secret  string
}

type item struct {
	label  string
	target location
	action string
}

const reselectMessage = "The list changed; choose an entry again."

func (m *Model) clearReselect() {
	m.reselect = false
	if m.message == reselectMessage {
		m.message = ""
	}
}

// connectable re-checks at activation time that the account still exists and
// permits human use, so a vanished account is never recorded.
func (m *Model) connectable(target location) bool {
	for _, server := range m.metadata.Servers {
		for _, account := range server.Accounts {
			if server.ID == target.server && account.Name == target.account && humanUsage(account.Usage) {
				return true
			}
		}
	}
	return false
}

func proxySummary(proxy sshproxy.Metadata) string {
	if proxy.Type == "" {
		return "Proxy: direct"
	}
	return "Proxy: " + escaped(proxy.Type) + " / " + escaped(proxy.Address) + " / login " + escaped(proxy.Username) + " / authenticated=" + strconv.FormatBool(proxy.Authenticated)
}

func escaped(value string) string { return strconv.Quote(value) }

func humanUsage(usage string) bool { return usage == "" || usage == "both" || usage == "human" }

// connectionItems lists one entry per human-permitted account, in metadata order.
// An empty list yields a non-actionable placeholder so the root is never bare.
func connectionItems(metadata vault.DirectoryMetadata) []item {
	var result []item
	for _, server := range metadata.Servers {
		for _, account := range server.Accounts {
			if humanUsage(account.Usage) {
				label := "Connect: " + escaped(server.Name) + " / " + escaped(server.Address) + " / login " + escaped(account.User) + " / account " + escaped(account.Name) + " / " + escaped(account.Authentication)
				if server.Proxy.Type != "" {
					label += " / " + proxySummary(server.Proxy)
				}
				result = append(result, item{label: label, target: location{server: server.ID, account: account.Name}, action: "connect"})
			}
		}
	}
	if len(result) == 0 {
		return []item{{label: "(no SSH connections available)", action: "none"}}
	}
	return result
}

func navigation(at location, metadata vault.DirectoryMetadata) []item {
	switch at.screen {
	case databaseScreen:
		return append(connectionItems(metadata), []item{{label: "Servers", target: location{screen: serversScreen}}, {label: "Global secrets", target: location{screen: secretsScreen}}, {label: "Export all credentials and values", action: "export"}, {label: "Import credentials and values", action: "import"}, {label: "Link secret store", action: "link"}, {label: "Pending change", action: "pending"}, {label: "Exit", action: "exit"}}...)
	case serversScreen:
		result := []item{{label: "[Add server]", action: "add-server"}}
		for _, server := range metadata.Servers {
			result = append(result, item{label: server.Name, target: location{screen: serverScreen, server: server.ID}})
		}
		return result
	case serverScreen:
		result := []item{{label: "[Rename server]", action: "rename-server"}, {label: "[Edit server connection]", action: "edit-server"}, {label: "[Add SSH account]", action: "add-account"}, {label: "Server secrets", target: location{screen: secretsScreen, server: at.server}}}
		for _, server := range metadata.Servers {
			if server.ID == at.server {
				for _, account := range server.Accounts {
					result = append(result, item{label: account.Name + " — " + escaped(account.User) + " (" + account.Authentication + ")", target: location{screen: accountScreen, server: at.server, account: account.Name}})
				}
			}
		}
		return append(result, item{label: "[Edit SSH proxy]", action: "edit-proxy"}, item{label: "Export server credentials and values", action: "export"})
	case accountScreen:
		result := []item{{label: "[Edit SSH account]", action: "edit-account"}, {label: "Export account and server secrets", action: "export"}}
		for _, server := range metadata.Servers {
			for _, account := range server.Accounts {
				if server.ID == at.server && account.Name == at.account && humanUsage(account.Usage) {
					connect := item{label: "Connect via SSH", target: location{server: at.server, account: at.account}, action: "connect"}
					return append([]item{connect}, result...)
				}
			}
		}
		return result
	case secretsScreen:
		result := []item{{label: "[Add secret]", action: "add-secret"}}
		var ids []string
		for id, secret := range metadata.Secrets {
			if secret.ServerID == at.server {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return metadata.Secrets[ids[i]].Name < metadata.Secrets[ids[j]].Name })
		for _, id := range ids {
			result = append(result, item{label: metadata.Secrets[id].Name, target: location{screen: secretScreen, server: at.server, secret: id}})
		}
		if at.server == "" {
			result = append(result, item{label: "Export global secret values", action: "export"})
		}
		return result
	case secretScreen:
		return []item{{label: "[Change secret value]", action: "edit-secret"}, {label: "[Remove secret]", action: "remove-secret"}}
	}
	return nil
}
