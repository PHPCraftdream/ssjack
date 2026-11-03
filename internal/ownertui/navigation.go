// Package ownertui implements the explicit trusted-terminal owner editor.
package ownertui

import (
	"sort"
	"strconv"

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

func escaped(value string) string { return strconv.Quote(value) }

func navigation(at location, metadata vault.DirectoryMetadata) []item {
	switch at.screen {
	case databaseScreen:
		return []item{{label: "Servers", target: location{screen: serversScreen}}, {label: "Global secrets", target: location{screen: secretsScreen}}, {label: "Link secret store", action: "link"}, {label: "Pending change", action: "pending"}, {label: "Exit", action: "exit"}}
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
		return result
	case accountScreen:
		return []item{{label: "[Edit SSH account]", action: "edit-account"}}
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
		return result
	case secretScreen:
		return []item{{label: "[Change secret value]", action: "edit-secret"}, {label: "[Remove secret]", action: "remove-secret"}}
	}
	return nil
}
