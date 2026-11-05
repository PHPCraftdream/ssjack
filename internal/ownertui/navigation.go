// Package ownertui implements the explicit trusted-terminal owner editor.
package ownertui

import (
	"errors"
	"sort"
	"strconv"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownermcp"
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
	mcpDirectoryScreen
	mcpServerScreen
	mcpAccountScreen
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
		return append(connectionItems(metadata), []item{{label: "Servers", target: location{screen: serversScreen}}, {label: "Global secrets", target: location{screen: secretsScreen}}, {label: "Remote MCP servers", target: location{screen: mcpDirectoryScreen}}, {label: "Export all credentials and values", action: "export"}, {label: "Import credentials and values", action: "import"}, {label: "Link secret store", action: "link"}, {label: "Pending change", action: "pending"}, {label: "Exit", action: "exit"}}...)
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
	case mcpDirectoryScreen, mcpServerScreen, mcpAccountScreen:
		return mcpItems(at, metadata)
	}
	return nil
}

func (m *Model) push(target location) {
	m.stack = append(m.stack, m.at)
	m.at, m.cursor, m.message, m.reselect = target, 0, "", false
}

func (m *Model) back() {
	if m.at.screen == importScreen {
		m.abortImport() // leaving the preview always drops the staged material
	}
	if m.form != nil {
		m.form.clear()
		m.form = nil
	}
	if len(m.stack) != 0 {
		m.at = m.stack[len(m.stack)-1]
		m.stack = m.stack[:len(m.stack)-1]
		m.cursor = 0
	}
	m.reselect = false
}

func (m *Model) Select(serverName, accountName string) error {
	if serverName == "" {
		if accountName != "" {
			return errors.New("account selection requires a named server")
		}
		return nil
	}
	metadata, err := m.backend.Metadata()
	if err != nil {
		return errors.New("cannot load named server metadata")
	}
	for _, server := range metadata.Servers {
		if server.Name != serverName {
			continue
		}
		at := location{screen: serverScreen, server: server.ID}
		stack := []location{{screen: databaseScreen}, {screen: serversScreen}}
		if accountName != "" {
			found := false
			for _, account := range server.Accounts {
				if account.Name == accountName {
					found = true
				}
			}
			if !found {
				return errors.New("selected named SSH account does not exist")
			}
			stack = append(stack, at)
			at.screen, at.account = accountScreen, accountName
		}
		m.metadata, m.at, m.stack, m.cursor = metadata, at, stack, 0
		return nil
	}
	return errors.New("selected named server does not exist")
}

// ConfigureCommand opens the same form as the menu, with metadata-only prefills.
func (m *Model) ConfigureCommand(request ownercommand.Request) error {
	spec, ok := ownercommand.Lookup(request.Action)
	if !ok || m.command != nil {
		return errForm
	}
	metadata, err := m.backend.Metadata()
	if err != nil {
		return err
	}
	m.metadata, m.status, m.imp, m.ready = metadata, m.backend.Status(), m.backend.ImportStatus(), true
	account := ""
	if spec.Scope == "account" || request.Scope == "account" {
		account = request.Account
	}
	if spec.Scope == "mcp-directory" || spec.Scope == "mcp-server" || spec.Scope == "mcp-account" {
		m.at = location{screen: mcpDirectoryScreen}
		if spec.Scope != "mcp-directory" {
			server, selected, err := ownermcp.Select(metadata.RemoteMCP, request.Server, request.Account, spec.Scope == "mcp-account")
			if err != nil {
				return err
			}
			m.at = location{screen: mcpServerScreen, server: server, account: selected}
			if selected != "" {
				m.at.screen = mcpAccountScreen
			}
		}
	} else if err := m.Select(request.Server, account); err != nil {
		return err
	}
	if spec.Scope == "secrets" || spec.Scope == "secret" || request.Scope == "global" {
		m.at.screen = secretsScreen
	}
	if spec.Scope == "secret" {
		for id, secret := range m.metadata.Secrets {
			if secret.Name == request.Secret && secret.ServerID == m.at.server {
				m.at.screen, m.at.secret = secretScreen, id
			}
		}
		if m.at.secret == "" {
			return errors.New("selected named secret does not exist in this scope")
		}
	}
	m.openForm(request.Action)
	if m.form == nil {
		return errForm
	}
	allowed := make(map[string]bool)
	for _, label := range spec.Options {
		allowed[label] = true
	}
	for label, value := range request.Fields {
		if !allowed[label] {
			m.ClearInput()
			return errForm
		}
		found := false
		for i := range m.form.fields {
			field := &m.form.fields[i]
			if field.label != label {
				continue
			}
			if len(value) > field.limit || (field.secret && (label != "Credential" || request.Fields["Authentication"] != "key")) {
				m.ClearInput()
				return errForm
			}
			clear(field.value)
			field.value, field.supplied, found = []byte(value), true, true
		}
		if !found {
			m.ClearInput()
			return errForm
		}
	}
	if m.form.fields[0].supplied {
		m.form.move(1)
	}
	m.command = &ownercommand.State{Request: request}
	return nil
}
