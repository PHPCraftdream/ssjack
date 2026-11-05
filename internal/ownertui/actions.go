package ownertui

import (
	"context"
	"strconv"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/owneredit"
	"github.com/PHPCraftdream/ssjack/internal/ownermcp"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (m *Model) describe() string {
	at := m.at
	if m.form != nil {
		at = m.form.origin
	}
	if at.screen == importScreen {
		return "Import preview — nothing is applied until you confirm"
	}
	if at.screen >= mcpDirectoryScreen && at.screen <= mcpAccountScreen {
		return ownermcp.Describe(at.server, at.account, m.metadata.RemoteMCP)
	}
	label := "Database / Global scope"
	for _, server := range m.metadata.Servers {
		if server.ID != at.server {
			continue
		}
		label = "Server " + escaped(server.Name) + " / " + escaped(server.Address)
		label += "\n" + proxySummary(server.Proxy)
		for _, fingerprint := range server.Fingerprints {
			label += "\nHost key: " + escaped(fingerprint)
		}
		for _, account := range server.Accounts {
			if account.Name == at.account {
				label += "\nAccount " + escaped(account.Name) + " / login " + escaped(account.User) + " / " + escaped(account.Authentication) + " / usage " + escaped(account.Usage)
			}
		}
	}
	if secret, exists := m.metadata.Secrets[at.secret]; exists {
		label += "\nSecret " + escaped(secret.Name) + " / exact reference " + escaped(secret.Ref)
	}
	if m.metadata.OwnerStore != nil && m.metadata.OwnerStore.PendingID != "" {
		label += "\nPending change: " + escaped(m.metadata.OwnerStore.PendingPhase)
	}
	return label
}

func input(label, help string, limit int, secret bool, value string) field {
	return field{label: label, help: help, limit: limit, secret: secret, value: []byte(value)}
}

func (m *Model) openForm(action string) {
	f := &form{action: action, origin: m.at, revision: m.status.Database.Revision}
	switch action {
	case "add-server":
		f.fields = []field{
			input("Server name", "Unique ASCII name, 1–64 characters.", 64, false, ""),
			input("Address", "Explicit host:port; no network discovery.", 1024, false, ""),
			input("Account name", "Named SSH identity on this server.", 64, false, "main"),
		}
		f.fields = append(f.fields, accountFields()...)
		f.fields = append(f.fields, input("Host keys", "Verified bare OpenSSH public keys, separated by |. Never trust an unverified scan.", 16384, false, ""))
	case "add-account", "edit-account":
		f.fields = []field{input("Account name", "Existing names replace that account only after Apply.", 64, false, m.at.account)}
		f.fields = append(f.fields, accountFields()...)
		for _, server := range m.metadata.Servers {
			if server.ID != m.at.server {
				continue
			}
			for _, account := range server.Accounts {
				if account.Name == m.at.account {
					f.fields[1].value = []byte(account.User)
					f.fields[2].value = []byte(account.Authentication)
					f.fields[4].value = []byte(account.Usage)
				}
			}
		}
	case "edit-server":
		address := ""
		for _, server := range m.metadata.Servers {
			if server.ID == m.at.server {
				address = server.Address
			}
		}
		f.fields = []field{
			input("Address", "Explicit host:port, applied to every account on this server.", 1024, false, address),
			input("Replacement host keys", "Blank keeps verified keys; otherwise bare verified public keys separated by |.", 16384, false, ""),
		}
	case "edit-proxy":
		m.prepareProxyForm(f)
	case "rename-server":
		f.fields = []field{input("Server name", "Stable identity and secret scopes are preserved.", 64, false, "")}
	case "export":
		if err := m.prepareExportForm(f); err != nil {
			m.message = "Export scope is unavailable."
			return
		}
	case "link":
		f.fields = []field{
			input("Store directory", "Existing authenticated installation; no new store is created.", 4096, false, ""),
			input("Store unlock secret", "Stored only inside the encrypted owner database.", 16384, true, ""),
		}
	case "add-secret", "edit-secret":
		name := ""
		if action == "edit-secret" {
			name = m.metadata.Secrets[m.at.secret].Name
		}
		f.fields = []field{
			input("Secret name", "Unique in this explicit global or server scope.", 64, false, name),
			input("Value", "New UTF-8 value; never displayed or sent to logs.", 16384, true, ""),
		}
	case "remove-secret":
		f.fields = []field{input("Confirmation", "Type REMOVE to remove the selected named secret.", 16, false, "")}
	case "pending":
		f.fields = []field{input("Action", "retry-db, reconcile, resume-draft, cancel-draft, resume-import or abort-import; no automatic replay.", 32, false, "")}
	case "import", "import-confirm":
		if !m.prepareImportForm(f) {
			return
		}
	default:
		for _, descriptor := range ownermcp.Fields(action, m.at.server, m.at.account, m.metadata.RemoteMCP) {
			f.fields = append(f.fields, input(descriptor.Label, descriptor.Help, descriptor.Limit, descriptor.Secret, descriptor.Value))
		}
		if len(f.fields) == 0 {
			m.message = "Unsupported owner action."
			return
		}
	}
	m.push(location{screen: formScreen})
	m.form = f
}

func accountFields() []field {
	return []field{
		input("SSH login", "Remote operating-system user.", 256, false, ""),
		input("Authentication", "key or password; exactly one identity.", 16, false, "key"),
		input("Credential", "Password, or existing private-key file path. Blank keeps an existing credential.", 4096, true, ""),
		input("Usage", "both, human or agent.", 8, false, "both"),
	}
}

func (m *Model) perform(f *form) error {
	value := func(index int) string { return string(f.fields[index].value) }
	switch f.action {
	case "export":
		return m.performExport(f)
	case "import", "import-confirm":
		return m.performImport(f)
	case "link":
		return m.backend.Link(value(0), f.fields[1].value)
	case "add-server", "add-account", "edit-account", "rename-server", "edit-server", "edit-proxy",
		"add-mcp-server", "edit-mcp-server", "remove-mcp-server", "add-mcp-account", "edit-mcp-account", "rename-mcp-account", "remove-mcp-account", "edit-mcp-header":
		return owneredit.Dispatch(m.backend, directoryChange(f))
	case "pending":
		return m.performPending(value(0))
	case "add-secret", "edit-secret", "remove-secret":
		return m.submitSecret(f)
	}
	return errForm
}

// Connection names one owner-selected SSH account; it carries no credentials.
type Connection struct{ ServerID, Account string }

// TakeConnection returns and clears the request recorded by selecting a
// connection point. The caller obtains credentials through the manager only.
func (m *Model) TakeConnection() (Connection, bool) {
	if m.connection == nil {
		return Connection{}, false
	}
	taken := *m.connection
	m.connection = nil
	return taken, true
}

// Connected reports the finished handoff with a fixed message, never raw error
// text. Navigation location and cursor are kept so a new Program resumes there.
func (m *Model) Connected(code int, err error) {
	m.working, m.quitting, m.connection = false, false, nil
	if err != nil {
		m.message = "SSH connection failed or ended with an error; no database change was made."
		return
	}
	m.message = "SSH session ended (exit code " + strconv.Itoa(code) + ")."
}

// applyMetadata keeps focus on the same item across a refresh. If that exact
// item (label included) is gone, the cursor resets and Enter is blocked until
// the owner moves deliberately. Nothing is flagged before the first list was
// shown or while a form is open.
func (m *Model) applyMetadata(next vault.DirectoryMetadata, imports ownerdb.ImportStatus) {
	old := m.items()
	focused, tracked := item{}, m.form == nil && m.ready && m.cursor >= 0 && m.cursor < len(old)
	if tracked {
		focused = old[m.cursor]
	}
	m.metadata, m.imp = next, imports
	if !tracked {
		return
	}
	for i, candidate := range m.items() {
		if candidate == focused {
			m.cursor = i
			return
		}
	}
	m.cursor, m.reselect, m.message = 0, true, reselectMessage
}

// activate runs the selected item; only an explicit Enter may start a connection.
func (m *Model) activate(selected item, enter bool) tea.Cmd {
	switch selected.action {
	case "exit":
		return m.requestClose()
	case "connect":
		if !enter {
			return nil
		}
		if !m.connectable(selected.target) {
			m.message = "That connection is no longer available."
			return nil
		}
		// The manager stays open: the caller needs it for the credential path.
		m.connection = &Connection{ServerID: selected.target.server, Account: selected.target.account}
		return tea.Quit
	case "none":
		m.message = "No SSH connection is available; add a server account that permits human use."
	case "info":
		// Preview rows are read-only.
	case "import-cancel":
		m.back()
		if m.command != nil {
			m.command.Err = ownercommand.ErrCancelled
			return tea.Quit
		}
	case "":
		m.push(selected.target)
	default:
		m.openForm(selected.action)
	}
	return nil
}

func (m *Model) ClearInput() {
	if m.form != nil {
		m.form.clear()
		m.form = nil
	}
}

func (m *Model) requestClose() tea.Cmd {
	m.working, m.quitting = true, true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, time.Minute)
		defer cancel()
		return closeMsg{err: m.backend.Close(ctx)}
	}
}

func (m *Model) CommandResult() error { return m.command.Result() }

func (m *Model) commandDone(message operationMsg) tea.Cmd {
	if message.err != nil {
		m.command.Err = ownercommand.ErrOperation
		return tea.Quit
	}
	if message.action == "import" {
		m.importDone(message.action, nil)
		if m.imp.Phase != ownerdb.ImportStaged {
			m.command.Err = ownercommand.ErrOperation
			return tea.Quit
		}
		return nil
	}
	if message.action == "command-finish" {
		m.command.Finished = true
		return tea.Quit
	}
	m.working = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 5*time.Minute)
		defer cancel()
		err := m.backend.Flush(ctx)
		status, imported := m.backend.Status(), m.backend.ImportStatus()
		if err == nil && (status.Err != nil || status.Database.Err != nil || status.Database.Pending || status.Pending || status.Busy) {
			err = ownercommand.ErrOperation
		}
		if err == nil && (message.action == "import-confirm" || m.command.Request.Fields["Action"] == "resume-import") && imported.Phase != ownerdb.ImportComplete {
			err = ownercommand.ErrOperation
		}
		return operationMsg{action: "command-finish", err: err}
	}
}
