package ownertui

import (
	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (m *Model) describe() string {
	at := m.at
	if m.form != nil {
		at = m.form.origin
	}
	label := "Database / Global scope"
	for _, server := range m.metadata.Servers {
		if server.ID != at.server {
			continue
		}
		label = "Server " + escaped(server.Name) + " / " + escaped(server.Address)
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
	f := &form{action: action, origin: m.at}
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
	case "rename-server":
		f.fields = []field{input("Server name", "Stable identity and secret scopes are preserved.", 64, false, "")}
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
		f.fields = []field{input("Action", "retry-db, reconcile, resume-draft or cancel-draft; no automatic replay.", 32, false, "")}
	default:
		m.message = "Unsupported owner action."
		return
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

func (m *Model) applyForm() tea.Cmd {
	f := m.form
	m.form = nil
	m.back()
	m.working = true
	return func() tea.Msg {
		defer f.clear()
		return operationMsg{err: m.perform(f)}
	}
}

func (m *Model) perform(f *form) error {
	value := func(index int) string { return string(f.fields[index].value) }
	switch f.action {
	case "link":
		return m.backend.Link(value(0), f.fields[1].value)
	case "add-server", "add-account", "edit-account", "rename-server":
		return m.backend.Edit(func(v *vault.Vault) error { return editDirectory(v, f) })
	case "pending":
		switch value(0) {
		case "retry-db":
			return m.backend.RetryDatabase()
		case "reconcile":
			return m.backend.Reconcile()
		case "resume-draft":
			return m.backend.ResumeDraft()
		case "cancel-draft":
			return m.backend.CancelDraft()
		}
		return errForm
	case "add-secret", "edit-secret", "remove-secret":
		return m.submitSecret(f)
	}
	return errForm
}
