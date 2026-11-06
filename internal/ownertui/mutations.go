package ownertui

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/owneredit"
	"github.com/PHPCraftdream/ssjack/internal/ownermcp"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var errForm = errors.New("invalid owner form")

func readOwnerSnapshot(b Backend) (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error) {
	if atomic, ok := b.(interface {
		OwnerSnapshot() (vault.DirectoryMetadata, ownerdb.Status, ownerdb.ImportStatus, error)
	}); ok {
		return atomic.OwnerSnapshot()
	}
	metadata, err := b.Metadata()
	if err != nil {
		return metadata, ownerdb.Status{}, ownerdb.ImportStatus{}, err
	}
	return metadata, b.Status(), b.ImportStatus(), nil
}

func (m *Model) prepareExportForm(f *form) error {
	selection := vault.ExportSelection{Servers: make(map[string][]string)}
	accountCount := 0
	switch f.origin.screen {
	case databaseScreen:
		selection.GlobalSecrets = true
		for _, server := range m.metadata.Servers {
			for _, account := range server.Accounts {
				selection.Servers[server.ID] = append(selection.Servers[server.ID], account.Name)
				accountCount++
			}
		}
		f.scopeLabel = "All " + strconv.Itoa(len(selection.Servers)) + " servers / " + strconv.Itoa(accountCount) + " accounts; global and server secrets."
	case serverScreen, accountScreen:
		for _, server := range m.metadata.Servers {
			if server.ID != f.origin.server {
				continue
			}
			for _, account := range server.Accounts {
				if f.origin.account == "" || account.Name == f.origin.account {
					selection.Servers[server.ID] = append(selection.Servers[server.ID], account.Name)
				}
			}
			accountCount = len(selection.Servers[server.ID])
			f.scopeLabel = "Server " + escaped(server.Name) + " / " + strconv.Itoa(accountCount) + " selected accounts; all server-local secrets, no global fallback."
		}
		if accountCount == 0 {
			return errForm
		}
	case secretsScreen:
		if f.origin.server != "" {
			return errForm
		}
		selection.GlobalSecrets = true
		f.scopeLabel = "Global secret values only; no SSH credentials or server-local secrets."
	default:
		return errForm
	}
	f.exportScope = &selection
	f.scopeLabel += "\nRemote MCP credentials and preferences are not included."
	f.scopeLabel += "\nWARNING: plaintext exposes selected private keys, passwords and application values."
	f.fields = []field{
		input("Destination", "A new private ZIP file; no overwrite or plaintext staging.", 4096, false, ""),
		input("Format", "encrypted (default), or plaintext after the disclosure warning.", 16, false, "encrypted"),
		input("Confirmation", "For plaintext only, type EXPORT PLAINTEXT. Leave empty for encrypted export.", 32, false, ""),
	}
	return nil
}

func (m *Model) performExport(f *form) error {
	if f.exportScope == nil {
		return errForm
	}
	format, confirmation := string(f.fields[1].value), string(f.fields[2].value)
	if (format != "encrypted" && format != "plaintext") || (format == "encrypted" && confirmation != "") || (format == "plaintext" && confirmation != "EXPORT PLAINTEXT") {
		return errForm
	}
	ctx, cancel := context.WithTimeout(m.ctx, time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	request := ownerdb.ExportRequest{Selection: *f.exportScope, Destination: string(f.fields[0].value), PlaintextConfirmation: confirmation}
	if err := m.backend.Export(request); err != nil {
		return err
	}
	return m.backend.Flush(ctx)
}

// performPending dispatches one explicit owner decision; there is no automatic replay.
func (m *Model) performPending(action string) error {
	switch action {
	case "retry-db":
		return m.backend.RetryDatabase()
	case "reconcile":
		return m.backend.Reconcile()
	case "resume-draft":
		return m.backend.ResumeDraft()
	case "cancel-draft":
		return m.backend.CancelDraft()
	case "resume-import":
		return m.backend.ResumeImport()
	case "abort-import":
		return m.backend.AbortImport()
	}
	return errForm
}

func directoryChange(f *form) owneredit.Change {
	change := owneredit.Change{Action: f.action, ServerID: f.origin.server, Account: f.origin.account}
	for _, field := range f.fields {
		change.Fields = append(change.Fields, field.value)
	}
	return change
}
func editDirectory(v *vault.Vault, f *form) error { return owneredit.Apply(v, directoryChange(f)) }
func editServer(v *vault.Vault, id, address, replacement string) error {
	return owneredit.Server(v, id, address, replacement)
}

func (m *Model) submitSecret(f *form) error {
	change := vault.OwnerChange{Action: "add", Name: string(f.fields[0].value), ServerID: f.origin.server, MediaType: "text/plain"}
	if f.action != "add-secret" {
		metadata, err := m.backend.Metadata()
		if err != nil {
			return err
		}
		alias, exists := metadata.Secrets[f.origin.secret]
		if !exists || alias.ServerID != f.origin.server {
			return errForm
		}
		ref, err := appstoreplaceholder.Parse([]byte(alias.Ref))
		if err != nil {
			return errForm
		}
		object := ref.ObjectID()
		change.AliasID, change.ObjectID = f.origin.secret, hex.EncodeToString(object[:])
		change.PreviousReference = alias.Ref
		change.Action = "update"
		if f.action == "remove-secret" {
			if string(f.fields[0].value) != "REMOVE" {
				return errForm
			}
			change.Action, change.Name = "remove", alias.Name
		}
	}
	if change.Action != "remove" {
		change.Value = f.fields[1].value
	}
	return m.backend.Submit(change)
}

func mcpItems(at location, metadata vault.DirectoryMetadata) []item {
	scope := map[screen]string{mcpDirectoryScreen: "mcp-directory", mcpServerScreen: "mcp-server", mcpAccountScreen: "mcp-account"}[at.screen]
	screens := map[string]screen{"mcp-directory": mcpDirectoryScreen, "mcp-server": mcpServerScreen, "mcp-account": mcpAccountScreen}
	var result []item
	for _, entry := range ownermcp.Items(scope, at.server, at.account, metadata.RemoteMCP) {
		result = append(result, item{label: entry.Label, action: entry.Action, target: location{screen: screens[entry.Scope], server: entry.ServerID, account: entry.AccountID}})
	}
	return result
}

func (m *Model) applyForm() tea.Cmd {
	m.epoch++
	f := m.form
	m.form = nil
	m.back()
	m.working = true
	operation := *m
	operation.backend = scopeBackend(m.backend, f.revision, f.planID)
	return func() tea.Msg {
		defer f.clear()
		return operationMsg{err: operation.perform(f), action: f.action}
	}
}

func scopeBackend(b Backend, revision, plan uint64) Backend {
	if scoped, ok := b.(interface{ AtImportPlan(uint64, uint64) Backend }); ok {
		return scoped.AtImportPlan(revision, plan)
	}
	if scoped, ok := b.(interface{ AtRevision(uint64) Backend }); ok {
		return scoped.AtRevision(revision)
	}
	return b
}

// Connection pins one owner-selected SSH account and its displayed revision.
type Connection struct {
	ServerID, Account string
	Revision          uint64
}
