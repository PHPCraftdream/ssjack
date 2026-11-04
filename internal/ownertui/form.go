package ownertui

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type field struct {
	label    string
	help     string
	value    []byte
	secret   bool
	supplied bool
	limit    int
}

type form struct {
	revision    uint64
	action      string
	fields      []field
	focus       int
	origin      location
	exportScope *vault.ExportSelection
	scopeLabel  string
}

func (f *form) clear() {
	for i := range f.fields {
		clear(f.fields[i].value)
		f.fields[i].value = nil
	}
}

func (f *form) move(delta int) {
	count := len(f.fields) + 2
	for {
		f.focus = (f.focus + delta + count) % count
		if f.focus >= len(f.fields) || !f.fields[f.focus].supplied {
			break
		}
	}
}

func (f *form) insert(text string) {
	if f.focus >= len(f.fields) || f.fields[f.focus].supplied || !utf8.ValidString(text) || strings.ContainsAny(text, "\x00\r\n\x1b") {
		return
	}
	current := &f.fields[f.focus]
	if len(text) > current.limit-len(current.value) {
		return
	}
	if cap(current.value) < current.limit {
		owned := make([]byte, len(current.value), current.limit)
		copy(owned, current.value)
		clear(current.value)
		current.value = owned
	}
	current.value = append(current.value, text...)
}

func (f *form) backspace() {
	if f.focus >= len(f.fields) || f.fields[f.focus].supplied {
		return
	}
	current := &f.fields[f.focus]
	if len(current.value) == 0 {
		return
	}
	_, size := utf8.DecodeLastRune(current.value)
	start := len(current.value) - size
	clear(current.value[start:])
	current.value = current.value[:start]
}

func (f *form) display(index int) string {
	current := &f.fields[index]
	if current.secret {
		if len(current.value) == 0 {
			return "<hidden; empty>"
		}
		return "<hidden; entered>"
	}
	if current.supplied {
		return escaped(string(current.value)) + " (parameter; read-only)"
	}
	return escaped(string(current.value))
}

// items returns the focused list; the import preview is derived from the
// latest ImportStatus rather than from directory metadata.
func (m *Model) items() []item {
	if m.at.screen == importScreen {
		return importItems(m.imp)
	}
	return navigation(m.at, m.metadata)
}

func previewCounts(p vault.ImportPreview) string {
	accounts := 0
	for _, server := range p.Servers {
		accounts += len(server.Accounts)
	}
	return strconv.Itoa(len(p.Servers)) + " servers, " + strconv.Itoa(accounts) + " accounts, " + strconv.Itoa(len(p.Secrets)) + " secrets"
}

// importItems lists actions, conflicts, then read-only metadata rows. No row
// ever carries a secret value, a credential or the archive password.
func importItems(st ownerdb.ImportStatus) []item {
	cancel := item{label: "[Cancel import]", action: "import-cancel"}
	if st.Phase != ownerdb.ImportStaged {
		return []item{{label: "Import is no longer staged.", action: "info"}, cancel}
	}
	var result []item
	if len(st.Conflicts) == 0 {
		result = append(result, item{label: "[Confirm import…]", action: "import-confirm"}, cancel)
	} else {
		result = append(result, item{label: "Import refused: conflicts with the destination (no overwrite, no merge)", action: "info"})
		for _, c := range st.Conflicts {
			result = append(result, item{label: "Conflict: " + c.Kind + " — " + escaped(c.Subject), action: "info"})
		}
		result = append(result, cancel)
	}
	kind := "plaintext"
	if st.Preview.Encrypted {
		kind = "encrypted"
	}
	info := func(label string) { result = append(result, item{label: label, action: "info"}) }
	info("Archive: " + kind + " — " + previewCounts(st.Preview) + " (values hidden)")
	for _, server := range st.Preview.Servers {
		keys := make([]string, 0, len(server.Fingerprints))
		for _, fingerprint := range server.Fingerprints {
			keys = append(keys, escaped(fingerprint))
		}
		if len(keys) == 0 {
			keys = append(keys, "(none)")
		}
		info("Server " + escaped(server.Name) + " / " + escaped(server.Address) + " / host key " + strings.Join(keys, ", "))
		if server.Proxy.Type != "" {
			info("  " + proxySummary(server.Proxy))
		}
		for _, a := range server.Accounts {
			info("  Account " + escaped(a.Name) + " / login " + escaped(a.User) + " / " + escaped(a.Authentication) + " / usage " + escaped(a.Usage))
		}
	}
	for _, secret := range st.Preview.Secrets {
		scope := "global"
		if secret.ServerID != "" {
			scope = "server " + escaped(secret.ServerName)
		}
		info("Secret " + escaped(secret.Name) + " / scope: " + scope + " / " + strconv.Itoa(secret.Length) + " bytes")
	}
	return result
}

func (m *Model) prepareProxyForm(f *form) {
	kind, address, user := "direct", "", ""
	for _, server := range m.metadata.Servers {
		if server.ID == f.origin.server && server.Proxy.Type != "" {
			kind, address, user = server.Proxy.Type, server.Proxy.Address, server.Proxy.Username
		}
	}
	f.scopeLabel = "All SSH accounts on this server. Proxy authentication is not encrypted on the proxy hop; trust the proxy/network. SSH host-key pinning remains mandatory."
	f.fields = []field{
		input("Proxy type", "direct (removes saved proxy credentials), socks5 or http (CONNECT). No direct fallback.", 16, false, kind),
		input("Proxy address", "host:port only; no URL or embedded credentials. Target DNS is resolved by the proxy.", 1024, false, address),
		input("Proxy login", "Optional; clear the login to disable proxy authentication.", 255, false, user),
		input("Proxy password", "Blank keeps it only when type, address and login are unchanged; otherwise re-enter it.", 1024, true, ""),
	}
}

func (m *Model) prepareImportForm(f *form) bool {
	if f.action == "import" {
		switch m.imp.Phase {
		case ownerdb.ImportStaged:
			// Reopen the retained plan: no second read or unlock, and no form.
			m.push(location{screen: importScreen})
			return false
		case ownerdb.ImportInspecting, ownerdb.ImportApplying:
			m.message = "An import is already running; wait for it to finish."
			return false
		case ownerdb.ImportPartial:
			m.message = "An import is incomplete: use Pending change → resume-import or abort-import."
			return false
		}
		f.fields = []field{
			input("Archive file", "Existing ssjack owner export ZIP; read-only, never modified.", 4096, false, ""),
			input("Archive password", "Encrypted archives only; may differ from the database password. Leave empty for a plaintext archive.", 16384, true, ""),
		}
		return true
	}
	if m.at.screen != importScreen || m.imp.Phase != ownerdb.ImportStaged || len(m.imp.Conflicts) != 0 {
		m.message = "Import is not ready to confirm."
		return false
	}
	f.scopeLabel = "Archive: " + previewCounts(m.imp.Preview) + ". Imports servers, SSH credentials and secret values into this database; secret values are published to the linked application store as new versions. Existing entries are never overwritten."
	f.fields = []field{input("Confirmation", "Type IMPORT to apply. Esc cancels; nothing was changed yet.", 16, false, "")}
	return true
}

// performImport runs off the UI goroutine. Inspection is waited for (Argon2
// can be slow); confirmation only queues the background apply.
func (m *Model) performImport(f *form) error {
	if f.action == "import-confirm" {
		if string(f.fields[0].value) != "IMPORT" {
			return errForm
		}
		return m.backend.ConfirmImport()
	}
	path := string(f.fields[0].value)
	if path == "" {
		return errForm
	}
	// The manager copies the password; the form's own buffer is wiped by clear.
	if err := m.backend.InspectImport(path, f.fields[1].value); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Minute)
	defer cancel()
	return m.backend.Flush(ctx)
}

// importMessage maps a manager error to fixed text; err.Error() is never shown.
func importMessage(err error) string {
	switch {
	case errors.Is(err, ownerarchive.ErrAuthentication):
		return "Import failed: wrong archive password or modified archive. Nothing was changed."
	case errors.Is(err, ownerarchive.ErrArchive):
		return "Import failed: not a valid ssjack owner export. Nothing was changed."
	}
	return "Import failed. Nothing was changed."
}

// importDone consumes the finished import/import-confirm operation.
func (m *Model) importDone(action string, err error) {
	m.imp = m.backend.ImportStatus()
	switch {
	case errors.Is(err, errForm):
		m.message = "Invalid import form: an archive file is required and the confirmation must be exactly IMPORT. Nothing was changed."
	case err != nil:
		m.message = "Import failed or could not be started. Nothing was changed."
	case action == "import-confirm":
		// The apply runs in the background; return to the root and poll.
		m.at, m.stack, m.cursor, m.reselect = location{screen: databaseScreen}, nil, 0, false
		m.message = "Import queued; progress is shown below."
	case m.imp.Phase == ownerdb.ImportStaged:
		m.push(location{screen: importScreen})
	default:
		m.message = importMessage(m.imp.Err)
	}
}

// abortImport drops the staged material; the manager clears it.
func (m *Model) abortImport() {
	if m.backend.AbortImport() != nil {
		m.message = "Import abort failed; use Pending change → abort-import."
	}
	m.imp = ownerdb.ImportStatus{}
}

// importLine is the status line for the latest ImportStatus, fixed text only.
func (m *Model) importLine() string {
	s := m.imp
	total, done := strconv.Itoa(s.Total), strconv.Itoa(s.Published)
	switch s.Phase {
	case ownerdb.ImportInspecting:
		return "Import: inspecting archive…"
	case ownerdb.ImportApplying:
		return "Import: applying — published " + done + " of " + total + " secrets (Esc/abort via Pending change)"
	case ownerdb.ImportPartial:
		return "Import INCOMPLETE: " + done + " of " + total + " secrets published, directory applied=" + strconv.FormatBool(s.DirectoryApplied) + ". Resolve any pending owner change, then use Pending change → resume-import (or abort-import). The remaining values of the plan exist only in this process's memory and are lost if ssjack exits; only the per-secret durable intents persist. Nothing is complete until every value is published."
	case ownerdb.ImportComplete:
		return "Import complete: servers, credentials and " + done + " secrets were added."
	case ownerdb.ImportStaged:
		if m.at.screen != databaseScreen || m.form != nil {
			if s.Err != nil {
				return importMessage(s.Err)
			}
			return ""
		}
		// At the root the staged plan is stranded unless the owner is told how to reach it.
		line := "The archive is staged but not applied: choose Import credentials and values to reopen the staged preview, or use Pending change → abort-import to discard it."
		if s.Err != nil {
			return importMessage(s.Err) + " " + line
		}
		return "Import: " + line
	}
	return ""
}
