package ownertui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestExportFormScopeAndSecretFieldMaskingAndBounds(t *testing.T) {
	b := &fakeBackend{metadata: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{{ID: "server", Name: "production", Accounts: []vault.AccountMetadata{{Name: "deploy"}, {Name: "maintenance"}}}}}}
	m := testModel(b)
	m.at = location{screen: accountScreen, server: "server", account: "deploy"}
	m.openForm("export")
	check(t, m.form == nil || m.form.exportScope.GlobalSecrets || len(m.form.exportScope.Servers["server"]) != 1 || m.form.exportScope.Servers["server"][0] != "deploy" || len(m.form.fields) != 4 || string(m.form.fields[1].value) != "encrypted" || !strings.Contains(m.View().Content, "WARNING") || !strings.Contains(m.form.scopeLabel, "MCP accounts"), "export form did not expose an exact encrypted-default scope")
	m.metadata.Servers[0].Accounts[0].Name = "changed-after-open"
	check(t, m.form.exportScope.Servers["server"][0] != "deploy", "open export scope borrowed mutable metadata")
	fill(m, "synthetic-export.zip", "plaintext")
	check(t, m.perform(m.form) == nil || b.exports != 0, "plaintext export bypassed explicit confirmation")
	m.form.fields[2].value = []byte("EXPORT PLAINTEXT")
	check(t, m.perform(m.form) != nil || b.exports != 1 || b.exportRequest.Selection.GlobalSecrets || b.exportRequest.PlaintextConfirmation != "EXPORT PLAINTEXT", "explicit export lost its captured scope or format")
	m.back()
	m.metadata.Servers[0].Accounts[0].Name = "deploy"
	m.openForm("export")
	check(t, m.form == nil, "export cancellation fixture did not open")
	m.back()
	check(t, b.exports != 1, "cancelled export invoked the backend")
	b = &fakeBackend{} // a pre-cancelled context must not queue an artifact
	m = testModel(b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.ctx = ctx
	open(m, "export", "synthetic-export.zip")
	check(t, m.perform(m.form) == nil || b.exports != 0, "pre-cancelled export queued an artifact")
	m.back()
	// Display escaping and secret masking: no terminal injection, no visible secret.
	got := escaped("user\x1b[31m\nnext")
	check(t, strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, "\\x1b"), "owner metadata could inject terminal control sequences")
	f := form{fields: []field{{label: "Secret", secret: true, limit: 32}}}
	f.insert("synthetic-secret")
	check(t, strings.Contains(f.display(0), "synthetic-secret") || f.display(0) != "<hidden; entered>", "secret form field exposed its value")
	owned := f.fields[0].value
	f.clear()
	check(t, !zeroed(owned) || len(f.fields[0].value) != 0, "cancelled form did not clear owned secret input")
	old := []byte("synthetic-input")
	g := form{fields: []field{{value: old, secret: true, limit: 4096}}}
	g.insert("-next")
	check(t, string(g.fields[0].value) != "synthetic-input-next" || cap(g.fields[0].value) != 4096 || !zeroed(old), "input did not allocate its bounded owned buffer or growth retained the superseded bytes")
	g.clear()
	f = form{fields: []field{{label: "Name", limit: 8}}}
	f.insert("é")
	f.backspace()
	check(t, len(f.fields[0].value) != 0, "backspace split a Unicode code point")
	f.insert("12345678")
	f.insert("9")
	check(t, string(f.fields[0].value) != "12345678", "input field exceeded its byte limit")
	f.move(1)
	f.insert("button-input")
	check(t, f.focus != 1 || string(f.fields[0].value) != "12345678", "focused action button modified input fields")
	f.move(1)
	cancelFocus := f.focus
	f.move(1)
	check(t, cancelFocus != 2 || f.focus != 0, "cancel button was unreachable or focus did not wrap to the first field")
	f.clear()
}

func pickerMetadata() vault.DirectoryMetadata {
	return vault.DirectoryMetadata{Servers: []vault.ServerMetadata{
		{ID: "s1", Name: "production", Address: "prod.example:22", Accounts: []vault.AccountMetadata{{Name: "agent", User: "bot", Authentication: "key", Usage: "agent"}, {Name: "deploy", User: "root\x1b[31m", Authentication: "password", Usage: "both"}}},
		{ID: "s2", Name: "other", Address: "other.example:22", Accounts: []vault.AccountMetadata{{Name: "admin", User: "admin", Authentication: "key", Usage: "human"}}},
	}}
}
func points(ids ...string) (metadata vault.DirectoryMetadata) {
	for _, id := range ids {
		metadata.Servers = append(metadata.Servers, vault.ServerMetadata{ID: id, Name: id, Address: id + ".example:22", Accounts: []vault.AccountMetadata{{Name: "main", User: "u", Authentication: "key", Usage: "both"}}})
	}
	return metadata
}
func press(m *Model, c rune) tea.Cmd { _, cmd := m.Update(tea.KeyPressMsg{Code: c}); return cmd }

func TestPickerListsEmptyHumanOnlyKeepsBackCtrlCEnterAndRefreshFocus(t *testing.T) {
	empty := testModel(&fakeBackend{})
	items := navigation(empty.at, empty.metadata)
	check(t, len(items) != 9 || items[0].action != "none" || items[0].label != "(no SSH connections available)" || items[3].target.screen != mcpDirectoryScreen || items[4].action != "export" || items[5].action != "import", "empty database lacks the placeholder, import or management items")
	check(t, press(empty, 13) != nil || empty.connection != nil || empty.message == "" || empty.at.screen != databaseScreen, "placeholder was actionable")
	press(empty, tea.KeyDown)
	press(empty, 13)
	check(t, empty.at.screen != serversScreen, "management was unreachable below the placeholder")
	items = navigation(location{screen: databaseScreen}, pickerMetadata())
	check(t, len(items) != 10 || items[0].action != "connect" || items[1].action != "connect" || items[2].label != "Servers" || items[4].target.screen != mcpDirectoryScreen || items[6].action != "import" || items[9].action != "exit" ||
		items[0].target != (location{server: "s1", account: "deploy"}) || items[1].target != (location{server: "s2", account: "admin"}), "root did not list exactly the human-permitted connection points first")
	label := items[0].label
	check(t, strings.ContainsAny(label, "\x1b\n") || !strings.Contains(label, escaped("production")) || !strings.Contains(label, escaped("prod.example:22")) || !strings.Contains(label, `\x1b`) || !strings.Contains(label, "password"), "connection label did not identify the escaped server and account")
	b := &fakeBackend{metadata: pickerMetadata()}
	m := testModel(b)
	for account, want := range map[string]int{"deploy": 3, "agent": 2} {
		must(t, m.Select("production", account))
		items := navigation(m.at, m.metadata)
		check(t, len(items) != want || (items[0].action == "connect") != (want == 3) || items[want-2].action != "edit-account" || (want == 3 && items[0].label != "Connect via SSH"), "account screen Connect item is not human-only")
	}
	_, ok := m.TakeConnection()
	check(t, ok || b.closes != 0, "named selection created a connection")
	must(t, m.Select("production", ""))
	press(m, 27)
	check(t, m.at.screen != serversScreen, "Escape did not go back")
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	check(t, cmd == nil || !m.working, "Ctrl+C did not request a bounded close")
	_, next := m.Update(cmd())
	check(t, b.closes != 1 || m.working || next == nil, "Ctrl+C did not close through the backend and quit")
	b = &fakeBackend{metadata: pickerMetadata()}
	m = testModel(b)
	check(t, press(m, tea.KeyRight) != nil || m.connection != nil, "only Enter may start a connection")
	cmd = press(m, 13)
	check(t, cmd == nil, "Enter on a connection point did not quit the program")
	_, quit := cmd().(tea.QuitMsg)
	check(t, !quit || b.closes != 0, "selection closed the database or did not quit")
	c, ok := m.TakeConnection()
	_, again := m.TakeConnection()
	check(t, !ok || c != (Connection{ServerID: "s1", Account: "deploy"}) || again, "selection recorded the wrong request or did not clear it when taken")
	m.working, m.quitting = true, true
	m.Connected(0, errors.New("synthetic-error-secret"))
	check(t, m.working || m.quitting || strings.Contains(m.View().Content, "synthetic-error-secret") || !strings.Contains(m.message, "failed"), "connection failure leaked raw error text or left the model busy")
	m.Connected(3, nil)
	check(t, !strings.Contains(m.message, "exit code 3"), "exit code was not reported")
	m = testModel(&fakeBackend{})
	m.metadata = points("a", "b")
	press(m, tea.KeyDown)
	m.Update(refreshMsg{metadata: points("new", "a", "b")})
	press(m, 13)
	c, ok = m.TakeConnection()
	check(t, m.reselect || !ok || c != (Connection{ServerID: "b", Account: "main"}), "focus did not follow the item to its new index")
	moved := points("a", "b")
	moved.Servers[1].Address = "moved.example:22"
	for i, next := range []vault.DirectoryMetadata{moved, points("a")} {
		m = testModel(&fakeBackend{metadata: points("a", "b")})
		press(m, tea.KeyDown)
		m.Connected(0, nil)
		m.Update(refreshMsg{metadata: next})
		check(t, press(m, 13) != nil || m.connection != nil || m.cursor != 0 || m.message != reselectMessage, "Enter acted on a changed list")
		press(m, tea.KeyDown)
		press(m, 13)
		check(t, m.reselect || m.message == reselectMessage || (m.connection != nil) != (i == 0), "deliberate reselection did not re-enable activation on the new focus")
	}
	check(t, m.activate(item{label: "Connect: stale", target: location{server: "gone", account: "main"}, action: "connect"}, true) != nil || m.connection != nil || m.message != "That connection is no longer available.", "a vanished account was recorded for connection")
}

func stagedBackend() *fakeBackend {
	return &fakeBackend{imp: ownerdb.ImportStatus{Phase: ownerdb.ImportStaged, Preview: vault.ImportPreview{Encrypted: true,
		Servers: []vault.ImportServer{{Name: "prod\x1b", Address: "h:22", Fingerprints: []string{"SHA256:fp"}, Accounts: []vault.ImportAccount{{Name: "main", User: "u", Authentication: "key", Usage: "both"}}}},
		Secrets: []vault.ImportSecret{{Name: "token", ServerID: "id", ServerName: "prod", Length: 7}}}}}
}
func paste(m *Model, text string) { m.Update(tea.PasteMsg{Content: text}) }

// openImport focuses the root Import item and presses Enter.
func openImport(m *Model) {
	for i := 0; m.items()[i].action != "import"; i++ {
		press(m, tea.KeyDown)
	}
	press(m, 13)
}

func TestImportModelFlowsPreviewsPhasesConfirmationAndFixedMessages(t *testing.T) {
	b := stagedBackend()
	m := testModel(b)
	openImport(m)
	check(t, m.form == nil || m.form.action != "import" || len(m.form.fields) != 2 || m.form.fields[0].secret || !m.form.fields[1].secret, "import form lacks its file field or masked password")
	paste(m, "archive.zip")
	press(m, 9)
	paste(m, "synthetic-archive-password")
	owned := m.form.fields[1].value
	view := m.View().Content
	check(t, strings.Contains(view, "synthetic-archive-password") || !strings.Contains(view, "<hidden; entered>") || !strings.Contains(view, "Archive password"), "password was shown")
	press(m, 9)
	cmd := press(m, 13)
	check(t, cmd == nil || len(b.calls) != 0, "Apply inspected synchronously")
	m.Update(cmd())
	check(t, strings.Join(b.calls, ",") != "inspect" || strings.Join(b.args, "|") != "archive.zip|synthetic-archive-password" || !zeroed(owned) || m.at.screen != importScreen || m.working || m.form != nil, "inspection lost input or kept the password buffer, or staged status did not open the preview")
	view = m.View().Content
	for _, want := range []string{"Import preview — nothing is applied until you confirm", "[Confirm import…]", "[Cancel import]", "Archive: encrypted — 1 servers, 1 accounts, 1 secrets (values hidden)", `Server "prod\x1b" / "h:22" / host key "SHA256:fp"`, `Account "main" / login "u" / "key" / usage "both"`, `Secret "token" / scope: server "prod" / 7 bytes`} {
		check(t, !strings.Contains(view, want), "preview omitted "+want)
	}
	check(t, strings.Contains(view, "synthetic-archive-password"), "preview exposed the archive password")
	press(m, 13)
	check(t, m.form == nil || m.form.action != "import-confirm", "Confirm did not open its form")
	paste(m, "IMPORT")
	press(m, 13)
	cmd = press(m, 13)
	check(t, cmd == nil || len(b.calls) != 1, "confirmation executed synchronously")
	m.Update(cmd())
	check(t, strings.Join(b.calls, ",") != "inspect,confirm" || m.at.screen != databaseScreen || len(m.stack) != 0 || m.form != nil || m.working, "confirmation did not queue once and return to the root")
	b = stagedBackend()
	m = testModel(b)
	show := func() { b.calls, m.imp = nil, b.imp; m.push(location{screen: importScreen}) }
	aborted := func(what string) {
		check(t, strings.Join(b.calls, ",") != "abort" || m.at.screen != databaseScreen || b.closes != 0, what+" did not abort once and pop")
	}
	show()
	m.cursor = len(m.items()) - 1
	check(t, press(m, 13) != nil || m.message != "" || m.at.screen != importScreen || len(b.calls) != 0, "an info row was actionable")
	m.cursor = 1
	m.Update(refreshMsg{imports: b.imp})
	check(t, m.reselect || m.cursor != 1, "an unchanged preview triggered reselection")
	press(m, 27)
	aborted("Escape")
	show()
	press(m, tea.KeyDown)
	press(m, 13)
	aborted("[Cancel import]")
	show()
	m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	aborted("Ctrl+C")
	show()
	m.cursor = 0
	m.Update(refreshMsg{imports: ownerdb.ImportStatus{Phase: ownerdb.ImportStaged, Preview: b.imp.Preview, Conflicts: []vault.ImportConflict{{Kind: "server-name", Subject: "pro\x1bd"}}}})
	check(t, !m.reselect || press(m, 13) != nil || m.form != nil, "a vanished Confirm item stayed activatable")
	items := m.items()
	check(t, items[0].action != "info" || items[1].label != "Conflict: server-name — "+escaped("pro\x1bd") || items[2].action != "import-cancel", "conflict preview rows are wrong")
	for _, entry := range items {
		check(t, entry.action == "import-confirm", "conflict preview offers Confirm")
	}
	m.openForm("import-confirm")
	check(t, m.form != nil || !strings.Contains(m.View().Content, "Import refused: conflicts"), "conflicted import could be confirmed")
	// Root reopens a stranded staged plan and guards the other phases.
	b = &fakeBackend{}
	m = testModel(b)
	m.imp = stagedBackend().imp
	m.imp.Err = vault.ErrImportConflict // stranded: a confirm failed without effects
	view = m.View().Content
	check(t, !strings.Contains(view, "staged but not applied") || !strings.Contains(view, "reopen the staged preview"), "root did not say how to reach the stranded plan")
	openImport(m)
	check(t, m.at.screen != importScreen || m.form != nil || len(b.calls) != 0 || !strings.Contains(m.View().Content, "Import preview"), "reopening inspected again or showed no preview")
	press(m, 27)
	check(t, strings.Join(b.calls, ",") != "abort" || m.at.screen != databaseScreen, "Escape did not abort the reopened plan exactly once")
	running, partial := "An import is already running; wait for it to finish.", "An import is incomplete: use Pending change → resume-import or abort-import."
	for phase, want := range map[ownerdb.ImportPhase]string{ownerdb.ImportInspecting: running, ownerdb.ImportApplying: running, ownerdb.ImportPartial: partial} {
		b.calls, m = nil, testModel(b)
		m.imp = ownerdb.ImportStatus{Phase: phase}
		openImport(m)
		check(t, m.form != nil || m.at.screen != databaseScreen || len(m.stack) != 0 || m.message != want || len(b.calls) != 0, "Import in phase "+string(phase)+" did not refuse with its fixed message")
	}
	for _, phase := range []ownerdb.ImportPhase{ownerdb.ImportIdle, ownerdb.ImportComplete} {
		m = testModel(b)
		m.imp = ownerdb.ImportStatus{Phase: phase}
		openImport(m)
		check(t, m.form == nil || m.form.action != "import", "Import in phase "+string(phase)+" did not open the form")
	}
	// Exact confirmation text and pending import commands.
	b = stagedBackend()
	m = testModel(b)
	m.imp = b.imp
	m.push(location{screen: importScreen})
	open(m, "import-confirm", "import")
	check(t, m.form == nil || !strings.Contains(m.form.scopeLabel, "1 servers, 1 accounts, 1 secrets") || !strings.Contains(m.form.scopeLabel, "Existing entries are never overwritten."), "confirm form lacks its summary")
	check(t, !errors.Is(m.perform(m.form), errForm) || len(b.calls) != 0, "confirmation was not exact")
	press(m, 27)
	check(t, m.at.screen != importScreen || len(b.calls) != 0, "cancelling the confirm form left the preview or called the backend")
	open(m, "import-confirm", "IMPORT")
	must(t, m.perform(m.form))
	check(t, strings.Join(b.calls, ",") != "confirm", "exact confirmation did not call ConfirmImport once")
	m.back()
	for action, want := range map[string]string{"resume-import": "resume", "abort-import": "abort"} {
		b.calls = nil
		pending := testModel(b)
		open(pending, "pending", action)
		check(t, !strings.Contains(pending.form.fields[0].help, "resume-import or abort-import"), "pending help omits the import commands")
		must(t, pending.perform(pending.form))
		check(t, strings.Join(b.calls, ",") != want, action+" was not dispatched")
	}
	// Fixed failure messages and status lines.
	raw := errors.New("synthetic-error-secret")
	for err, want := range map[error]string{
		ownerarchive.ErrAuthentication: "Import failed: wrong archive password or modified archive. Nothing was changed.",
		ownerarchive.ErrArchive:        "Import failed: not a valid ssjack owner export. Nothing was changed.",
		raw:                            "Import failed. Nothing was changed.",
	} {
		m := testModel(&fakeBackend{imp: ownerdb.ImportStatus{Err: err}})
		m.importDone("import", nil)
		check(t, m.at.screen != databaseScreen || len(m.stack) != 0 || m.message != want || strings.Contains(m.View().Content, "synthetic-error-secret"), "failed inspection pushed a screen or showed unfixed text")
		m.importDone("import", raw)
		check(t, !strings.HasPrefix(m.message, "Import failed") || strings.Contains(m.message, "synthetic"), "a queue failure showed raw error text")
	}
	m = testModel(&fakeBackend{})
	for want, status := range map[string]ownerdb.ImportStatus{
		"Import: applying — published 2 of 5 secrets":                          {Phase: ownerdb.ImportApplying, Published: 2, Total: 5},
		"Import INCOMPLETE: 2 of 5 secrets published, directory applied=true.": {Phase: ownerdb.ImportPartial, Published: 2, Total: 5, DirectoryApplied: true},
		"Import complete: servers, credentials and 5 secrets were added.":      {Phase: ownerdb.ImportComplete, Published: 5, Total: 5},
		"Import failed. Nothing was changed.":                                  {Phase: ownerdb.ImportStaged, Err: vault.ErrImportConflict},
	} {
		m.imp = status
		check(t, !strings.Contains(m.View().Content, want), "status line missing: "+want)
	}
	m.imp = ownerdb.ImportStatus{Phase: ownerdb.ImportPartial, Published: 1, Total: 2}
	check(t, !strings.Contains(m.View().Content, "only in this process's memory"), "partial line omits that the remaining values are RAM-only")
}
