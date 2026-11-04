package ownertui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestNavigationKeepsServerSecretScopesSeparate(t *testing.T) {
	metadata := vault.DirectoryMetadata{Secrets: map[string]vault.SecretBinding{
		"global": {Name: "token", Ref: "global-reference"},
		"first":  {Name: "token", ServerID: "first-server", Ref: "first-reference"},
		"second": {Name: "token", ServerID: "second-server", Ref: "second-reference"},
	}}
	for scope, want := range map[string]string{"": "global", "first-server": "first", "second-server": "second"} {
		items := navigation(location{screen: secretsScreen, server: scope}, metadata)
		count := 2
		if scope == "" {
			count++
		}
		if len(items) != count || items[1].target.secret != want || items[1].target.server != scope {
			t.Fatal("navigation selected another server's secret or a global fallback")
		}
	}
}

func TestNamedStartupOpensOnlyTheSelectedServerOrAccount(t *testing.T) {
	b := &fakeBackend{metadata: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{
		{ID: "first", Name: "production", Accounts: []vault.AccountMetadata{{Name: "deploy"}, {Name: "maintenance"}}},
		{ID: "second", Name: "other", Accounts: []vault.AccountMetadata{{Name: "deploy"}}},
	}}}
	m := testModel(b)
	if err := m.Select("production", "maintenance"); err != nil {
		t.Fatal(err)
	}
	if m.at.server != "first" || m.at.account != "maintenance" || m.at.screen != accountScreen {
		t.Fatal("startup selection crossed the server/account scope")
	}
	m.back()
	if m.at.screen != serverScreen || m.at.server != "first" {
		t.Fatal("selected account lost its parent server")
	}
	m.back()
	m.back()
	before := m.at
	if err := m.Select("missing", "deploy"); err == nil || m.at != before {
		t.Fatal("unknown startup server silently fell back")
	}
	if err := m.Select("production", "missing"); err == nil || m.at != before {
		t.Fatal("unknown startup account silently fell back")
	}
	if err := m.Select("production", ""); err != nil || m.at.screen != serverScreen {
		t.Fatal("interactive server selection did not expose its explicit account list")
	}
	if b.edits != 0 || b.submissions != 0 || b.closes != 0 {
		t.Fatal("startup selection performed a mutation")
	}
}

func TestExportFormCapturesScopeDefaultsEncryptedAndRequiresPlaintextConfirmation(t *testing.T) {
	b := &fakeBackend{metadata: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{{ID: "server", Name: "production", Accounts: []vault.AccountMetadata{{Name: "deploy"}, {Name: "maintenance"}}}}}}
	m := testModel(b)
	m.at = location{screen: accountScreen, server: "server", account: "deploy"}
	m.openForm("export")
	if m.form == nil || m.form.exportScope.GlobalSecrets || len(m.form.exportScope.Servers["server"]) != 1 || m.form.exportScope.Servers["server"][0] != "deploy" || string(m.form.fields[1].value) != "encrypted" || !strings.Contains(m.View().Content, "WARNING") {
		t.Fatal("export form did not expose an exact encrypted-default scope")
	}
	m.metadata.Servers[0].Accounts[0].Name = "changed-after-open"
	if m.form.exportScope.Servers["server"][0] != "deploy" {
		t.Fatal("open export scope borrowed mutable metadata")
	}
	m.form.fields[0].value = []byte("synthetic-export.zip")
	m.form.fields[1].value = []byte("plaintext")
	if err := m.perform(m.form); err == nil || b.exports != 0 {
		t.Fatal("plaintext export bypassed explicit confirmation")
	}
	m.form.fields[2].value = []byte("EXPORT PLAINTEXT")
	if err := m.perform(m.form); err != nil || b.exports != 1 || b.exportRequest.Selection.GlobalSecrets || b.exportRequest.PlaintextConfirmation != "EXPORT PLAINTEXT" {
		t.Fatal("explicit export lost its captured scope or format")
	}
	m.back()
	m.metadata.Servers[0].Accounts[0].Name = "deploy"
	m.openForm("export")
	if m.form == nil {
		t.Fatal("export cancellation fixture did not open")
	}
	m.back()
	if b.exports != 1 {
		t.Fatal("cancelled export invoked the backend")
	}
}

func TestPreCancelledExportDoesNotQueueAnArtifact(t *testing.T) {
	b := &fakeBackend{}
	m := testModel(b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.ctx = ctx
	m.openForm("export")
	m.form.fields[0].value = []byte("synthetic-export.zip")
	if err := m.perform(m.form); err == nil || b.exports != 0 {
		t.Fatal("pre-cancelled export queued an artifact")
	}
	m.back()
}

func TestDisplayEscapesTerminalControlSequences(t *testing.T) {
	got := escaped("user\x1b[31m\nnext")
	if strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, "\\x1b") {
		t.Fatal("owner metadata could inject terminal control sequences")
	}
}

func TestSecretFieldMasksInputAndClearsCancelledBytes(t *testing.T) {
	f := form{fields: []field{{label: "Secret", secret: true, limit: 32}}}
	f.insert("synthetic-secret")
	if strings.Contains(f.display(0), "synthetic-secret") || f.display(0) != "<hidden; entered>" {
		t.Fatal("secret form field exposed its value")
	}
	owned := f.fields[0].value
	f.clear()
	if !bytes.Equal(owned, make([]byte, len(owned))) || len(f.fields[0].value) != 0 {
		t.Fatal("cancelled form did not clear owned secret input")
	}
}

func TestInputGrowthClearsSupersededBuffer(t *testing.T) {
	old := []byte("synthetic-input")
	f := form{fields: []field{{value: old, secret: true, limit: 4096}}}
	f.insert("-next")
	if string(f.fields[0].value) != "synthetic-input-next" || cap(f.fields[0].value) != 4096 {
		t.Fatal("input did not allocate its bounded owned buffer")
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("input growth retained the superseded bytes")
	}
	f.clear()
}

func TestFieldBoundsUnicodeBackspaceAndButtonFocus(t *testing.T) {
	f := form{fields: []field{{label: "Name", limit: 8}}}
	f.insert("é")
	f.backspace()
	if len(f.fields[0].value) != 0 {
		t.Fatal("backspace split a Unicode code point")
	}
	f.insert("12345678")
	f.insert("9")
	if string(f.fields[0].value) != "12345678" {
		t.Fatal("input field exceeded its byte limit")
	}
	f.move(1)
	f.insert("button-input")
	if f.focus != 1 || string(f.fields[0].value) != "12345678" {
		t.Fatal("focused action button modified input fields")
	}
	f.move(1)
	cancel := f.focus
	f.move(1)
	if cancel != 2 || f.focus != 0 {
		t.Fatal("cancel button was unreachable or focus did not wrap to the first field")
	}
	f.clear()
}

func pickerMetadata() vault.DirectoryMetadata {
	return vault.DirectoryMetadata{Servers: []vault.ServerMetadata{
		{ID: "s1", Name: "production", Address: "prod.example:22", Accounts: []vault.AccountMetadata{{Name: "agent", User: "bot", Authentication: "key", Usage: "agent"}, {Name: "deploy", User: "root\x1b[31m", Authentication: "password", Usage: "both"}}},
		{ID: "s2", Name: "other", Address: "other.example:22", Accounts: []vault.AccountMetadata{{Name: "admin", User: "admin", Authentication: "key", Usage: "human"}}},
	}}
}

func points(ids ...string) vault.DirectoryMetadata {
	var servers []vault.ServerMetadata
	for _, id := range ids {
		servers = append(servers, vault.ServerMetadata{ID: id, Name: id, Address: id + ".example:22", Accounts: []vault.AccountMetadata{{Name: "main", User: "u", Authentication: "key", Usage: "both"}}})
	}
	return vault.DirectoryMetadata{Servers: servers}
}

func press(m *Model, code rune) tea.Cmd {
	_, cmd := m.Update(tea.KeyPressMsg{Code: code})
	return cmd
}

func TestPickerListsEmptyHumanOnlyAndKeepsBackAndCtrlC(t *testing.T) {
	empty := testModel(&fakeBackend{})
	items := navigation(empty.at, empty.metadata)
	if len(items) != 7 || items[0].action != "none" || items[0].label != "(no SSH connections available)" {
		t.Fatal("empty database lacks the placeholder or management items")
	}
	if cmd := press(empty, 13); cmd != nil || empty.connection != nil || empty.message == "" || empty.at.screen != databaseScreen {
		t.Fatal("placeholder was actionable")
	}
	press(empty, tea.KeyDown)
	press(empty, 13)
	if empty.at.screen != serversScreen {
		t.Fatal("management was unreachable below the placeholder")
	}
	items = navigation(location{screen: databaseScreen}, pickerMetadata())
	if len(items) != 8 || items[0].action != "connect" || items[1].action != "connect" || items[2].label != "Servers" || items[7].action != "exit" ||
		items[0].target != (location{server: "s1", account: "deploy"}) || items[1].target != (location{server: "s2", account: "admin"}) {
		t.Fatal("root did not list exactly the human-permitted connection points first")
	}
	label := items[0].label
	if strings.ContainsAny(label, "\x1b\n") || !strings.Contains(label, escaped("production")) || !strings.Contains(label, escaped("prod.example:22")) || !strings.Contains(label, `\x1b`) || !strings.Contains(label, "password") {
		t.Fatal("connection label did not identify the escaped server and account")
	}
	b := &fakeBackend{metadata: pickerMetadata()}
	m := testModel(b)
	for account, want := range map[string]int{"deploy": 3, "agent": 2} {
		if err := m.Select("production", account); err != nil {
			t.Fatal(err)
		}
		items := navigation(m.at, m.metadata)
		if len(items) != want || (items[0].action == "connect") != (want == 3) || items[want-2].action != "edit-account" || (want == 3 && items[0].label != "Connect via SSH") {
			t.Fatal("account screen Connect item is not human-only")
		}
	}
	if _, ok := m.TakeConnection(); ok || b.closes != 0 {
		t.Fatal("named selection created a connection")
	}
	if err := m.Select("production", ""); err != nil {
		t.Fatal(err)
	}
	if press(m, 27); m.at.screen != serversScreen {
		t.Fatal("Escape did not go back")
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if cmd == nil || !m.working {
		t.Fatal("Ctrl+C did not request a bounded close")
	}
	if _, next := m.Update(cmd()); b.closes != 1 || m.working || next == nil {
		t.Fatal("Ctrl+C did not close through the backend and quit")
	}
}

func TestEnterOnConnectionRecordsRequestAndQuitsWithoutClosing(t *testing.T) {
	b := &fakeBackend{metadata: pickerMetadata()}
	m := testModel(b)
	if cmd := press(m, tea.KeyRight); cmd != nil || m.connection != nil {
		t.Fatal("only Enter may start a connection")
	}
	cmd := press(m, 13)
	if cmd == nil {
		t.Fatal("Enter on a connection point did not quit the program")
	}
	if _, quit := cmd().(tea.QuitMsg); !quit || b.closes != 0 {
		t.Fatal("selection closed the database or did not quit")
	}
	c, ok := m.TakeConnection()
	if _, again := m.TakeConnection(); !ok || c != (Connection{ServerID: "s1", Account: "deploy"}) || again {
		t.Fatal("selection recorded the wrong request or did not clear it when taken")
	}
	m.working, m.quitting = true, true
	m.Connected(0, errors.New("synthetic-error-secret"))
	if m.working || m.quitting || strings.Contains(m.View().Content, "synthetic-error-secret") || !strings.Contains(m.message, "failed") {
		t.Fatal("connection failure leaked raw error text or left the model busy")
	}
	if m.Connected(3, nil); !strings.Contains(m.message, "exit code 3") {
		t.Fatal("exit code was not reported")
	}
}

func TestRefreshKeepsFocusOrRequiresReselection(t *testing.T) {
	m := testModel(&fakeBackend{})
	m.metadata = points("a", "b")
	press(m, tea.KeyDown)
	m.Update(refreshMsg{metadata: points("new", "a", "b")})
	press(m, 13)
	if c, ok := m.TakeConnection(); m.reselect || !ok || c != (Connection{ServerID: "b", Account: "main"}) {
		t.Fatal("focus did not follow the item to its new index")
	}
	moved := points("a", "b")
	moved.Servers[1].Address = "moved.example:22"
	for i, next := range []vault.DirectoryMetadata{moved, points("a")} {
		m = testModel(&fakeBackend{})
		m.metadata = points("a", "b")
		press(m, tea.KeyDown)
		m.Update(refreshMsg{metadata: next})
		if cmd := press(m, 13); cmd != nil || m.connection != nil || m.cursor != 0 || m.message != reselectMessage {
			t.Fatal("Enter acted on a changed list")
		}
		press(m, tea.KeyDown)
		press(m, 13)
		if m.reselect || m.message == reselectMessage || (m.connection != nil) != (i == 0) {
			t.Fatal("deliberate reselection did not re-enable activation on the new focus")
		}
	}
	stale := item{label: "Connect: stale", target: location{server: "gone", account: "main"}, action: "connect"}
	if m.activate(stale, true) != nil || m.connection != nil || m.message != "That connection is no longer available." {
		t.Fatal("a vanished account was recorded for connection")
	}
}
