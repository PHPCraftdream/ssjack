package ownertui

import (
	"bytes"
	tea "charm.land/bubbletea/v2"
	"context"
	"errors"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/terminalmodel"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	backend                             // Unused fake methods intentionally panic.
	metadata                            vault.DirectoryMetadata
	status                              ownerdb.Status
	closeErr                            error
	change                              vault.OwnerChange
	exportRequest                       ownerdb.ExportRequest
	imp                                 ownerdb.ImportStatus
	calls                               []string // import calls in order
	args                                []string // InspectImport's path and password, in call order
	edits, submissions, closes, exports int
	mu                                  sync.Mutex // Guards import state and hooks in Program tests.
	on                                  map[string]func(*fakeBackend)
}

func (b *fakeBackend) Metadata() (vault.DirectoryMetadata, error) { return b.metadata, nil }
func (b *fakeBackend) Status() ownerdb.Status                     { return b.status }
func (b *fakeBackend) Edit(func(*vault.Vault) error) error        { b.edits++; return nil }
func (b *fakeBackend) Submit(change vault.OwnerChange) error {
	b.submissions, b.change = b.submissions+1, change
	b.change.Value = append([]byte(nil), change.Value...)
	return nil
}
func (b *fakeBackend) Export(request ownerdb.ExportRequest) error {
	b.exports, b.exportRequest = b.exports+1, request
	return nil
}
func (b *fakeBackend) Flush(context.Context) error { return nil }
func (b *fakeBackend) Close(context.Context) error { b.closes++; return b.closeErr }
func (b *fakeBackend) InspectImport(path string, password []byte) error {
	return b.record("inspect", path, string(password)) // copy now: the form wipes its buffer
}
func (b *fakeBackend) ImportStatus() ownerdb.ImportStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.imp
}
func (b *fakeBackend) ConfirmImport() error { return b.record("confirm") }
func (b *fakeBackend) ResumeImport() error  { return b.record("resume") }
func (b *fakeBackend) AbortImport() error   { return b.record("abort") }
func (b *fakeBackend) record(name string, args ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls, b.args = append(b.calls, name), append(b.args, args...)
	if hook := b.on[name]; hook != nil {
		hook(b)
	}
	return nil
}
func testModel(b *fakeBackend) *Model {
	return &Model{ctx: context.Background(), backend: b, metadata: b.metadata, ready: true, height: 24}
}
func zeroed(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }
func check(t *testing.T, bad bool, msg any) {
	t.Helper()
	if bad {
		t.Fatal(msg)
	}
}
func must(t *testing.T, err error) { t.Helper(); check(t, err != nil, err) }
func fill(m *Model, texts ...string) {
	for i, text := range texts {
		m.form.fields[i].value = []byte(text)
	}
}
func open(m *Model, action string, texts ...string) { m.openForm(action); fill(m, texts...) }
func TestTeaFormsKeepSecretsOwnedAndHiddenRefreshAndCloseStaySafeAndDirectoryFormsKeepAccounts(t *testing.T) {
	b := &fakeBackend{}
	m := testModel(b)
	open(m, "add-secret", "", "synthetic-hidden")
	owned := m.form.fields[1].value
	m.Update(tea.KeyPressMsg{Code: 27})
	check(t, m.form != nil || b.edits != 0 || b.submissions != 0 || m.at.screen != databaseScreen || !zeroed(owned), "Escape did not cancel the form without effects, or cancel retained secret bytes")
	open(m, "add-secret", "token", "synthetic-hidden")
	owned = m.form.fields[1].value
	m.form.focus = len(m.form.fields)
	_, cmd := m.Update(tea.KeyPressMsg{Code: 13})
	check(t, cmd == nil || b.submissions != 0 || !m.working || m.form != nil, "Apply executed synchronously or retained an editable form")
	m.Update(cmd())
	check(t, b.submissions != 1 || string(b.change.Value) != "synthetic-hidden" || m.working || !zeroed(owned), "Apply lost input, did not complete or retained secret bytes")
	b = &fakeBackend{status: ownerdb.Status{Err: errors.New("synthetic-error-secret")}}
	m = testModel(b)
	m.status = b.status
	open(m, "add-secret", "", "synthetic-hidden")
	view := m.View().Content
	check(t, strings.Contains(view, "synthetic-hidden") || strings.Contains(view, "synthetic-error-secret") || !strings.Contains(view, "ERROR") || !strings.Contains(view, "[Cancel]"), "view exposed private data or omitted actionable status or cancellation")
	m.form.focus, m.form.fields[1].value = 1, nil
	m.Update(tea.PasteMsg{Content: "synthetic-paste"})
	check(t, string(m.form.fields[1].value) != "synthetic-paste" || strings.Contains(m.View().Content, "synthetic-paste"), "paste was lost or exposed")
	m.Update(tea.PasteMsg{Content: "\x1b[31m"})
	check(t, string(m.form.fields[1].value) != "synthetic-paste", "paste accepted terminal control input")
	m.back()
	m = testModel(&fakeBackend{})
	_, cmd = m.Update(tickMsg{})
	check(t, cmd == nil, "status refresh chain stopped")
	_, next := m.Update(cmd())
	check(t, next == nil, "refresh did not schedule its successor")
	_, extra := m.Update(operationMsg{})
	check(t, extra != nil, "operation completion started a duplicate polling chain")
	b = &fakeBackend{closeErr: errors.New("unsaved")}
	m = testModel(b)
	cmd = m.requestClose()
	_, next = m.Update(cmd())
	check(t, next != nil || b.closes != 1 || m.working || !strings.Contains(m.message, "Exit stopped"), "failed persistence allowed exit")
	v := vault.NewDirectory()
	defer v.Close()
	m = testModel(&fakeBackend{})
	open(m, "add-server", "production", "localhost:22", "main", "first", "password", "synthetic-first", "both", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA"+strings.Repeat("A", 40)) // a syntactically valid all-zero ed25519 host key
	must(t, editDirectory(v, m.form))
	m.back()
	id, err := v.ServerID("production")
	must(t, err)
	m.at = location{screen: serverScreen, server: id}
	open(m, "add-account", "second", "another", "password", "synthetic-second", "human")
	must(t, editDirectory(v, m.form))
	check(t, editDirectory(v, m.form) == nil, "add silently overwrote an account")
	m.back()
	first, _ := v.AccountProfile(id, "main")
	second, _ := v.AccountProfile(id, "second")
	check(t, first == second || string(v.Targets[first].Password) != "synthetic-first" || string(v.Targets[second].Password) != "synthetic-second", "account form lost or shared another account's credentials")
	m.at = location{screen: accountScreen, server: id, account: "second"}
	open(m, "edit-account", "second", "changed", "password", "", "human")
	must(t, editDirectory(v, m.form))
	check(t, string(v.Targets[second].Password) != "synthetic-second" || v.Targets[second].User != "changed", "blank credential did not preserve selected account")
	m.form.fields[2].value = []byte("key")
	check(t, editDirectory(v, m.form) == nil, "authentication switch reused the wrong credential kind")
	check(t, editServer(v, id, "changed:2222", "invalid pin") == nil || v.Targets[first].Address != "localhost:22" || v.Targets[second].Address != "localhost:22", "invalid server edit partially changed accounts")
	must(t, editServer(v, id, "changed:2222", ""))
	check(t, v.Targets[first].Address != "changed:2222" || v.Targets[second].Address != "changed:2222" || string(v.Targets[first].Password) != "synthetic-first" || string(v.Targets[second].Password) != "synthetic-second", "server edit lost account metadata or credentials")
	m.back()
	m.at = location{screen: serverScreen, server: id}
	open(m, "edit-proxy", "socks5", "proxy.invalid:1080", "operator", "synthetic-proxy-private")
	owned = m.form.fields[3].value
	check(t, !m.form.fields[3].secret || strings.Contains(m.View().Content, "synthetic-proxy-private") || !strings.Contains(m.form.scopeLabel, "not encrypted"), "proxy form exposed authentication or omitted the wire warning")
	m.back()
	check(t, !zeroed(owned) || v.Targets[first].Proxy != nil, "cancelled proxy form retained credentials or changed the route")
	open(m, "edit-proxy", "socks5", "proxy.invalid:1080", "operator", "synthetic-proxy-private")
	must(t, editDirectory(v, m.form))
	check(t, v.Targets[first].Proxy.Type != "socks5" || v.Targets[second].Proxy.Address != "proxy.invalid:1080", "proxy form did not update all server accounts")
	m.back()
	open(m, "edit-proxy", "socks5", "proxy.invalid:1080", "operator", "")
	must(t, editDirectory(v, m.form))
	check(t, string(v.Targets[first].Proxy.Password) != "synthetic-proxy-private", "blank proxy password lost an unchanged credential")
	m.form.fields[1].value = []byte("other.invalid:1080")
	check(t, editDirectory(v, m.form) == nil || v.Targets[first].Proxy.Address != "proxy.invalid:1080", "proxy form silently sent an old password to a new endpoint")
	m.form.fields[0].value = []byte("direct")
	must(t, editDirectory(v, m.form))
	check(t, v.Targets[first].Proxy != nil || v.Targets[second].Proxy != nil, "direct mode left another account proxied")
	m.back()
}
func TestNavigationKeepsServerSecretScopesSeparateAndNamedStartupStaysScoped(t *testing.T) {
	metadata := vault.DirectoryMetadata{Secrets: map[string]vault.SecretBinding{
		"global": {Name: "token", Ref: "global-reference"},
		"first":  {Name: "token", ServerID: "first-server", Ref: "first-reference"},
		"second": {Name: "token", ServerID: "second-server", Ref: "second-reference"},
	}}
	for scope, want := range map[string]string{"": "global", "first-server": "first", "second-server": "second"} {
		items := navigation(location{screen: secretsScreen, server: scope}, metadata)
		count := map[bool]int{true: 3, false: 2}[scope == ""]
		check(t, len(items) != count || items[1].target.secret != want || items[1].target.server != scope, "navigation selected another server's secret or a global fallback")
	}
	b := &fakeBackend{metadata: vault.DirectoryMetadata{Servers: []vault.ServerMetadata{
		{ID: "first", Name: "production", Accounts: []vault.AccountMetadata{{Name: "deploy"}, {Name: "maintenance"}}},
		{ID: "second", Name: "other", Accounts: []vault.AccountMetadata{{Name: "deploy"}}},
	}}}
	m := testModel(b)
	must(t, m.Select("production", "maintenance"))
	check(t, m.at.server != "first" || m.at.account != "maintenance" || m.at.screen != accountScreen, "startup selection crossed the server/account scope")
	m.back()
	check(t, m.at.screen != serverScreen || m.at.server != "first", "selected account lost its parent server")
	m.back()
	m.back()
	before := m.at
	check(t, m.Select("missing", "deploy") == nil || m.at != before || m.Select("production", "missing") == nil || m.at != before, "unknown startup server or account silently fell back")
	check(t, m.Select("production", "") != nil || m.at.screen != serverScreen || b.edits != 0 || b.submissions != 0 || b.closes != 0, "interactive server selection did not expose its explicit account list, or startup selection performed a mutation")
}

type terminalBuffer = terminalmodel.Output

func waitOutput(t *testing.T, out *terminalBuffer, text string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(out.String(), text); time.Sleep(5 * time.Millisecond) {
		check(t, time.Now().After(deadline), "timed out waiting for expected terminal output")
	}
}

func startProgram(t *testing.T, b *fakeBackend) (*Model, *tea.Program, *terminalBuffer, func() string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model := testModel(b)
	model.ctx = ctx
	output := &terminalBuffer{}
	program := tea.NewProgram(terminalmodel.Capture(model, output), tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(output), tea.WithWindowSize(100, 30), tea.WithEnvironment([]string{"TERM=dumb"}), tea.WithoutSignalHandler())
	done := make(chan error, 1)
	go func() { _, err := program.Run(); done <- err }()
	return model, program, output, func() string { must(t, <-done); return output.Raw() }
}
func send(p *tea.Program, msgs ...tea.Msg) {
	for _, msg := range msgs {
		p.Send(msg)
	}
}
func downTo(p *tea.Program, b *fakeBackend, action string) {
	for i := 0; navigation(location{screen: databaseScreen}, b.metadata)[i].action != action; i++ {
		p.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
}
func TestBubbleTeaProgramNavigatesCancelsClosesAndKeepsSingleConnection(t *testing.T) {
	backend := &fakeBackend{}
	model, program, _, wait := startProgram(t, backend)
	send(program, tea.KeyPressMsg{Code: tea.KeyDown}, tea.KeyPressMsg{Code: tea.KeyDown}, tea.KeyPressMsg{Code: 13}, tea.KeyPressMsg{Code: 13}, tea.PasteMsg{Content: "token"}, tea.KeyPressMsg{Code: 9}, tea.PasteMsg{Content: "synthetic-terminal-private"}, tea.KeyPressMsg{Code: 27}, tea.KeyPressMsg{Code: 27})
	downTo(program, backend, "exit")
	program.Send(tea.KeyPressMsg{Code: 13})
	output := wait()
	check(t, backend.closes != 1 || backend.edits != 0 || backend.submissions != 0 || model.form != nil, "program did not cancel input and close without mutation")
	check(t, !strings.Contains(output, "owner database") || strings.Contains(output, "synthetic-terminal-private"), "terminal renderer omitted the interface or exposed input")
	backend = &fakeBackend{metadata: points("only")}
	model, program, _, wait = startProgram(t, backend)
	send(program, tea.KeyPressMsg{Code: tea.KeyDown}, tea.KeyPressMsg{Code: tea.KeyUp}, tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	output = wait()
	_, ok := model.TakeConnection()
	check(t, ok || backend.closes != 1 || !strings.Contains(output, escaped("only")), "a single connection point was activated, or exit did not close once")
}

const archivePassword = "synthetic-archive-password" // Wait for stable rendered output before sending more keys.

func importBackend(inspected ownerdb.ImportStatus) *fakeBackend {
	return &fakeBackend{on: map[string]func(*fakeBackend){
		"inspect": func(f *fakeBackend) { f.imp = inspected },
		"confirm": func(f *fakeBackend) {
			f.imp = ownerdb.ImportStatus{Phase: ownerdb.ImportComplete, Published: 1, Total: 1}
		},
		"abort": func(f *fakeBackend) { f.imp = ownerdb.ImportStatus{} },
	}}
}
func importFlow(t *testing.T, b *fakeBackend) (*tea.Program, *terminalBuffer, func() string) {
	_, program, out, wait := startProgram(t, b)
	downTo(program, b, "import")
	send(program, tea.KeyPressMsg{Code: 13}, tea.PasteMsg{Content: "synthetic-archive.zip"}, tea.KeyPressMsg{Code: 9}, tea.PasteMsg{Content: archivePassword}, tea.KeyPressMsg{Code: 9}, tea.KeyPressMsg{Code: 13})
	return program, out, wait
}

func TestCompletedImportRejectsAnOlderRefreshSnapshot(t *testing.T) {
	b := stagedBackend()
	m := testModel(b)
	stale := m.refresh()()
	b.imp = ownerdb.ImportStatus{Phase: ownerdb.ImportComplete, Published: 1, Total: 1}
	m.Update(operationMsg{action: "import-confirm"})
	_, next := m.Update(stale)
	check(t, m.imp.Phase != ownerdb.ImportComplete || m.at.screen != databaseScreen || next == nil,
		"old refresh rolled back the completed import or stopped its single refresh chain")
}

func TestBubbleTeaProgramImportsThroughPreviewAndConfirmation(t *testing.T) {
	b := importBackend(stagedBackend().imp)
	program, out, wait := importFlow(t, b)
	waitOutput(t, out, "Import preview")
	program.Send(tea.KeyPressMsg{Code: 13}) // cursor 0: [Confirm import…]
	waitOutput(t, out, "Type IMPORT")
	send(program, tea.PasteMsg{Content: "IMPORT"}, tea.KeyPressMsg{Code: 9}, tea.KeyPressMsg{Code: 13})
	waitOutput(t, out, "were added")
	program.Send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	output := wait()
	check(t, strings.Join(b.calls, ",") != "inspect,confirm" || strings.Join(b.args, "|") != "synthetic-archive.zip|"+archivePassword || b.closes != 1 || strings.Contains(output, archivePassword), "program flow lost input, did not inspect, confirm and close once, or exposed the archive password")
}
func TestBubbleTeaProgramShowsFixedMessageForWrongPasswordAndEscapeAbortsOnce(t *testing.T) {
	b := importBackend(ownerdb.ImportStatus{Err: ownerarchive.ErrAuthentication})
	program, out, wait := importFlow(t, b)
	waitOutput(t, out, "wrong archive password")
	program.Send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	output := wait()
	check(t, strings.Join(b.calls, ",") != "inspect" || strings.Contains(output, "Import preview"), "failed inspection staged a preview or called more")
	check(t, strings.Contains(output, archivePassword) || strings.Contains(output, ownerarchive.ErrAuthentication.Error()), "output exposed the password or the raw error")
	b = importBackend(stagedBackend().imp)
	program, out, wait = importFlow(t, b)
	waitOutput(t, out, "Import preview")
	send(program, tea.KeyPressMsg{Code: 27}, tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	wait()
	check(t, strings.Join(b.calls, ",") != "inspect,abort", "Escape on the preview did not abort exactly once without confirming")
}
