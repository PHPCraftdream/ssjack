package ownerarchiveuitest

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type fakeBackend struct {
	ownertui.Backend
	metadata vault.DirectoryMetadata
	imports  ownerdb.ImportStatus
	request  ownerdb.ExportRequest
	exports  int
}

func (b *fakeBackend) Metadata() (vault.DirectoryMetadata, error) { return b.metadata, nil }
func (b *fakeBackend) Status() ownerdb.Status                     { return ownerdb.Status{} }
func (b *fakeBackend) ImportStatus() ownerdb.ImportStatus         { return b.imports }
func (b *fakeBackend) Export(request ownerdb.ExportRequest) error {
	b.exports++
	b.request = request
	return nil
}
func (b *fakeBackend) Flush(context.Context) error { return nil }
func (b *fakeBackend) Close(context.Context) error { return nil }

func metadata() (vault.DirectoryMetadata, string, string) {
	serverID, accountID := strings.Repeat("01", 16), strings.Repeat("02", 16)
	return vault.DirectoryMetadata{RemoteMCP: mcpdirectory.Metadata{
		Servers:  []mcpdirectory.ServerMetadata{{ID: serverID, Name: "remote\x1b", URL: "https://safe.invalid/mcp", Enabled: false, Revision: 7}},
		Accounts: []mcpdirectory.AccountMetadata{{ID: accountID, ServerID: serverID, Name: "disabled", Authentication: "bearer", Enabled: false, CredentialSet: true, Revision: 8}},
	}}, serverID, accountID
}

func key(m *ownertui.Model, code rune) tea.Cmd {
	_, cmd := m.Update(tea.KeyPressMsg{Code: code})
	return cmd
}

func applyCommandExport(t *testing.T, m *ownertui.Model) tea.Msg {
	key(m, tea.KeyTab) // supplied destination starts focus on Format
	key(m, tea.KeyTab) // Confirmation, then supplied MCP accounts are skipped
	cmd := key(m, tea.KeyEnter)
	if cmd == nil {
		t.Fatal("command export Apply did not produce an operation")
	}
	return cmd()
}

func applyMenuExport(t *testing.T, m *ownertui.Model, accountID string) tea.Msg {
	m.Update(tea.PasteMsg{Content: "synthetic.zip"})
	key(m, tea.KeyTab)
	key(m, tea.KeyTab)
	key(m, tea.KeyTab)
	m.Update(tea.PasteMsg{Content: accountID})
	key(m, tea.KeyTab)
	cmd := key(m, tea.KeyEnter)
	if cmd == nil {
		t.Fatal("menu export Apply did not produce an operation")
	}
	return cmd()
}

func TestPublicExportCommandAndMenuShareCapturedMCPBindings(t *testing.T) {
	for _, mode := range []string{"command", "menu"} {
		t.Run(mode, func(t *testing.T) {
			data, serverID, accountID := metadata()
			backend := &fakeBackend{metadata: data}
			model := ownertui.New(context.Background(), backend)
			if mode == "command" {
				request := ownercommand.Request{Action: "export", Scope: "mcp", Fields: map[string]string{
					"Destination": "synthetic.zip", "MCP accounts": accountID,
				}}
				if err := model.ConfigureCommand(request); err != nil {
					t.Fatal("configured public export command:", err)
				}
			} else {
				model.Update(model.Init()())
				for i := 0; i < 3; i++ {
					key(model, tea.KeyDown)
				}
				key(model, tea.KeyEnter) // Remote MCP directory
				key(model, tea.KeyDown)
				key(model, tea.KeyDown)
				key(model, tea.KeyEnter) // Export selected MCP accounts
				if !strings.Contains(model.View().Content, "MCP accounts: \"\"") {
					t.Fatal("menu export did not default to excluding MCP accounts")
				}
			}
			if !strings.Contains(model.View().Content, `"remote\x1b"/"disabled"`) || !strings.Contains(model.View().Content, `"https://safe.invalid/mcp"`) {
				t.Fatal("export form did not render escaped selectable metadata")
			}
			// Mutation after opening must not change the form's captured revisions.
			backend.metadata.RemoteMCP.Servers[0].Revision = 99
			var result tea.Msg
			if mode == "command" {
				result = applyCommandExport(t, model)
			} else {
				result = applyMenuExport(t, model, accountID)
			}
			model.Update(result)
			want := []mcpdirectory.Binding{{ServerID: serverID, AccountID: accountID, ServerRevision: 7, AccountRevision: 8}}
			if backend.exports != 1 || len(backend.request.Selection.RemoteMCP) != 1 || backend.request.Selection.RemoteMCP[0] != want[0] {
				t.Fatal("command and menu did not export the same captured MCP binding")
			}
			if len(backend.request.Selection.Servers) != 0 || backend.request.Selection.GlobalSecrets {
				t.Fatal("MCP-only export included SSH accounts or global secrets")
			}
		})
	}
}

func TestPublicExportRejectsDuplicateMCPSelectionBeforeBackendEffect(t *testing.T) {
	data, _, accountID := metadata()
	backend := &fakeBackend{metadata: data}
	model := ownertui.New(context.Background(), backend)
	request := ownercommand.Request{Action: "export", Scope: "mcp", Fields: map[string]string{
		"Destination": "synthetic.zip", "MCP accounts": accountID + "," + accountID,
	}}
	if err := model.ConfigureCommand(request); err != nil {
		t.Fatal("configured malformed-selection fixture:", err)
	}
	model.Update(applyCommandExport(t, model))
	if backend.exports != 0 {
		t.Fatal("duplicate MCP selection reached the export backend")
	}
}

func TestPublicGlobalExportRefusesOversizedMCPPaste(t *testing.T) {
	for _, input := range []struct {
		name string
		text string
	}{
		{name: "oversized", text: strings.Repeat("a", 4096)},
		{name: "newline", text: "valid\ntext"},
		{name: "invalid UTF-8", text: string([]byte{'a', 0xff})},
	} {
		t.Run(input.name, func(t *testing.T) {
			data, _, _ := metadata()
			backend := &fakeBackend{metadata: data}
			model := ownertui.New(context.Background(), backend)
			request := ownercommand.Request{Action: "export", Scope: "global", Fields: map[string]string{
				"Destination": "synthetic.zip",
			}}
			if err := model.ConfigureCommand(request); err != nil {
				t.Fatal("configured global export command:", err)
			}
			key(model, tea.KeyTab) // Format -> Confirmation
			key(model, tea.KeyTab) // Confirmation -> MCP accounts
			model.Update(tea.PasteMsg{Content: input.text})
			key(model, tea.KeyTab) // MCP accounts -> Apply
			cmd := key(model, tea.KeyEnter)
			if cmd == nil {
				t.Fatal("global export Apply did not produce an operation")
			}
			model.Update(cmd())
			if backend.exports != 0 {
				t.Fatal("invalid MCP paste fell back to global export")
			}
		})
	}
}

func TestPublicImportPreviewEscapesMCPMetadataAndHidesCredentials(t *testing.T) {
	data, _, _ := metadata()
	backend := &fakeBackend{
		metadata: data,
		imports:  ownerdb.ImportStatus{Phase: ownerdb.ImportStaged, Preview: vault.ImportPreview{RemoteMCP: data.RemoteMCP}},
	}
	model := ownertui.New(context.Background(), backend)
	model.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	model.Update(model.Init()())
	for i := 0; i < 5; i++ {
		key(model, tea.KeyDown)
	}
	key(model, tea.KeyEnter)
	view := model.View().Content
	for _, want := range []string{`MCP server "remote\x1b"`, `"https://safe.invalid/mcp"`, `MCP account "disabled"`, "bearer", "enabled=false"} {
		if !strings.Contains(view, want) {
			t.Fatalf("preview omitted safe MCP metadata %q", want)
		}
	}
	if strings.Contains(view, "credential-set") || strings.Contains(view, "CredentialSet") || strings.ContainsRune(view, '\x1b') {
		t.Fatal("import preview exposed credential metadata or an unescaped control character")
	}
}
