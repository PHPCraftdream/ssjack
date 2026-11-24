package ownercommands

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/terminalmodel"
)

func program(t *testing.T, b *backend, args ...string) (*ownertui.Model, *tea.Program, *terminalmodel.Output, func(), func(error)) {
	t.Helper()
	request, err := ownercommand.Parse(args, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model := ownertui.New(ctx, b)
	release := make(chan error, 1)
	model.SetSecretReader(func(int) ([]byte, error) {
		err := <-release
		if err != nil {
			return nil, err
		}
		return []byte("synthetic-input-secret"), nil
	})
	if err := model.ConfigureCommand(request); err != nil {
		t.Fatal(err)
	}
	output := &terminalmodel.Output{}
	p := tea.NewProgram(terminalmodel.Capture(model, output), tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(output), tea.WithWindowSize(120, 40), tea.WithEnvironment([]string{"TERM=dumb"}), tea.WithoutSignalHandler())
	done := make(chan error, 1)
	go func() { _, err := p.Run(); done <- err }()
	return model, p, output, func() {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output.Raw(), "synthetic-input-secret") || strings.Contains(output.Raw(), syntheticFailure.Error()) {
				t.Fatal("raw renderer output exposed private input or diagnostics")
			}
		case <-ctx.Done():
			t.Fatal("command Program did not stop before timeout")
		}
	}, func(err error) { release <- err }
}
func waitFrame(t *testing.T, out *terminalmodel.Output, text string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !strings.Contains(out.String(), text) {
		if time.Now().After(deadline) {
			rendered := out.String()
			t.Fatalf("expected command frame did not appear (want %q bytes=%d sha256=%s)\ngoroutine dump:\n%s", text, len(rendered), flakediag.Short([]byte(rendered)), flakediag.GoroutineDump(64*1024))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func waitPrompt(t *testing.T, out *terminalmodel.Output) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !strings.Contains(out.Raw(), "Secret (hidden; Enter submits, Esc/Ctrl+C cancels): ") {
		if time.Now().After(deadline) {
			raw := out.Raw()
			t.Fatalf("secret prompt marker did not appear (bytes=%d sha256=%s)", len(raw), flakediag.Short([]byte(raw)))
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func releasePrompt(t *testing.T, p *tea.Program, out *terminalmodel.Output, release func(error)) {
	t.Helper()
	p.Send(tea.KeyPressMsg{Code: 13})
	waitPrompt(t, out)
	release(nil)
	waitFrame(t, out, "<hidden; entered>")
}
func TestCommandProgramLocksArgumentsPromptsSecretFlushesAndExits(t *testing.T) {
	t.Run("success", func(t *testing.T) { commandCase(t, "success") })
	t.Run("cancel", func(t *testing.T) { commandCase(t, "cancel") })
	t.Run("cancel-button", func(t *testing.T) { commandCase(t, "cancel-button") })
	t.Run("flush-failure", func(t *testing.T) { commandCase(t, "flush-failure") })
}
func commandCase(t *testing.T, mode string) {
	b := fixture(t)
	if mode == "flush-failure" {
		b.flushErr = syntheticFailure
	}
	model, p, output, wait, release := program(t, b, "edit-account", "--server", "production", "--account", "main", "--login", "selected-login", "--auth", "password", "--usage", "human")
	waitFrame(t, output, "> Credential:")
	releasePrompt(t, p, output, release)
	if mode == "cancel" {
		p.Send(tea.KeyPressMsg{Code: 27})
	} else if mode == "cancel-button" {
		p.Send(tea.KeyPressMsg{Code: 9})
		waitFrame(t, output, "> [Apply]")
		p.Send(tea.KeyPressMsg{Code: 9})
		waitFrame(t, output, "> [Cancel]")
		p.Send(tea.KeyPressMsg{Code: 13})
	} else {
		p.Send(tea.KeyPressMsg{Code: 9})
		waitFrame(t, output, "> [Apply]")
		p.Send(tea.KeyPressMsg{Code: 13})
	}
	wait()
	result := model.CommandResult()
	if strings.HasPrefix(mode, "cancel") {
		if !errors.Is(result, ownercommand.ErrCancelled) || b.state.Targets["production"].User != "operator" || b.flushes != 0 {
			t.Fatal("cancel applied the command or reported success")
		}
	} else if b.state.Targets["production"].User != "selected-login" || string(b.state.Targets["production"].Password) != "synthetic-input-secret" || b.flushes == 0 || (mode == "success") != (result == nil) {
		t.Fatal("command lost private input, skipped persistence, or misreported its result")
	}
}

func TestMCPCommandProgramMasksPrivateInputAndWaitsForPersistence(t *testing.T) {
	t.Run("account-success", func(t *testing.T) { mcpCase(t, "edit-mcp-account", "success") })
	t.Run("account-cancel", func(t *testing.T) { mcpCase(t, "edit-mcp-account", "cancel") })
	t.Run("account-flush-failure", func(t *testing.T) { mcpCase(t, "edit-mcp-account", "flush-failure") })
	t.Run("header-success", func(t *testing.T) { mcpCase(t, "edit-mcp-header", "success") })
	t.Run("header-cancel", func(t *testing.T) { mcpCase(t, "edit-mcp-header", "cancel") })
	t.Run("header-flush-failure", func(t *testing.T) { mcpCase(t, "edit-mcp-header", "flush-failure") })
}
func mcpCase(t *testing.T, action, mode string) {
	b := fixture(t)
	if mode == "flush-failure" {
		b.flushErr = syntheticFailure
	}
	args := []string{action, "--server", "docs", "--account", "work"}
	label := "Header credential"
	if action == "edit-mcp-account" {
		args = append(args, "--enabled", "true", "--auth", "bearer", "--login=", "--credential-action", "replace")
		label = "MCP credential"
	} else {
		args = append(args, "--header", "X-Api-Key", "--header-action", "replace")
	}
	model, p, out, wait, release := program(t, b, args...)
	waitFrame(t, out, "> "+label+":")
	releasePrompt(t, p, out, release)
	if mode == "cancel" {
		p.Send(tea.KeyPressMsg{Code: 27})
	} else {
		p.Send(tea.KeyPressMsg{Code: 9})
		waitFrame(t, out, "> [Apply]")
		p.Send(tea.KeyPressMsg{Code: 13})
	}
	wait()
	account := b.state.RemoteMCP.Accounts[strings.Repeat("04", 16)]
	if mode == "cancel" {
		if !errors.Is(model.CommandResult(), ownercommand.ErrCancelled) || b.flushes != 0 || string(account.Auth.Secret) != "synthetic-existing-mcp-token" || len(account.Headers) != 0 {
			t.Fatal("cancel applied private MCP input")
		}
		return
	}
	if b.flushes == 0 || (mode == "success") != (model.CommandResult() == nil) {
		t.Fatal("MCP command did not wait for persistence or distinguish failure")
	}
	if action == "edit-mcp-account" && string(account.Auth.Secret) != "synthetic-input-secret" {
		t.Fatal("MCP command lost private credential input")
	}
	if action == "edit-mcp-header" && (len(account.Headers) != 1 || string(account.Headers[0].Value) != "synthetic-input-secret") {
		t.Fatal("MCP command lost private header input")
	}
}
func TestCommandProgramImportStillRequiresPreviewAndExactConfirmation(t *testing.T) {
	b := fixture(t)
	model, p, out, wait, release := program(t, b, "import", "--file", "synthetic.zip")
	waitFrame(t, out, "> Archive password:")
	releasePrompt(t, p, out, release)
	p.Send(tea.KeyPressMsg{Code: 9})
	p.Send(tea.KeyPressMsg{Code: 13})
	waitFrame(t, out, "Import preview")
	b.mu.Lock()
	calls := strings.Join(b.calls, ",")
	b.mu.Unlock()
	if calls != "inspect" {
		t.Fatal("inspection applied the import")
	}
	p.Send(tea.KeyPressMsg{Code: 13})
	waitFrame(t, out, "Type IMPORT")
	p.Send(tea.PasteMsg{Content: "IMPORT"})
	p.Send(tea.KeyPressMsg{Code: 9})
	p.Send(tea.KeyPressMsg{Code: 13})
	wait()
	if model.CommandResult() != nil || strings.Join(b.calls, ",") != "inspect,confirm" {
		t.Fatal("command skipped confirmation or failed to wait for import completion")
	}
}
