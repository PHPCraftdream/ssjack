package ownercommands

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/terminalmodel"
)

func program(t *testing.T, b *backend, args ...string) (*ownertui.Model, *tea.Program, *terminalmodel.Output, func()) {
	t.Helper()
	request, err := ownercommand.Parse(args, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	model := ownertui.New(ctx, b)
	if err := model.ConfigureCommand(request); err != nil {
		t.Fatal(err)
	}
	output := &terminalmodel.Output{}
	p := tea.NewProgram(terminalmodel.Capture(model, output), tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(output), tea.WithWindowSize(120, 40), tea.WithEnvironment([]string{"TERM=dumb"}), tea.WithoutSignalHandler())
	done := make(chan error, 1)
	go func() { _, err := p.Run(); done <- err }()
	return model, p, output, func() {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.Raw(), "synthetic-input-secret") || strings.Contains(output.Raw(), syntheticFailure.Error()) {
			t.Fatal("raw renderer output exposed private input or diagnostics")
		}
	}
}
func waitFrame(t *testing.T, out *terminalmodel.Output, text string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !strings.Contains(out.String(), text) {
		if time.Now().After(deadline) {
			t.Fatal("expected command frame did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func TestCommandProgramLocksArgumentsPromptsSecretFlushesAndExits(t *testing.T) {
	for _, mode := range []string{"success", "cancel", "cancel-button", "flush-failure"} {
		t.Run(mode, func(t *testing.T) {
			b := fixture(t)
			if mode == "flush-failure" {
				b.flushErr = syntheticFailure
			}
			model, p, output, wait := program(t, b, "edit-account", "--server", "production", "--account", "main", "--login", "selected-login", "--auth", "password", "--usage", "human")
			waitFrame(t, output, "> Credential:")
			p.Send(tea.PasteMsg{Content: "synthetic-input-secret"})
			if mode == "cancel" {
				p.Send(tea.KeyPressMsg{Code: 27})
			} else {
				p.Send(tea.KeyPressMsg{Code: 9})
				waitFrame(t, output, "> [Apply]")
				if mode == "cancel-button" {
					p.Send(tea.KeyPressMsg{Code: 9})
					waitFrame(t, output, "> [Cancel]")
				}
				p.Send(tea.KeyPressMsg{Code: 13})
			}
			wait()
			result := model.CommandResult()
			if strings.HasPrefix(mode, "cancel") {
				if !errors.Is(result, ownercommand.ErrCancelled) || b.state.Targets["production"].User != "operator" || b.flushes != 0 {
					t.Fatal("cancel applied the command or reported success")
				}
			} else {
				if b.state.Targets["production"].User != "selected-login" || string(b.state.Targets["production"].Password) != "synthetic-input-secret" || b.flushes == 0 {
					t.Fatal("command lost parameters/secret or skipped persistence")
				}
				if (mode == "success") != (result == nil) {
					t.Fatal("command did not distinguish saved success from persistence failure")
				}
			}
		})
	}
}
func TestMCPCommandProgramMasksPrivateInputAndWaitsForPersistence(t *testing.T) {
	for _, action := range []string{"edit-mcp-account", "edit-mcp-header"} {
		for _, mode := range []string{"success", "cancel", "flush-failure"} {
			t.Run(action+"/"+mode, func(t *testing.T) {
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
				model, p, out, wait := program(t, b, args...)
				waitFrame(t, out, "> "+label+":")
				p.Send(tea.PasteMsg{Content: "synthetic-input-secret"})
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
			})
		}
	}
}

func TestCommandProgramImportStillRequiresPreviewAndExactConfirmation(t *testing.T) {
	b := fixture(t)
	model, p, out, wait := program(t, b, "import", "--file", "synthetic.zip")
	waitFrame(t, out, "> Archive password:")
	p.Send(tea.PasteMsg{Content: "synthetic-input-secret"})
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
