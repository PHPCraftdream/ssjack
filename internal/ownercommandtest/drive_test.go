package ownercommands

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/terminalmodel"
)

func key(m *ownertui.Model, code rune) tea.Cmd {
	_, command := m.Update(tea.KeyPressMsg{Code: code})
	return command
}
func drain(m *ownertui.Model, command tea.Cmd) {
	for command != nil {
		message := command()
		if _, quit := message.(tea.QuitMsg); quit {
			return
		}
		_, command = m.Update(message)
	}
}
func selected(m *ownertui.Model) string {
	for _, line := range strings.Split(m.View().Content, "\n") {
		if strings.HasPrefix(line, "> ") {
			return strings.TrimPrefix(line, "> ")
		}
	}
	return ""
}
func choose(t *testing.T, m *ownertui.Model, label string) {
	t.Helper()
	for i := 0; i < 40; i++ {
		if selected(m) == label {
			key(m, 13)
			return
		}
		key(m, tea.KeyDown)
	}
	t.Fatalf("menu item is unreachable: %s", label)
}
func menu(t *testing.T, b *backend, server, account string, path ...string) *ownertui.Model {
	t.Helper()
	m := ownertui.New(context.Background(), b)
	m.Update(m.Init()())
	if err := m.Select(server, account); err != nil {
		t.Fatal(err)
	}
	for _, label := range path {
		choose(t, m, label)
	}
	return m
}

func secretEntry(t *testing.T, m *ownertui.Model, value string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output := &terminalmodel.Output{}
	release := make(chan struct{})
	m.SetSecretReader(func(int) ([]byte, error) {
		<-release
		return append([]byte(nil), value...), nil
	})
	p := tea.NewProgram(terminalmodel.Capture(m, output), tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(output), tea.WithWindowSize(120, 40), tea.WithEnvironment([]string{"TERM=dumb"}), tea.WithoutSignalHandler())
	done := make(chan error, 1)
	go func() { _, err := p.Run(); done <- err }()
	stop := func() {
		p.Quit()
		if flakediag.WaitFor(t, "temporary secret-entry Program to stop", 3*time.Second, func() (string, bool) {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("temporary secret-entry Program returned an error")
				}
				return "stopped", true
			default:
				if ctx.Err() != nil {
					return "timeout", true
				}
				return "running", false
			}
		}) != "stopped" {
			t.Fatal("temporary secret-entry Program did not stop")
		}
	}
	p.Send(tea.KeyPressMsg{Code: 13})
	if flakediag.WaitFor(t, "secret prompt marker", 3*time.Second, func() (string, bool) {
		matched := strings.Contains(output.Raw(), "Secret (hidden; Enter submits, Esc/Ctrl+C cancels): ")
		return "matched=" + strconv.FormatBool(matched), matched
	}) != "matched=true" {
		close(release)
		stop()
		t.Fatal("temporary secret-entry Program did not render the secret prompt")
	}
	close(release)
	if flakediag.WaitFor(t, "secret-entry form to render its masked completion", 3*time.Second, func() (string, bool) {
		matched := strings.Contains(output.String(), "<hidden; entered>")
		return "masked=" + strconv.FormatBool(matched), matched
	}) != "masked=true" {
		stop()
		t.Fatal("temporary secret-entry Program did not render masked completion")
	}
	stop()
}

// apply fills only editable fields; command-prefilled fields must remain immutable.
func apply(t *testing.T, m *ownertui.Model, values map[string]string) {
	t.Helper()
	for step := 0; step < 24; step++ {
		line := selected(m)
		if line == "[Apply]" {
			drain(m, key(m, 13))
			return
		}
		label, rendered, field := strings.Cut(line, ": ")
		if !field || strings.Contains(rendered, "parameter; read-only") {
			t.Fatalf("not an editable form field: %s", line)
		}
		if value, exists := values[label]; exists {
			if strings.Contains(rendered, "<hidden;") {
				secretEntry(t, m, value)
			} else {
				if current, err := strconv.Unquote(rendered); err == nil {
					for i := 0; i < utf8.RuneCountInString(current); i++ {
						key(m, 127)
					}
				}
				m.Update(tea.PasteMsg{Content: value})
			}
		}
		if strings.Contains(m.View().Content, "synthetic-input-secret") {
			t.Fatal("form exposed a secret")
		}
		key(m, 9)
	}
	t.Fatal("form did not reach Apply")
}
