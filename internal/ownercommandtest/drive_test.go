package ownercommands

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/ownertui"
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
			if current, err := strconv.Unquote(rendered); err == nil {
				for i := 0; i < utf8.RuneCountInString(current); i++ {
					key(m, 127)
				}
			}
			m.Update(tea.PasteMsg{Content: value})
		}
		if strings.Contains(m.View().Content, "synthetic-input-secret") {
			t.Fatal("form exposed a secret")
		}
		key(m, 9)
	}
	t.Fatal("form did not reach Apply")
}
