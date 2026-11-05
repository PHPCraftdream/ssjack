package ownercommands

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestMCPCommandAndMenuCancelNeverApplyPrivateInput(t *testing.T) {
	for _, parameterized := range []bool{false, true} {
		b := fixture(t)
		before := remoteEffects(b.state)
		m := menu(t, b, "", "", "Remote MCP servers", "docs", "work", "[Edit MCP account]")
		if parameterized {
			m = commandModel(t, b, "edit-mcp-account", "--server", "docs", "--account", "work", "--credential-action", "replace")
		}
		for i := 0; i < 8 && !strings.HasPrefix(selected(m), "MCP credential: "); i++ {
			key(m, 9)
		}
		if !strings.HasPrefix(selected(m), "MCP credential: ") {
			t.Fatal("private credential field is unreachable")
		}
		m.Update(tea.PasteMsg{Content: "synthetic-input-secret"})
		if strings.Contains(m.View().Content, "synthetic-input-secret") {
			t.Fatal("MCP credential appeared in the terminal")
		}
		drain(m, key(m, 27))
		if !reflect.DeepEqual(before, remoteEffects(b.state)) || len(b.calls) != 0 {
			t.Fatal("cancel changed MCP directory")
		}
		if parameterized && !errors.Is(m.CommandResult(), ownercommand.ErrCancelled) {
			t.Fatal("cancel was reported successful")
		}
	}
}

func TestMCPWrongConfirmationAndPrincipalKeepFailWithoutMutation(t *testing.T) {
	for _, args := range [][]string{
		{"remove-mcp-server", "--server", "docs"},
		{"remove-mcp-account", "--server", "docs", "--account", "work"},
		{"edit-mcp-account", "--server", "docs", "--account", "work", "--auth", "basic", "--login", "other", "--credential-action", "keep"},
	} {
		b := fixture(t)
		before := remoteEffects(b.state)
		m := commandModel(t, b, args...)
		apply(t, m, map[string]string{"Confirmation": "WRONG"})
		if !errors.Is(m.CommandResult(), ownercommand.ErrOperation) || !reflect.DeepEqual(before, remoteEffects(b.state)) {
			t.Fatal("invalid MCP action mutated state or reported success")
		}
	}
}

type revisionBackend struct{ *backend }
type revisionOperation struct {
	ownertui.Backend
	expected uint64
	current  *backend
}

func (b *revisionBackend) AtRevision(revision uint64) ownertui.Backend {
	return &revisionOperation{Backend: b.backend, expected: revision, current: b.backend}
}
func (b *revisionOperation) Edit(edit func(*vault.Vault) error) error {
	if b.expected != b.current.status.Database.Revision {
		return vault.ErrOwnerRevision
	}
	return b.current.Edit(edit)
}

func TestMCPFormsUseDisplayedRevisionForBothEntryPoints(t *testing.T) {
	for _, parameterized := range []bool{false, true} {
		b := fixture(t)
		b.status.Database.Revision = 7
		guard := &revisionBackend{b}
		m := ownertui.New(context.Background(), guard)
		if parameterized {
			r, err := ownercommand.Parse([]string{"edit-mcp-server", "--server", "docs", "--name", "changed"}, "", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := m.ConfigureCommand(r); err != nil {
				t.Fatal(err)
			}
		} else {
			m.Update(m.Init()())
			for _, label := range []string{"Remote MCP servers", "docs", "[Edit MCP server]"} {
				choose(t, m, label)
			}
		}
		before := remoteEffects(b.state)
		b.status.Database.Revision = 8
		apply(t, m, map[string]string{"MCP server name": "changed"})
		if !reflect.DeepEqual(before, remoteEffects(b.state)) {
			t.Fatal("stale displayed revision reached the edit callback")
		}
		if parameterized && !errors.Is(m.CommandResult(), ownercommand.ErrOperation) {
			t.Fatal("stale command reported successful")
		}
	}
}

func TestMCPPrivateFieldsCannotBePrefilledByRequest(t *testing.T) {
	for action, label := range map[string]string{"edit-mcp-account": "MCP credential", "edit-mcp-header": "Header credential", "remove-mcp-account": "Confirmation"} {
		b := fixture(t)
		r, err := ownercommand.Parse([]string{action, "--server", "docs", "--account", "work"}, "", "")
		if err != nil {
			t.Fatal(err)
		}
		r.Fields[label] = "synthetic-input-secret"
		m := ownertui.New(context.Background(), b)
		if m.ConfigureCommand(r) == nil || strings.Contains(m.View().Content, "synthetic-input-secret") || key(m, 13) != nil {
			t.Fatal("private field or approval bypassed trusted terminal input")
		}
	}
}
