package mcpselect

import (
	"reflect"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

func fixture() mcpdirectory.Metadata {
	return mcpdirectory.Metadata{
		Servers:  []mcpdirectory.ServerMetadata{{ID: "server", Name: "remote", URL: "https://remote.invalid/mcp", Enabled: true, Revision: 2}},
		Accounts: []mcpdirectory.AccountMetadata{{ID: "account", ServerID: "server", Name: "primary", Enabled: true, Revision: 3}},
		Last:     map[string][]mcpdirectory.Binding{},
	}
}

func current() mcpdirectory.Binding {
	return mcpdirectory.Binding{ServerID: "server", AccountID: "account", ServerRevision: 2, AccountRevision: 3}
}

func newModel(t *testing.T, metadata mcpdirectory.Metadata) *Model {
	t.Helper()
	model, err := New("ssh-profile", 42, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func key(model *Model, code rune) tea.Cmd {
	_, command := model.Update(tea.KeyPressMsg{Code: code})
	return command
}

func TestSingletonNeedsCheckboxAndExplicitContinue(t *testing.T) {
	model := newModel(t, fixture())
	if model.Init() != nil || model.items[0].checked {
		t.Fatal("singleton was preselected or started work")
	}
	if _, ok := model.Result(); ok {
		t.Fatal("unconfirmed singleton returned a choice")
	}
	key(model, 32)
	if !model.items[0].checked {
		t.Fatal("space did not toggle checkbox")
	}
	key(model, 13)
	if model.items[0].checked || model.done {
		t.Fatal("enter on checkbox confirmed instead of toggling")
	}
	key(model, 32)
	key(model, tea.KeyDown)
	if key(model, 13) == nil {
		t.Fatal("explicit Continue did not finish")
	}
	choice, ok := model.Result()
	if !ok || choice.Profile != "ssh-profile" || choice.Revision != 42 || !reflect.DeepEqual(choice.Bindings, []mcpdirectory.Binding{current()}) {
		t.Fatal("confirmed choice lost exact context/revisions")
	}
	choice.Bindings[0].AccountID = "changed"
	key(model, 27)
	choice, ok = model.Result()
	if !ok || choice.Bindings[0] != current() {
		t.Fatal("result borrowed output buffers or accepted late input")
	}
}

func TestEmptyChoiceAndCancellationNeverImplicitlyPersist(t *testing.T) {
	model := newModel(t, mcpdirectory.Metadata{})
	if !strings.Contains(model.View().Content, "No remote MCP accounts") {
		t.Fatal("empty selector did not explain its scope")
	}
	if _, ok := model.Result(); ok {
		t.Fatal("empty list auto-confirmed")
	}
	key(model, 13)
	if choice, ok := model.Result(); !ok || len(choice.Bindings) != 0 || choice.Bindings == nil {
		t.Fatal("explicit empty choice was not represented")
	}
	for _, cancel := range []tea.KeyPressMsg{{Code: 27}, {Code: 'c', Mod: tea.ModCtrl}, {Code: 'q'}} {
		metadata := fixture()
		metadata.Last["ssh-profile"] = []mcpdirectory.Binding{current()}
		model = newModel(t, metadata)
		model.Update(cancel)
		if _, ok := model.Result(); ok || len(metadata.Last["ssh-profile"]) != 1 {
			t.Fatal("cancel returned or changed a remembered choice")
		}
	}
	model = newModel(t, fixture())
	key(model, tea.KeyEnd)
	key(model, 13)
	if _, ok := model.Result(); ok {
		t.Fatal("explicit Cancel returned a choice")
	}
}

func TestSuggestionsRequireExactEnabledBindingsForThisProfile(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*mcpdirectory.Metadata)
		checked bool
	}{
		{"unchanged", func(*mcpdirectory.Metadata) {}, true},
		{"rename", func(m *mcpdirectory.Metadata) { m.Servers[0].Name = "renamed"; m.Accounts[0].Name = "renamed" }, true},
		{"endpoint", func(m *mcpdirectory.Metadata) {
			m.Servers[0].Revision++
			m.Servers[0].URL = "https://changed.invalid/mcp"
		}, false},
		{"credential", func(m *mcpdirectory.Metadata) { m.Accounts[0].Revision++ }, false},
		{"disabled-server", func(m *mcpdirectory.Metadata) { m.Servers[0].Enabled = false }, false},
		{"disabled-account", func(m *mcpdirectory.Metadata) { m.Accounts[0].Enabled = false }, false},
		{"deleted", func(m *mcpdirectory.Metadata) { m.Accounts = nil }, false},
		{"other-profile", func(m *mcpdirectory.Metadata) { m.Last["other"] = m.Last["ssh-profile"]; delete(m.Last, "ssh-profile") }, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			metadata := fixture()
			metadata.Last["ssh-profile"] = []mcpdirectory.Binding{current()}
			test.change(&metadata)
			model := newModel(t, metadata)
			checked := len(model.items) != 0 && model.items[0].checked
			if checked != test.checked {
				t.Fatal("suggestion silently adopted changed context")
			}
			if _, ok := model.Result(); ok {
				t.Fatal("remembered suggestion became approval")
			}
			if len(model.items) != 0 && !model.items[0].enabled {
				key(model, 32)
				if model.items[0].checked {
					t.Fatal("disabled row could be selected")
				}
			}
		})
	}
}
