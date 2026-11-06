package mcpselect

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

func TestSnapshotOwnsChoicesAndQuotesDisplayWithoutTerminalControls(t *testing.T) {
	metadata := fixture()
	metadata.Last["ssh-profile"] = []mcpdirectory.Binding{current()}
	model := newModel(t, metadata)
	metadata.Accounts[0].Name = "changed"
	metadata.Servers[0].URL = "https://changed.invalid/mcp"
	metadata.Last["ssh-profile"][0].AccountRevision++
	if !model.items[0].checked || model.items[0].binding != current() || strings.Contains(model.View().Content, "changed") {
		t.Fatal("selector borrowed mutable caller metadata")
	}
	metadata = fixture()
	metadata.Servers[0].Name = "display\x1b[31m\n"
	model = newModel(t, metadata)
	if strings.ContainsAny(model.View().Content, "\x1b\x00") || !strings.Contains(model.View().Content, `display\x1b[31m\n`) {
		t.Fatal("selector emitted unquoted terminal controls")
	}
}

func TestDisplayOrderDoesNotDependOnMetadataSliceOrder(t *testing.T) {
	metadata := fixture()
	metadata.Accounts = append(metadata.Accounts, mcpdirectory.AccountMetadata{ID: "earlier", ServerID: "server", Name: "aaa", Enabled: true, Revision: 1})
	model := newModel(t, metadata)
	if model.items[0].binding.AccountID != "earlier" || model.items[1].binding != current() {
		t.Fatal("display ordering followed mutable source slice order")
	}
}

func TestSelectionLimitAndViewportNeverTruncateChoice(t *testing.T) {
	metadata := fixture()
	metadata.Accounts = nil
	for index := range mcpdirectory.MaxSelections + 1 {
		metadata.Accounts = append(metadata.Accounts, mcpdirectory.AccountMetadata{ID: fmt.Sprintf("account-%02d", index), ServerID: "server", Name: fmt.Sprintf("name-%02d", index), Enabled: true, Revision: 1})
	}
	model := newModel(t, metadata)
	model.Update(tea.WindowSizeMsg{Height: 12, Width: 80})
	for range len(metadata.Accounts) {
		key(model, 32)
		key(model, tea.KeyDown)
	}
	if !strings.Contains(model.View().Content, "at most 16") || !strings.Contains(model.View().Content, "Showing") || strings.Contains(model.View().Content, "name-00") {
		t.Fatal("selection limit or cursor viewport was not preserved")
	}
	key(model, 13)
	choice, ok := model.Result()
	if !ok || len(choice.Bindings) != mcpdirectory.MaxSelections || choice.Bindings[0].AccountID != "account-00" || choice.Bindings[15].AccountID != "account-15" {
		t.Fatal("viewport silently truncated or substituted confirmed choices")
	}
}

func TestInvalidAndOversizedDisplaySnapshotsRefuse(t *testing.T) {
	for _, change := range []func(*mcpdirectory.Metadata){
		func(m *mcpdirectory.Metadata) { m.Servers = append(m.Servers, m.Servers[0]) },
		func(m *mcpdirectory.Metadata) { m.Accounts = append(m.Accounts, m.Accounts[0]) },
		func(m *mcpdirectory.Metadata) { m.Accounts[0].ServerID = "missing" },
		func(m *mcpdirectory.Metadata) { m.Servers[0].Revision = 0 },
		func(m *mcpdirectory.Metadata) { m.Accounts[0].Revision = 0 },
		func(m *mcpdirectory.Metadata) { m.Servers[0].URL = strings.Repeat("x", 2049) },
		func(m *mcpdirectory.Metadata) {
			m.Accounts = make([]mcpdirectory.AccountMetadata, mcpdirectory.MaxAccounts+1)
		},
		func(m *mcpdirectory.Metadata) {
			m.Servers = make([]mcpdirectory.ServerMetadata, mcpdirectory.MaxServers+1)
		},
		func(m *mcpdirectory.Metadata) {
			m.Last["ssh-profile"] = make([]mcpdirectory.Binding, mcpdirectory.MaxSelections+1)
		},
	} {
		metadata := fixture()
		change(&metadata)
		if model, err := New("ssh-profile", 42, metadata); model != nil || err != ErrSelection {
			t.Fatal("invalid metadata granted a selector or was truncated")
		}
	}
	for _, profile := range []string{"", strings.Repeat("x", 65)} {
		if model, err := New(profile, 0, fixture()); model != nil || err != ErrSelection {
			t.Fatal("invalid SSH context was accepted")
		}
	}
	zero := &Model{}
	key(zero, 13)
	if _, ok := zero.Result(); ok {
		t.Fatal("zero model manufactured an empty approval")
	}
}
