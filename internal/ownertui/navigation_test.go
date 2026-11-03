package ownertui

import (
	"bytes"
	"strings"
	"testing"

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
		if len(items) != 2 || items[1].target.secret != want || items[1].target.server != scope {
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

func TestDisplayEscapesTerminalControlSequences(t *testing.T) {
	value := "user\x1b[31m\nnext"
	got := escaped(value)
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
	if f.focus != 2 {
		t.Fatal("cancel button was not reachable")
	}
	f.move(1)
	if f.focus != 0 {
		t.Fatal("focus did not wrap back to the first field")
	}
	f.clear()
}
