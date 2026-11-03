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
