package ownermcp

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func change(action, server, account string, fields ...string) ownerpacket.DirectoryChange {
	c := ownerpacket.DirectoryChange{Action: action, ServerID: server, Account: account}
	for _, value := range fields {
		c.Fields = append(c.Fields, []byte(value))
	}
	return c
}

func fixture(t *testing.T) (*vault.Vault, string, string) {
	t.Helper()
	v := &vault.Vault{}
	t.Cleanup(func() { v.Close() })
	if err := Apply(v, change("add-mcp-server", "", "", "docs", "https://docs.invalid/mcp")); err != nil {
		t.Fatal(err)
	}
	var server, account string
	for id := range v.RemoteMCP.Servers {
		server = id
	}
	if err := Apply(v, change("add-mcp-account", server, "", "work", "true", "bearer", "", "replace", "synthetic-private-token")); err != nil {
		t.Fatal(err)
	}
	for id := range v.RemoteMCP.Accounts {
		account = id
	}
	return v, server, account
}

func TestPrimaryCredentialDecisionsAreExplicitAndOwned(t *testing.T) {
	v, server, account := fixture(t)
	d := v.RemoteMCP
	original := d.Accounts[account].Auth.Secret
	c := change("edit-mcp-account", server, account, "work", "true", "bearer", "", "replace", "synthetic-replacement")
	if err := Apply(v, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, make([]byte, len(original))) {
		t.Fatal("replacement retained prior credential bytes")
	}
	clear(c.Fields[5])
	if string(d.Accounts[account].Auth.Secret) != "synthetic-replacement" {
		t.Fatal("account borrowed input credential bytes")
	}
	if err := Apply(v, change("edit-mcp-account", server, account, "work", "true", "bearer", "", "keep", "")); err != nil {
		t.Fatal(err)
	}
	if string(d.Accounts[account].Auth.Secret) != "synthetic-replacement" {
		t.Fatal("explicit keep discarded credential")
	}
	owned := d.Accounts[account].Auth.Secret
	if err := Apply(v, change("edit-mcp-account", server, account, "work", "true", "none", "", "clear", "")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) || len(d.Accounts[account].Auth.Secret) != 0 {
		t.Fatal("explicit clear retained primary credential")
	}
}

func TestInvalidCredentialChangesRefuseBeforeMutation(t *testing.T) {
	cases := [][]string{
		{"work", "true", "basic", "other", "keep", ""},
		{"work", "true", "bearer", "", "keep", "unexpected"},
		{"work", "true", "bearer", "", "replace", ""},
		{"work", "true", "bearer", "", "clear", ""},
		{"work", "true", "none", "", "clear", "unexpected"},
		{"work", "true", "bearer", "", "", ""},
		{"renamed", "true", "bearer", "", "keep", ""},
		{"work", "bad", "bearer", "", "keep", ""},
	}
	for _, fields := range cases {
		t.Run(fields[2]+"-"+fields[4]+"-"+fields[0], func(t *testing.T) {
			v, server, account := fixture(t)
			before := v.RemoteMCP.Record()
			if err := Apply(v, change("edit-mcp-account", server, account, fields...)); err == nil {
				t.Fatal("invalid credential decision accepted")
			}
			if !reflect.DeepEqual(before, v.RemoteMCP.Record()) {
				t.Fatal("refused edit changed private directory")
			}
		})
	}
}

func TestHeaderReplacementClearAndBounds(t *testing.T) {
	v, server, account := fixture(t)
	d := v.RemoteMCP
	for _, name := range []string{"X-One", "X-Two", "X-Three", "X-Four"} {
		if err := Apply(v, change("edit-mcp-header", server, account, name, "replace", "synthetic-header")); err != nil {
			t.Fatal(err)
		}
	}
	before := d.Metadata()
	for _, fields := range [][]string{{"X-Five", "replace", "extra"}, {"Authorization", "replace", "extra"}, {"X-One", "clear", "extra"}, {"X-Missing", "clear", ""}, {"X-One", "replace", ""}} {
		if err := Apply(v, change("edit-mcp-header", server, account, fields...)); err == nil {
			t.Fatal("invalid header edit accepted")
		}
		if !reflect.DeepEqual(before, d.Metadata()) {
			t.Fatal("failed header edit changed account revision or metadata")
		}
	}
	old := d.Accounts[account].Headers[0].Value
	if err := Apply(v, change("edit-mcp-header", server, account, "X-One", "replace", "synthetic-new-header")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("header replacement retained obsolete private bytes")
	}
	if err := Apply(v, change("edit-mcp-header", server, account, "X-One", "clear", "")); err != nil {
		t.Fatal(err)
	}
	if len(d.Accounts[account].Headers) != 3 || string(d.Accounts[account].Auth.Secret) != "synthetic-private-token" {
		t.Fatal("header clear changed unrelated primary credential")
	}
}

func TestRenamePreservesPreferenceButPolicyChangesInvalidateIt(t *testing.T) {
	v, server, account := fixture(t)
	d := v.RemoteMCP
	binding, err := d.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Remember("synthetic-profile", []mcpdirectory.Binding{binding}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []ownerpacket.DirectoryChange{
		change("edit-mcp-server", server, "", "renamed", "https://docs.invalid/mcp", "true"),
		change("rename-mcp-account", server, account, "renamed"),
	} {
		if err := Apply(v, c); err != nil {
			t.Fatal(err)
		}
	}
	if got := d.Suggested("synthetic-profile"); len(got) != 1 || got[0] != binding {
		t.Fatal("display rename invalidated stable preference")
	}
	if err := Apply(v, change("edit-mcp-server", server, "", "renamed", "https://other.invalid/mcp", "true")); err != nil {
		t.Fatal(err)
	}
	if len(d.Suggested("synthetic-profile")) != 0 {
		t.Fatal("endpoint change silently retained preselection")
	}
}

func TestRemovalRequiresConfirmationAndExactServerAccount(t *testing.T) {
	for _, action := range []string{"remove-mcp-account", "remove-mcp-server"} {
		t.Run(action, func(t *testing.T) {
			v, server, account := fixture(t)
			before := v.RemoteMCP.Metadata()
			if err := Apply(v, change(action, server, account, "")); err == nil {
				t.Fatal("removal did not require explicit confirmation")
			}
			if !reflect.DeepEqual(before, v.RemoteMCP.Metadata()) {
				t.Fatal("refused removal changed metadata")
			}
			secret := v.RemoteMCP.Accounts[account].Auth.Secret
			if err := Apply(v, change(action, server, account, "REMOVE")); err != nil {
				t.Fatal(err)
			}
			if len(v.RemoteMCP.Accounts) != 0 || !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("removal retained account or credential")
			}
		})
	}
	v, _, account := fixture(t)
	other, err := v.RemoteMCP.AddServer("other", "https://other.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(v, change("remove-mcp-account", other, account, "REMOVE")); err == nil {
		t.Fatal("cross-server account selector accepted")
	}
}

func TestClosedChangesRefuseMalformedFieldCounts(t *testing.T) {
	v, server, account := fixture(t)
	for action, count := range map[string]int{"add-mcp-server": 2, "edit-mcp-server": 3, "remove-mcp-server": 1, "add-mcp-account": 6, "edit-mcp-account": 6, "rename-mcp-account": 1, "remove-mcp-account": 1, "edit-mcp-header": 3} {
		for _, size := range []int{0, count - 1, count + 1} {
			c := ownerpacket.DirectoryChange{Action: action, ServerID: server, Account: account, Fields: make([][]byte, size)}
			if c.Valid() || Apply(v, c) == nil {
				t.Fatalf("malformed %s accepted %d fields", action, size)
			}
		}
	}
}
