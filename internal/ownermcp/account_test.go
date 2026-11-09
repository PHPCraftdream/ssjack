package ownermcp

import (
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestNewAccountCannotKeepAndFailedInitializationStaysAbsent(t *testing.T) {
	v := &vault.Vault{}
	defer v.Close()
	if err := Apply(v, change("add-mcp-server", "", "", "docs", "http://docs.invalid/mcp")); err == nil || v.RemoteMCP != nil {
		t.Fatal("invalid initialization installed MCP state")
	}
	v, server, _ := fixture(t)
	before := v.RemoteMCP.Record()
	if err := Apply(v, change("add-mcp-account", server, "", "other", "true", "none", "", "keep", "")); err == nil {
		t.Fatal("new account accepted a borrowed credential decision")
	}
	if !reflect.DeepEqual(before, v.RemoteMCP.Record()) {
		t.Fatal("failed new account changed directory")
	}
	if err := Apply(v, change("add-mcp-account", server, "", "public", "true", "none", "", "clear", "")); err != nil {
		t.Fatal(err)
	}
	for _, a := range v.RemoteMCP.Accounts {
		if a.Name == "public" && (a.Auth.Kind != "none" || len(a.Auth.Secret) != 0) {
			t.Fatal("public account inherited another credential")
		}
	}
}

func TestBasicPrincipalChangeRequiresNewCredential(t *testing.T) {
	v, server, account := fixture(t)
	if err := Apply(v, change("edit-mcp-account", server, account, "work", "true", "basic", "first", "replace", "synthetic-password")); err != nil {
		t.Fatal(err)
	}
	before := v.RemoteMCP.Record()
	if err := Apply(v, change("edit-mcp-account", server, account, "work", "true", "basic", "second", "keep", "")); err == nil {
		t.Fatal("changed Basic principal inherited password")
	}
	if !reflect.DeepEqual(before, v.RemoteMCP.Record()) {
		t.Fatal("refused principal change altered account")
	}
	if err := Apply(v, change("edit-mcp-account", server, account, "work", "true", "basic", "first", "keep", "")); err != nil {
		t.Fatal(err)
	}
}

func TestAccountPolicyAndHeaderChangesInvalidatePreference(t *testing.T) {
	for _, action := range []string{"disable", "keep", "header"} {
		t.Run(action, func(t *testing.T) {
			v, server, account := fixture(t)
			d := v.RemoteMCP
			binding, err := d.CurrentBinding(account)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.Remember("synthetic-profile", []mcpdirectory.Binding{binding}); err != nil {
				t.Fatal(err)
			}
			c := change("edit-mcp-account", server, account, "work", "true", "bearer", "", "keep", "")
			switch action {
			case "disable":
				c.Fields[1] = []byte("false")
			case "header":
				c = change("edit-mcp-header", server, account, "X-Api-Key", "replace", "synthetic-api-key")
			}
			if err := Apply(v, c); err != nil {
				t.Fatal(err)
			}
			if len(d.Suggested("synthetic-profile")) != 0 {
				t.Fatal("account edit preserved an obsolete confirmed binding")
			}
		})
	}
}
