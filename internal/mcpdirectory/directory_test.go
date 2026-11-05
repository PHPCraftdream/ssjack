package mcpdirectory

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func fixture(t *testing.T) (*Directory, string, string) {
	t.Helper()
	d := New()
	server, err := d.AddServer("docs", "https://docs.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account, err := d.AddAccount(Account{ServerID: server, Name: "work", Enabled: true, Auth: Authentication{Kind: "bearer", Secret: []byte("synthetic-mcp-secret")}, Headers: []Header{{Name: "X-Api-Key", Value: []byte("synthetic-header-secret")}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Clear)
	return d, server, account
}
func TestCredentialsAreOwnedAndMetadataIsRedacted(t *testing.T) {
	d, server, _ := fixture(t)
	secret := []byte("synthetic-owned-password")
	input := Account{ServerID: server, Name: "second", Enabled: true, Auth: Authentication{Kind: "basic", Username: "operator", Secret: secret}}
	id, err := d.AddAccount(input)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	if !bytes.Equal(d.Accounts[id].Auth.Secret, []byte("synthetic-owned-password")) {
		t.Fatal("MCP account borrowed caller credentials")
	}
	metadata := d.Metadata()
	text := fmt.Sprintf("%+v", metadata)
	for _, value := range []string{"synthetic-owned-password", "synthetic-mcp-secret", "synthetic-header-secret"} {
		if bytes.Contains([]byte(text), []byte(value)) {
			t.Fatal("MCP metadata exposed a credential")
		}
	}
	for i := range metadata.Accounts {
		if len(metadata.Accounts[i].HeaderNames) != 0 {
			metadata.Accounts[i].HeaderNames[0] = "Changed"
		}
	}
	for _, account := range d.Accounts {
		if len(account.Headers) != 0 && account.Headers[0].Name != "X-Api-Key" {
			t.Fatal("metadata borrowed private account slices")
		}
	}
	owned := d.Accounts[id].Auth.Secret
	if err := d.RemoveAccount(id); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("removed MCP credentials were not cleared")
	}
}
func TestLastChoiceIsPerContextExplicitAndRevisionPinned(t *testing.T) {
	d, server, account := fixture(t)
	binding, err := d.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Suggested("deploy")) != 0 {
		t.Fatal("singleton MCP was automatically selected")
	}
	selected := []Binding{binding}
	if err := d.Remember("deploy", selected); err != nil {
		t.Fatal(err)
	}
	selected[0].AccountID = "changed"
	if len(d.Suggested("deploy")) != 1 || len(d.Suggested("admin")) != 0 {
		t.Fatal("selection leaked across SSH contexts or borrowed caller state")
	}
	if err := d.EditServer(server, "renamed", "https://docs.invalid/mcp", true); err != nil {
		t.Fatal(err)
	}
	if err := d.RenameAccount(account, "renamed"); err != nil {
		t.Fatal(err)
	}
	if len(d.Suggested("deploy")) != 1 {
		t.Fatal("display rename changed MCP identity")
	}
	if err := d.EditServer(server, "renamed", "https://other.invalid/mcp", true); err != nil {
		t.Fatal(err)
	}
	if len(d.Suggested("deploy")) != 0 || !errors.Is(d.Remember("deploy", []Binding{binding}), ErrChanged) {
		t.Fatal("changed endpoint inherited a confirmed choice")
	}
	fresh, err := d.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Remember("deploy", []Binding{fresh}); err != nil {
		t.Fatal(err)
	}
	if err := d.Remember("deploy", []Binding{fresh, fresh}); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate MCP selection accepted")
	}
	if err := d.Remember("deploy", nil); err != nil {
		t.Fatal(err)
	}
	if len(d.Suggested("deploy")) != 0 {
		t.Fatal("explicit empty choice was not preserved")
	}
	if _, exists := d.Last["deploy"]; !exists {
		t.Fatal("empty confirmation was dropped")
	}
}
func TestAccountReplacementDisableAndDeletionInvalidateSuggestions(t *testing.T) {
	d, server, account := fixture(t)
	binding, err := d.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Remember("deploy", []Binding{binding}); err != nil {
		t.Fatal(err)
	}
	previous := d.Accounts[account].Auth.Secret
	value := d.Accounts[account]
	value.Auth.Secret = []byte("synthetic-replacement-secret")
	if err := d.ReplaceAccount(account, value); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(previous, make([]byte, len(previous))) || len(d.Suggested("deploy")) != 0 {
		t.Fatal("credential replacement retained old material or authorization suggestion")
	}
	binding, err = d.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Remember("deploy", []Binding{binding}); err != nil {
		t.Fatal(err)
	}
	if err := d.EditServer(server, "docs", "https://docs.invalid/mcp", false); err != nil {
		t.Fatal(err)
	}
	if len(d.Suggested("deploy")) != 0 {
		t.Fatal("disabled MCP was preselected")
	}
	if err := d.RemoveServer(server); err != nil {
		t.Fatal(err)
	}
	if len(d.Accounts) != 0 || len(d.Last["deploy"]) != 0 || d.Validate() != nil {
		t.Fatal("MCP deletion left dangling records")
	}
}
