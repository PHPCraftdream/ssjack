package vault

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
)

type mcpArchiveFixture struct {
	session        *Session
	sshID, profile string
	serverID       string
	bindings       []mcpdirectory.Binding
	secrets        [][]byte
}

func newMCPArchiveFixture(t *testing.T) *mcpArchiveFixture {
	t.Helper()
	state, sshID := directoryFixture(t)
	profile := state.Servers[sshID].Accounts["main"]
	state.RemoteMCP = mcpdirectory.New()
	serverID, err := state.RemoteMCP.AddServer("private-docs", "https://docs.example.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{[]byte("synthetic-basic-secret"), []byte("synthetic-bearer-secret"), []byte("synthetic-header-secret")}
	accounts := []mcpdirectory.Account{
		{ServerID: serverID, Name: "none", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}},
		{ServerID: serverID, Name: "basic", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "basic", Username: "synthetic-user", Secret: secrets[0]}, Headers: []mcpdirectory.Header{{Name: "X-Account-Tag", Value: []byte("synthetic-basic-header")}}},
		{ServerID: serverID, Name: "bearer", Enabled: false, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: secrets[1]}, Headers: []mcpdirectory.Header{{Name: "X-Bearer-Tag", Value: secrets[2]}}},
	}
	var bindings []mcpdirectory.Binding
	for _, account := range accounts {
		id, err := state.RemoteMCP.AddAccount(account)
		if err != nil {
			t.Fatal(err)
		}
		saved := state.RemoteMCP.Accounts[id]
		bindings = append(bindings, mcpdirectory.Binding{ServerID: serverID, AccountID: id, ServerRevision: state.RemoteMCP.Servers[serverID].Revision, AccountRevision: saved.Revision})
	}
	other, err := state.RemoteMCP.AddServer("unselected", "https://other.example.test/mcp")
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := state.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: other, Name: "excluded", Enabled: true, Auth: mcpdirectory.Authentication{Kind: "none"}})
	if err != nil {
		t.Fatal(err)
	}
	state.RemoteMCP.Last[profile] = []mcpdirectory.Binding{
		bindings[0],
		{ServerID: serverID, AccountID: bindings[1].AccountID, ServerRevision: bindings[1].ServerRevision, AccountRevision: bindings[1].AccountRevision + 1},
		bindings[2],
		{ServerID: other, AccountID: otherID, ServerRevision: state.RemoteMCP.Servers[other].Revision, AccountRevision: state.RemoteMCP.Accounts[otherID].Revision},
	}
	session := newSession(state, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(session.Discard)
	return &mcpArchiveFixture{session: session, sshID: sshID, profile: profile, serverID: serverID, bindings: bindings, secrets: secrets}
}

func exportedMCPImport(t *testing.T, session *Session, selection ExportSelection) *OwnerImport {
	t.Helper()
	plan, err := session.PrepareOwnerExport(selection)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	path := filepath.Join(t.TempDir(), "selected-mcp.zip")
	if err := plan.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	opened, err := ownerarchive.ReadFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	imported, err := ParseOwnerImport(opened)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(imported.Close)
	return imported
}

func TestOwnerMCPArchiveSelectionRoundTripAndImport(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	selection := ExportSelection{Servers: map[string][]string{fx.sshID: {"main"}}, RemoteMCP: fx.bindings}
	imported := exportedMCPImport(t, fx.session, selection)
	if len(imported.servers) != 1 || len(imported.targets) != 1 || len(imported.remoteMCP.Servers) != 1 || len(imported.remoteMCP.Accounts) != 3 {
		t.Fatal("selected archive records changed")
	}
	if _, exists := imported.remoteMCP.Servers[fx.serverID]; exists {
		t.Fatal("archive MCP server ID survived import")
	}
	for _, server := range imported.remoteMCP.Servers {
		if server.Revision != 1 {
			t.Fatal("MCP server revision was not reset")
		}
	}
	kinds := map[string]bool{}
	for _, account := range imported.remoteMCP.Accounts {
		kinds[account.Auth.Kind] = true
		if account.Revision != 1 {
			t.Fatal("MCP account revision was not reset")
		}
		switch account.Auth.Kind {
		case "none":
			if !account.Enabled {
				t.Fatal("none enabled state changed")
			}
		case "basic":
			if !account.Enabled || account.Auth.Username != "synthetic-user" || !bytes.Equal(account.Auth.Secret, fx.secrets[0]) || len(account.Headers) != 1 || !bytes.Equal(account.Headers[0].Value, []byte("synthetic-basic-header")) {
				t.Fatal("basic auth/header changed")
			}
		case "bearer":
			if account.Enabled || !bytes.Equal(account.Auth.Secret, fx.secrets[1]) || len(account.Headers) != 1 || !bytes.Equal(account.Headers[0].Value, fx.secrets[2]) {
				t.Fatal("disabled bearer auth/header changed")
			}
		}
	}
	if !kinds["none"] || !kinds["basic"] || !kinds["bearer"] {
		t.Fatal("authentication kind omitted")
	}
	for _, binding := range fx.bindings {
		if _, exists := imported.remoteMCP.Accounts[binding.AccountID]; exists {
			t.Fatal("archive MCP account ID survived import")
		}
	}
	if len(imported.remoteMCP.Last[fx.profile]) != 1 || imported.remoteMCP.Validate() != nil || imported.remoteMCP.Last[fx.profile][0].ServerRevision != 1 || imported.remoteMCP.Last[fx.profile][0].AccountRevision != 1 {
		t.Fatal("Last references were not revision-filtered and remapped")
	}
	if len(imported.remoteMCP.Accounts) != 3 {
		t.Fatal("unselected MCP account was included")
	}
	metadata := []byte(fmt.Sprintf("%+v", imported.Preview().RemoteMCP))
	for _, secret := range [][]byte{fx.secrets[0], fx.secrets[1], fx.secrets[2], []byte("synthetic-basic-header")} {
		if bytes.Contains(metadata, secret) {
			t.Fatal("MCP preview exposed private bytes")
		}
	}
	var owned [][]byte
	for _, account := range imported.remoteMCP.Accounts {
		owned = append(owned, account.Auth.Secret)
		for _, header := range account.Headers {
			owned = append(owned, header.Value)
		}
	}
	imported.Close()
	for _, value := range owned {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("closing the import left MCP private bytes uncleared")
		}
	}
}

func TestOwnerMCPArchiveRefusesBadSelection(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	binding := fx.bindings[0]
	badSelections := [][]mcpdirectory.Binding{
		{binding, binding},
		{{ServerID: binding.ServerID, AccountID: fmt.Sprintf("%032x", 999), ServerRevision: binding.ServerRevision, AccountRevision: binding.AccountRevision}},
		{{ServerID: fmt.Sprintf("%032x", 998), AccountID: binding.AccountID, ServerRevision: binding.ServerRevision, AccountRevision: binding.AccountRevision}},
		{{ServerID: binding.ServerID, AccountID: binding.AccountID, ServerRevision: binding.ServerRevision + 1, AccountRevision: binding.AccountRevision}},
		{{ServerID: binding.ServerID, AccountID: binding.AccountID, ServerRevision: binding.ServerRevision, AccountRevision: binding.AccountRevision + 1}},
	}
	for _, selected := range badSelections {
		if plan, err := fx.session.PrepareOwnerExport(ExportSelection{RemoteMCP: selected}); err == nil {
			plan.Close()
			t.Fatal("duplicate, unknown, or stale selection accepted")
		}
	}
	if (ExportSelection{RemoteMCP: []mcpdirectory.Binding{{ServerID: binding.ServerID, AccountID: binding.AccountID, AccountRevision: binding.AccountRevision}}}).Validate() == nil {
		t.Fatal("zero server revision accepted")
	}
	oversized := make([]mcpdirectory.Binding, mcpdirectory.MaxAccounts+1)
	for index := range oversized {
		oversized[index] = mcpdirectory.Binding{ServerID: binding.ServerID, AccountID: fmt.Sprintf("%032x", index+1), ServerRevision: 1, AccountRevision: 1}
	}
	if (ExportSelection{RemoteMCP: oversized}).Validate() == nil {
		t.Fatal("oversized account selection accepted")
	}
}
