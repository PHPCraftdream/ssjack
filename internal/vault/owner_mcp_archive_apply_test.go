package vault

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

func TestOwnerMCPArchiveMCPOnlyIsIsolated(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	binding := fx.bindings[0]
	imported := exportedMCPImport(t, fx.session, ExportSelection{RemoteMCP: []mcpdirectory.Binding{binding}})
	if len(imported.servers) != 0 || len(imported.targets) != 0 || len(imported.remoteMCP.Last) != 0 || len(imported.remoteMCP.Accounts) != 1 {
		t.Fatal("MCP-only import invented SSH context or included records")
	}
	destination := importDestination(t, false, nil)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil || destination.Status().Revision != 1 || destination.VerifyOwnerImportDirectory(imported) != nil {
		t.Fatal("MCP-only import did not apply and verify once")
	}
	conflicts, err := destination.ImportConflicts(imported)
	if err != nil || !hasConflict(conflicts, ConflictMCPServerID, "private-docs") || destination.ApplyOwnerImportDirectory(imported) != ErrImportConflict {
		t.Fatal("repeat MCP import did not refuse overwrite")
	}
}

func TestOwnerMCPImportConflictsLeaveExistingSSHProfileUntouched(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	imported := exportedMCPImport(t, fx.session, ExportSelection{RemoteMCP: fx.bindings})
	state, sshID := directoryFixture(t)
	profile := state.Servers[sshID].Accounts["main"]
	before := ownTarget(state.Targets[profile])
	defer clear(before.PrivateKey)
	state.RemoteMCP = mcpdirectory.New()
	destination := newSession(state, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(destination.Discard)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil {
		t.Fatal(err)
	}
	inspectSession(destination, func(current *Vault) {
		if len(current.RemoteMCP.Last) != 0 || !sameImportTarget(current.Targets[profile], before) || len(current.Servers) != 1 {
			t.Fatal("MCP-only import attached to or changed the existing SSH profile")
		}
	})
}

func TestOwnerMCPImportResumeVerificationChecksPrivateMutations(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	imported := exportedMCPImport(t, fx.session, ExportSelection{Servers: map[string][]string{fx.sshID: {"main"}}, RemoteMCP: fx.bindings})
	destination := importDestination(t, false, nil)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil || destination.VerifyOwnerImportDirectory(imported) != nil {
		t.Fatal("freshly applied MCP import did not verify")
	}
	fx.secrets[0][0] ^= 1
	stored := fx.session.state.RemoteMCP.Accounts[fx.bindings[1].AccountID].Auth.Secret
	var copied []byte
	for _, account := range imported.remoteMCP.Accounts {
		if account.Auth.Kind == "basic" {
			copied = account.Auth.Secret
			break
		}
	}
	if !bytes.Equal(stored, []byte("synthetic-basic-secret")) || !bytes.Equal(copied, []byte("synthetic-basic-secret")) {
		t.Fatal("MCP import or directory retained caller-owned auth bytes")
	}
	if err := destination.Apply(func(candidate *Vault) error {
		for id, account := range candidate.RemoteMCP.Accounts {
			if len(account.Headers) != 0 {
				account.Headers[0].Value[0] ^= 1
				candidate.RemoteMCP.Accounts[id] = account
				return nil
			}
		}
		return ErrImportChanged
	}); err != nil || destination.VerifyOwnerImportDirectory(imported) != ErrImportChanged {
		t.Fatal("resume verification missed an imported MCP header mutation")
	}

	lastDestination := importDestination(t, false, nil)
	if err := lastDestination.ApplyOwnerImportDirectory(imported); err != nil || lastDestination.VerifyOwnerImportDirectory(imported) != nil {
		t.Fatal("freshly applied MCP import did not verify before Last mutation")
	}
	if err := lastDestination.Apply(func(candidate *Vault) error {
		candidate.RemoteMCP.Last[fx.profile] = nil
		return nil
	}); err != nil || lastDestination.VerifyOwnerImportDirectory(imported) != ErrImportChanged {
		t.Fatal("resume verification missed an imported Last mutation")
	}
}

func TestOwnerMCPImportResumeDetectsChangedAuthentication(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	imported := exportedMCPImport(t, fx.session, ExportSelection{Servers: map[string][]string{fx.sshID: {"main"}}, RemoteMCP: fx.bindings})
	destination := importDestination(t, false, nil)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil {
		t.Fatal(err)
	}
	if err := destination.Apply(func(candidate *Vault) error {
		for id, account := range candidate.RemoteMCP.Accounts {
			if account.Auth.Kind == "basic" {
				account.Auth.Secret[0] ^= 1
				candidate.RemoteMCP.Accounts[id] = account
				return nil
			}
		}
		return ErrImportChanged
	}); err != nil {
		t.Fatal(err)
	}
	if destination.VerifyOwnerImportDirectory(imported) != ErrImportChanged {
		t.Fatal("resume verification missed an imported MCP authentication mutation")
	}
	for _, account := range imported.remoteMCP.Accounts {
		if account.Auth.Kind == "basic" && !bytes.Equal(account.Auth.Secret, fx.secrets[0]) {
			t.Fatal("destination mutation changed the imported plan's original authentication")
		}
	}
}

func TestOwnerMCPImportDestinationConflicts(t *testing.T) {
	fx := newMCPArchiveFixture(t)
	imported := exportedMCPImport(t, fx.session, ExportSelection{RemoteMCP: fx.bindings})
	cases := []struct {
		name, kind, existingName, endpoint string
	}{
		{"name", ConflictMCPServerName, "private-docs", "https://different.example.test/mcp"},
		{"endpoint", ConflictMCPServerURL, "existing", "https://docs.example.test/mcp"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			destination := importDestination(t, false, func(state *Vault) {
				state.RemoteMCP = mcpdirectory.New()
				if _, err := state.RemoteMCP.AddServer(test.existingName, test.endpoint); err != nil {
					t.Fatal(err)
				}
			})
			conflicts, err := destination.ImportConflicts(imported)
			if err != nil || !hasConflict(conflicts, test.kind, "private-docs") || destination.ApplyOwnerImportDirectory(imported) != ErrImportConflict || destination.Status().Revision != 0 {
				t.Fatalf("%s collision was not refused: %v", test.name, conflicts)
			}
		})
	}
	t.Run("server limit", func(t *testing.T) {
		destination := importDestination(t, false, func(state *Vault) {
			state.RemoteMCP = mcpdirectory.New()
			for n := 0; n < mcpdirectory.MaxServers; n++ {
				name := fmt.Sprintf("existing-%02d", n)
				endpoint := fmt.Sprintf("https://existing-%02d.example.test/mcp", n)
				if _, err := state.RemoteMCP.AddServer(name, endpoint); err != nil {
					t.Fatal(err)
				}
			}
		})
		conflicts, err := destination.ImportConflicts(imported)
		if err != nil || !hasConflict(conflicts, ConflictMCPServerLimit, "") || destination.ApplyOwnerImportDirectory(imported) != ErrImportConflict || destination.Status().Revision != 0 {
			t.Fatalf("server limit was not refused: %v", conflicts)
		}
	})
}

func TestOwnerMCPArchiveAllowsSharedSourceURLsButRefusesDestinationCollision(t *testing.T) {
	state, _ := directoryFixture(t)
	state.RemoteMCP = mcpdirectory.New()
	const sharedURL = "https://shared.example.test/mcp"
	serverIDs := make(map[string]string)
	var bindings []mcpdirectory.Binding
	for _, name := range []string{"alpha", "beta"} {
		serverID, err := state.RemoteMCP.AddServer(name, sharedURL)
		if err != nil {
			t.Fatal(err)
		}
		serverIDs[name] = serverID
		accountID, err := state.RemoteMCP.AddAccount(mcpdirectory.Account{
			ServerID: serverID, Name: name + "-account", Enabled: true,
			Auth:    mcpdirectory.Authentication{Kind: "basic", Username: name + "-user", Secret: []byte("synthetic-" + name + "-secret")},
			Headers: []mcpdirectory.Header{{Name: "X-Source-Tag", Value: []byte("synthetic-" + name + "-header")}},
		})
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, mcpdirectory.Binding{ServerID: serverID, AccountID: accountID, ServerRevision: state.RemoteMCP.Servers[serverID].Revision, AccountRevision: state.RemoteMCP.Accounts[accountID].Revision})
	}
	source := newSession(state, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(source.Discard)
	imported := exportedMCPImport(t, source, ExportSelection{RemoteMCP: bindings})
	if len(imported.remoteMCP.Servers) != 2 || len(imported.remoteMCP.Accounts) != 2 || imported.remoteMCP.Validate() != nil {
		t.Fatal("archive did not preserve the valid shared-URL source directory")
	}
	for name := range serverIDs {
		var importedID, accountID string
		for id, server := range imported.remoteMCP.Servers {
			if server.Name == name {
				importedID = id
				if server.URL != sharedURL {
					t.Fatalf("%s server URL changed in the archive", name)
				}
			}
		}
		for id, account := range imported.remoteMCP.Accounts {
			if account.Name == name+"-account" {
				accountID = id
				if account.ServerID != importedID || account.Auth.Kind != "basic" || account.Auth.Username != name+"-user" || !bytes.Equal(account.Auth.Secret, []byte("synthetic-"+name+"-secret")) || len(account.Headers) != 1 || !bytes.Equal(account.Headers[0].Value, []byte("synthetic-"+name+"-header")) {
					t.Fatalf("%s account credentials or server link changed", name)
				}
			}
		}
		if importedID == "" || accountID == "" {
			t.Fatalf("%s record was omitted from the archive", name)
		}
		for _, originalID := range serverIDs {
			if importedID == originalID {
				t.Fatalf("%s server ID was not freshly remapped", name)
			}
		}
		for _, binding := range bindings {
			if accountID == binding.AccountID {
				t.Fatalf("%s account ID was not freshly remapped", name)
			}
		}
	}

	empty := importDestination(t, false, nil)
	if conflicts, err := empty.ImportConflicts(imported); err != nil || len(conflicts) != 0 {
		t.Fatalf("shared-URL archive conflicted with empty destination: %v", conflicts)
	}
	if err := empty.ApplyOwnerImportDirectory(imported); err != nil || empty.Status().Revision != 1 || empty.VerifyOwnerImportDirectory(imported) != nil {
		t.Fatal("valid shared-URL archive did not apply once and verify")
	}
	inspectSession(empty, func(current *Vault) {
		if len(current.RemoteMCP.Servers) != 2 || len(current.RemoteMCP.Accounts) != 2 {
			t.Fatal("applying archive lost a server or account")
		}
		for id, expected := range imported.remoteMCP.Accounts {
			got, exists := current.RemoteMCP.Accounts[id]
			if !exists || got.ServerID != expected.ServerID || got.Name != expected.Name || got.Auth.Username != expected.Auth.Username || !bytes.Equal(got.Auth.Secret, expected.Auth.Secret) || len(got.Headers) != 1 || !bytes.Equal(got.Headers[0].Value, expected.Headers[0].Value) {
				t.Fatal("applied account credentials or graph link changed")
			}
		}
	})

	var existingServerID, existingAccountID string
	const existingSecret = "synthetic-destination-secret"
	collision := importDestination(t, false, func(current *Vault) {
		current.RemoteMCP = mcpdirectory.New()
		var err error
		existingServerID, err = current.RemoteMCP.AddServer("destination", sharedURL)
		if err != nil {
			t.Fatal(err)
		}
		existingAccountID, err = current.RemoteMCP.AddAccount(mcpdirectory.Account{
			ServerID: existingServerID, Name: "destination-account", Enabled: true,
			Auth: mcpdirectory.Authentication{Kind: "basic", Username: "destination-user", Secret: []byte(existingSecret)},
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	conflicts, err := collision.ImportConflicts(imported)
	if err != nil || !hasConflict(conflicts, ConflictMCPServerURL, "alpha") || collision.ApplyOwnerImportDirectory(imported) != ErrImportConflict || collision.Status().Revision != 0 {
		t.Fatalf("destination URL collision was not refused without an Apply: %v", conflicts)
	}
	inspectSession(collision, func(current *Vault) {
		server, serverExists := current.RemoteMCP.Servers[existingServerID]
		account, accountExists := current.RemoteMCP.Accounts[existingAccountID]
		if len(current.RemoteMCP.Servers) != 1 || len(current.RemoteMCP.Accounts) != 1 || !serverExists || server.Name != "destination" || server.URL != sharedURL || !accountExists || account.Name != "destination-account" || account.Auth.Username != "destination-user" || !bytes.Equal(account.Auth.Secret, []byte(existingSecret)) {
			t.Fatal("refused URL collision overwrote destination MCP records or credentials")
		}
	})
}
