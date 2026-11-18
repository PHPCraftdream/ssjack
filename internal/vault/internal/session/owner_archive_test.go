package session

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
)

func TestOwnerExportSelectsAccountsAndExplicitSecretScopes(t *testing.T) {
	v, first := vaulttest.DirectoryFixture(t)
	second, err := v.AddServer("other", "main", vaulttest.Target(t))
	if err != nil {
		t.Fatal(err)
	}
	passwordAccount := v.Targets["production"]
	passwordAccount.PrivateKey, passwordAccount.Password, passwordAccount.User = nil, []byte("synthetic-selected-password"), "other-user"
	if err := v.SetAccount(first, "second", passwordAccount); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", first, second} {
		if _, err := v.BindSecret("", SecretBinding{Name: "token", ServerID: scope, Ref: vaulttest.DirectoryRef(t, 1)}); err != nil {
			t.Fatal(err)
		}
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(s.Discard)
	plan, err := s.PrepareOwnerExport(ExportSelection{Servers: map[string][]string{first: {"second"}}, GlobalSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	bindings := plan.Bindings()
	if len(bindings) != 2 {
		t.Fatal("export did not select exact global and server scopes")
	}
	for id, binding := range bindings {
		if binding.ServerID == second {
			t.Fatal("export included another server's secret")
		}
		ref, err := appstoreplaceholder.Parse([]byte(binding.Ref))
		if err != nil {
			t.Fatal(err)
		}
		if err := plan.Add(id, ref, []byte("synthetic-selected-value")); err != nil {
			t.Fatal(err)
		}
		delete(bindings, id)
	}
	if len(plan.Bindings()) != 2 {
		t.Fatal("caller changed the prepared scope metadata")
	}
	if status := s.Status(); status.Pending || status.Revision != 0 {
		t.Fatal("export preparation queued database persistence")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return
	}
	path := filepath.Join(t.TempDir(), "selected.zip")
	if err := plan.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var selected *Vault
	for _, entry := range reader.File {
		if entry.Name != "database.ktav" {
			continue
		}
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		selected, err = core.Unmarshal(body)
		clear(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	if selected == nil {
		t.Fatal("archive omitted the selected Ktav directory")
	}
	defer selected.Close()
	profile := v.Servers[first].Accounts["second"]
	if len(selected.Servers) != 1 || len(selected.Targets) != 1 || len(selected.Secrets) != 2 || selected.OwnerStore != nil || !bytes.Equal(selected.Targets[profile].Password, passwordAccount.Password) {
		t.Fatal("export lost selected credentials or included unselected material")
	}
	if len(v.Servers) != 2 || len(v.Servers[first].Accounts) != 2 {
		t.Fatal("export changed the live database")
	}
}

func TestOwnerExportRefusesEmptyMissingDuplicateAndStaleSelections(t *testing.T) {
	v, server := vaulttest.DirectoryFixture(t)
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(s.Discard)
	for _, selection := range []ExportSelection{
		{},
		{Servers: map[string][]string{"missing": {"main"}}},
		{Servers: map[string][]string{server: {}}},
		{Servers: map[string][]string{server: {"main", "main"}}},
		{Servers: map[string][]string{server: {"missing"}}},
	} {
		if plan, err := s.PrepareOwnerExport(selection); err == nil {
			plan.Close()
			t.Fatal("invalid selection produced an export plan")
		}
	}
	plan, err := s.PrepareOwnerExport(ExportSelection{Servers: map[string][]string{server: {"main"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	path := filepath.Join(t.TempDir(), "stale.zip")
	if err := plan.WriteEncrypted(context.Background(), path); err == nil {
		t.Fatal("test session without an authenticated key sealed an export")
	}
	if err := s.Apply(func(v *Vault) error { return v.RenameServer(server, "renamed") }); err != nil {
		t.Fatal(err)
	}
	if err := plan.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err == nil {
		t.Fatal("stale export plan wrote an artifact")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("refused export touched its destination")
	}
}

type importFixture struct {
	source        *Vault
	imported      *OwnerImport
	alpha, beta   string
	tokenID       string
	passwordBytes []byte
}

// newImportFixture exports through the real plaintext writer and re-reads the
// file, so ParseOwnerImport sees exactly what an owner would hand over.
func newImportFixture(t *testing.T, tokenValue []byte) *importFixture {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("owner export requires a supported private-file runtime")
	}
	v, alpha := vaulttest.DirectoryFixture(t)
	main := v.Servers[alpha].Accounts["main"]
	target := v.Targets[main]
	target.Usage, target.SSHPolicy = "agent", SSHPolicy{Ciphers: ssh.SupportedAlgorithms().Ciphers[:1]}
	v.Targets[main] = target
	deploy := record.OwnTarget(target)
	deploy.PrivateKey, deploy.Password, deploy.User, deploy.Usage, deploy.SSHPolicy = nil, []byte("synthetic-import-password"), "deployer", "human", SSHPolicy{}
	if err := v.SetAccount(alpha, "deploy", deploy); err != nil {
		t.Fatal(err)
	}
	beta, err := v.AddServer("staging", "main", vaulttest.Target(t))
	if err != nil {
		t.Fatal(err)
	}
	fx := &importFixture{source: v, alpha: alpha, beta: beta, passwordBytes: deploy.Password}
	values := make(map[string][]byte)
	for n, spec := range []struct {
		scope, name string
		value       []byte
	}{{"", "token", tokenValue}, {alpha, "dbpass", []byte("synthetic-alpha-value")}, {beta, "dbpass", []byte("synthetic-beta-value")}} {
		id, err := v.BindSecret("", SecretBinding{Name: spec.name, ServerID: spec.scope, Ref: vaulttest.DirectoryRef(t, byte(n+1))})
		if err != nil {
			t.Fatal(err)
		}
		values[id] = spec.value
		if n == 0 {
			fx.tokenID = id
		}
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(s.Discard)
	plan, err := s.PrepareOwnerExport(ExportSelection{Servers: map[string][]string{alpha: {"main", "deploy"}, beta: {"main"}}, GlobalSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	for id, binding := range plan.Bindings() {
		reference, err := appstoreplaceholder.Parse([]byte(binding.Ref))
		if err != nil {
			t.Fatal(err)
		}
		if err := plan.Add(id, reference, values[id]); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "owner.zip")
	if err := plan.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	opened, err := ownerarchive.ReadFile(vaulttest.Context(t), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	fx.imported, err = ParseOwnerImport(opened)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fx.imported.Close)
	return fx
}

func importDestination(t *testing.T, linked bool, mutate func(*Vault)) *Session {
	t.Helper()
	v := core.NewDirectory()
	if linked {
		if err := v.LinkOwnerStore(OwnerStore{Directory: t.TempDir(), StoreID: vaulttest.OwnerID(1), Master: []byte("synthetic destination master")}); err != nil {
			t.Fatal(err)
		}
	}
	if mutate != nil {
		mutate(v)
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(s.Discard)
	return s
}

func inspectSession(s *Session, check func(*Vault)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	check(s.state)
}

func sameImportedTarget(a, b Target) bool {
	return bytes.Equal(a.PrivateKey, b.PrivateKey) && bytes.Equal(a.Password, b.Password) && a.Address == b.Address && a.User == b.User && a.Usage == b.Usage &&
		slices.Equal(a.HostKeys, b.HostKeys) && slices.Equal(a.SSHPolicy.HostKeys, b.SSHPolicy.HostKeys) && slices.Equal(a.SSHPolicy.KeyExchanges, b.SSHPolicy.KeyExchanges) &&
		slices.Equal(a.SSHPolicy.Ciphers, b.SSHPolicy.Ciphers) && slices.Equal(a.SSHPolicy.MACs, b.SSHPolicy.MACs)
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestOwnerImportPreviewIsMetadataOnly(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	preview := fx.imported.Preview()
	if preview.Encrypted || len(preview.Conflicts) != 0 || len(preview.Servers) != 2 || len(preview.Secrets) != 3 {
		t.Fatal("preview has an unexpected shape")
	}
	production := preview.Servers[0]
	key, err := record.ParseHostKey([]byte(fx.source.Targets[fx.source.Servers[fx.alpha].Accounts["main"]].HostKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	wantAccounts := []ImportAccount{{Name: "deploy", User: "deployer", Authentication: "password", Usage: "human"}, {Name: "main", User: "test", Authentication: "key", Usage: "agent"}}
	if production.ID != fx.alpha || production.Name != "production" || production.Address != "example.test:22" || !slices.Equal(production.Fingerprints, []string{ssh.FingerprintSHA256(key)}) || !reflect.DeepEqual(production.Accounts, wantAccounts) || preview.Servers[1].Name != "staging" {
		t.Fatal("preview lost server identity, pins, or account metadata")
	}
	want := []ImportSecret{
		{AliasID: fx.tokenID, Name: "token", Length: len("synthetic-global-value")},
		{Name: "dbpass", ServerID: fx.alpha, ServerName: "production", Length: len("synthetic-alpha-value")},
		{Name: "dbpass", ServerID: fx.beta, ServerName: "staging", Length: len("synthetic-beta-value")},
	}
	for n := range want {
		if want[n].AliasID != "" && preview.Secrets[n].AliasID != want[n].AliasID {
			t.Fatal("preview changed a secret alias")
		}
		preview.Secrets[n].AliasID, want[n].AliasID = "", ""
	}
	if !reflect.DeepEqual(preview.Secrets, want) {
		t.Fatal("preview secrets are wrongly scoped or ordered")
	}
	text := fmt.Sprintf("%+v", preview)
	for _, secret := range []string{"synthetic-global-value", "synthetic-alpha-value", "synthetic-beta-value", string(fx.passwordBytes), "PRIVATE KEY"} {
		if bytes.Contains([]byte(text), []byte(secret)) {
			t.Fatal("preview exposed secret material")
		}
	}
}

func TestOwnerImportSecretChangeOrderCopyAndClose(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	i := fx.imported
	if i.SecretCount() != 3 {
		t.Fatal("unexpected secret count")
	}
	preview := i.Preview()
	for n, secret := range preview.Secrets {
		change, err := i.SecretChange(n)
		if err != nil || change.Action != "add" || change.AliasID != secret.AliasID || change.Name != secret.Name || change.ServerID != secret.ServerID || change.MediaType != "text/plain" || len(change.Value) != secret.Length || change.ObjectID != "" || change.PreviousReference != "" {
			t.Fatal("secret change does not follow the preview order")
		}
		clear(change.Value)
	}
	first, err := i.SecretChange(0)
	if err != nil || string(first.Value) != "synthetic-global-value" {
		t.Fatal("clearing a handed-out value changed the owned copy")
	}
	if _, err := i.SecretChange(3); err == nil {
		t.Fatal("out-of-range secret change was accepted")
	}
	if _, err := i.SecretChange(-1); err == nil {
		t.Fatal("negative secret change was accepted")
	}
	value, key := i.secrets[0].value, i.targets[i.servers[fx.alpha].Accounts["main"]].PrivateKey
	if allZero(value) || allZero(key) {
		t.Fatal("fixture material is unexpectedly empty")
	}
	i.Close()
	i.Close()
	(*OwnerImport)(nil).Close()
	if !allZero(value) || !allZero(key) || i.SecretCount() != 0 || len(i.Preview().Servers) != 0 {
		t.Fatal("close left credential or value bytes reachable")
	}
	if _, err := i.SecretChange(0); err == nil {
		t.Fatal("closed import produced a secret change")
	}
}

func TestOwnerImportApplyPreservesIdentityAndCredentials(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	s := importDestination(t, true, nil)
	if conflicts, err := s.ImportConflicts(fx.imported); err != nil || len(conflicts) != 0 {
		t.Fatal("empty linked destination reported conflicts")
	}
	if err := s.ApplyOwnerImportDirectory(fx.imported); err != nil {
		t.Fatal(err)
	}
	if status := s.Status(); status.Revision != 1 {
		t.Fatal("import did not use exactly one Apply")
	}
	inspectSession(s, func(v *Vault) {
		if len(v.Servers) != 2 || len(v.Targets) != 3 || len(v.Secrets) != 0 || v.OwnerStore == nil || v.OwnerStore.Pending != nil || v.OwnerStore.StoreID != vaulttest.OwnerID(1) {
			t.Fatal("import changed more than servers and credentials")
		}
		for id, server := range fx.source.Servers {
			if !reflect.DeepEqual(v.Servers[id], server) {
				t.Fatal("server identity or account mapping changed")
			}
			for _, profile := range server.Accounts {
				if !sameImportedTarget(v.Targets[profile], fx.source.Targets[profile]) {
					t.Fatal("credential material changed during import")
				}
			}
		}
	})
	// The import owns separate copies, so applying never consumed them.
	if !sameImportedTarget(fx.imported.targets[fx.source.Servers[fx.alpha].Accounts["main"]], fx.source.Targets[fx.source.Servers[fx.alpha].Accounts["main"]]) {
		t.Fatal("apply disturbed the import's own credential copy")
	}
	if err := s.ApplyOwnerImportDirectory(fx.imported); err != ErrImportConflict {
		t.Fatal("repeating an import overwrote existing identities")
	}
	if status := s.Status(); status.Revision != 1 {
		t.Fatal("refused repeat import bumped the revision")
	}
}

func TestOwnerImportWithoutServersIsApplyFree(t *testing.T) {
	i := &OwnerImport{servers: map[string]Server{}, targets: map[string]Target{}, secrets: []importSecret{{aliasID: vaulttest.OwnerID(3), name: "only", value: []byte("synthetic"), supported: true}}}
	s := importDestination(t, true, nil)
	if err := s.ApplyOwnerImportDirectory(i); err != nil || s.Status().Revision != 0 {
		t.Fatal("secret-only import should succeed without an Apply")
	}
	if err := importDestinationApply(t, i); err != ErrImportConflict {
		t.Fatal("secret-only import into an unlinked destination was not refused")
	}
}

func importDestinationApply(t *testing.T, i *OwnerImport) error {
	t.Helper()
	return importDestination(t, false, nil).ApplyOwnerImportDirectory(i)
}

type mcpArchiveFixture struct {
	session        *Session
	sshID, profile string
	serverID       string
	bindings       []mcpdirectory.Binding
	secrets        [][]byte
}

func newMCPArchiveFixture(t *testing.T) *mcpArchiveFixture {
	t.Helper()
	state, sshID := vaulttest.DirectoryFixture(t)
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
	state, sshID := vaulttest.DirectoryFixture(t)
	profile := state.Servers[sshID].Accounts["main"]
	before := record.OwnTarget(state.Targets[profile])
	defer clear(before.PrivateKey)
	state.RemoteMCP = mcpdirectory.New()
	destination := newSession(state, func(context.Context, []byte) error { return nil }, func() {})
	t.Cleanup(destination.Discard)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil {
		t.Fatal(err)
	}
	inspectSession(destination, func(current *Vault) {
		if len(current.RemoteMCP.Last) != 0 || !record.SameTarget(current.Targets[profile], before) || len(current.Servers) != 1 {
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
	state, _ := vaulttest.DirectoryFixture(t)
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
