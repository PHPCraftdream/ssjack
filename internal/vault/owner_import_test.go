package vault

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
)

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
	v, alpha := directoryFixture(t)
	main := v.Servers[alpha].Accounts["main"]
	target := v.Targets[main]
	target.Usage, target.SSHPolicy = "agent", SSHPolicy{Ciphers: ssh.SupportedAlgorithms().Ciphers[:1]}
	v.Targets[main] = target
	deploy := ownTarget(target)
	deploy.PrivateKey, deploy.Password, deploy.User, deploy.Usage, deploy.SSHPolicy = nil, []byte("synthetic-import-password"), "deployer", "human", SSHPolicy{}
	if err := v.SetAccount(alpha, "deploy", deploy); err != nil {
		t.Fatal(err)
	}
	beta, err := v.AddServer("staging", "main", testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	fx := &importFixture{source: v, alpha: alpha, beta: beta, passwordBytes: deploy.Password}
	values := make(map[string][]byte)
	for n, spec := range []struct {
		scope, name string
		value       []byte
	}{{"", "token", tokenValue}, {alpha, "dbpass", []byte("synthetic-alpha-value")}, {beta, "dbpass", []byte("synthetic-beta-value")}} {
		id, err := v.BindSecret("", SecretBinding{Name: spec.name, ServerID: spec.scope, Ref: directoryRef(t, byte(n+1))})
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
	opened, err := ownerarchive.ReadFile(sessionTestContext(t), path, nil)
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
	v := NewDirectory()
	if linked {
		if err := v.LinkOwnerStore(OwnerStore{Directory: t.TempDir(), StoreID: ownerID(1), Master: []byte("synthetic destination master")}); err != nil {
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
	key, err := ParseHostKey([]byte(fx.source.Targets[fx.source.Servers[fx.alpha].Accounts["main"]].HostKeys[0]))
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
		if len(v.Servers) != 2 || len(v.Targets) != 3 || len(v.Secrets) != 0 || v.OwnerStore == nil || v.OwnerStore.Pending != nil || v.OwnerStore.StoreID != ownerID(1) {
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
	i := &OwnerImport{servers: map[string]Server{}, targets: map[string]Target{}, secrets: []importSecret{{aliasID: ownerID(3), name: "only", value: []byte("synthetic"), supported: true}}}
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
