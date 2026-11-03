package vault

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func TestOwnerExportSelectsAccountsAndExplicitSecretScopes(t *testing.T) {
	v, first := directoryFixture(t)
	second, err := v.AddServer("other", "main", testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	passwordAccount := v.Targets["production"]
	passwordAccount.PrivateKey, passwordAccount.Password, passwordAccount.User = nil, []byte("synthetic-selected-password"), "other-user"
	if err := v.SetAccount(first, "second", passwordAccount); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", first, second} {
		if _, err := v.BindSecret("", SecretBinding{Name: "token", ServerID: scope, Ref: directoryRef(t, 1)}); err != nil {
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
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
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
		selected, err = unmarshal(body)
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
	v, server := directoryFixture(t)
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
