package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func ownerExportAcceptance(t *testing.T, ctx context.Context, manager *ownerdb.Manager, database string, password []byte, server, alias string, original vault.Target) {
	t.Helper()
	before, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	selection := vault.ExportSelection{Servers: map[string][]string{server: {"main", "second"}}, GlobalSecrets: true}
	for _, encrypted := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "owner-export.zip")
		request := ownerdb.ExportRequest{Selection: selection, Destination: path}
		if !encrypted {
			request.PlaintextConfirmation = "EXPORT PLAINTEXT"
		}
		if err := manager.Export(request); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		verifyOwnerArchive(t, path, password, encrypted, server, alias, original)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Export(request); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err == nil {
			t.Fatal("owner export overwrote an existing artifact")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(encoded, after) {
			t.Fatal("refused export changed an existing artifact")
		}
		if err := manager.RetryDatabase(); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(database)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("owner export changed the source database")
	}
}

func verifyOwnerArchive(t *testing.T, path string, password []byte, encrypted bool, server, alias string, original vault.Target) {
	t.Helper()
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 3 {
		t.Fatal("owner export did not include its exact value inventory")
	}
	foundDatabase, foundValue, foundManifest := false, false, false
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(input, 1024*1024))
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		if encrypted {
			body, err = keyfile.Open(body, password)
			if err != nil {
				t.Fatal(err)
			}
		}
		switch entry.Name {
		case "database.ktav", "database.ssjack.ktav":
			var selected vault.Vault
			err := pure.LoadsInto(string(body), &selected)
			clear(body)
			if err != nil {
				t.Fatal(err)
			}
			main := selected.Servers[server].Accounts["main"]
			second := selected.Servers[server].Accounts["second"]
			if len(selected.Targets) != 2 || selected.OwnerStore != nil || selected.Secrets[alias].Name != "initial" || !bytes.Equal(selected.Targets[main].PrivateKey, original.PrivateKey) || !bytes.Equal(selected.Targets[second].Password, []byte("synthetic SSH account password")) {
				selected.Close()
				t.Fatal("owner export lost credentials, scopes or settings")
			}
			selected.Close()
			foundDatabase = true
		case "secrets/" + alias + ".bin", "secrets/" + alias + ".bin.ktav":
			value := body
			if encrypted {
				if len(value) == 0 || value[0] != 1 {
					clear(body)
					t.Fatal("encrypted value omitted its format frame")
				}
				value = value[1:]
			}
			if !bytes.Equal(value, []byte("updated owner fixture value")) {
				clear(body)
				t.Fatal("export did not collect the actual exact private value")
			}
			clear(body)
			foundValue = true
		case "manifest.json", "manifest.json.ktav":
			var manifest struct {
				Format  string         `json:"format"`
				Secrets map[string]any `json:"secrets"`
			}
			err := json.Unmarshal(body, &manifest)
			clear(body)
			if err != nil || manifest.Format != "ssjack-owner-export-v1" || len(manifest.Secrets) != 1 || manifest.Secrets[alias] == nil {
				t.Fatal("export manifest lost the selected alias inventory")
			}
			foundManifest = true
		default:
			clear(body)
			t.Fatal("owner export included unselected material")
		}
	}
	if !foundDatabase || !foundValue || !foundManifest {
		t.Fatal("owner export was incomplete")
	}
}
