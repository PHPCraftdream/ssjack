package vault

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func verifyOwnerExportFullProfile(t *testing.T, session *Session, password []byte, server, source string) {
	t.Helper()
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := session.PrepareOwnerExport(ExportSelection{Servers: map[string][]string{server: {"main"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	path := filepath.Join(t.TempDir(), "encrypted-owner.zip")
	if err := plan.WriteEncrypted(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("export rewrote its authenticated source database")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 2 {
		t.Fatal("credential-only archive has an unexpected inventory")
	}
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name == "manifest.json.ktav" {
			if _, err := keyfile.Open(encoded, []byte("wrong synthetic export password")); err == nil {
				t.Fatal("encrypted export accepted the wrong password")
			}
		}
		plain, err := keyfile.Open(encoded, password)
		if err != nil {
			t.Fatal(err)
		}
		switch entry.Name {
		case "database.ssjack.ktav":
			selected, err := unmarshal(plain)
			clear(plain)
			if err != nil {
				t.Fatal(err)
			}
			if len(selected.Targets) != 1 || len(selected.Servers) != 1 || len(selected.Secrets) != 0 || selected.OwnerStore != nil || selected.Servers[server].Name != "second-save" || len(selected.Targets["production"].PrivateKey) == 0 {
				selected.Close()
				t.Fatal("encrypted export lost its exact selected directory")
			}
			selected.Close()
		case "manifest.json.ktav":
			var index struct {
				Format   string `json:"format"`
				Database struct {
					Name string `json:"name"`
				} `json:"database"`
			}
			err := json.Unmarshal(plain, &index)
			clear(plain)
			if err != nil || index.Format != "ssjack-owner-export-v1" || index.Database.Name != "database.ssjack.ktav" {
				t.Fatal("encrypted manifest does not identify the selected database")
			}
		default:
			clear(plain)
			t.Fatal("unexpected encrypted export entry")
		}
	}
}
