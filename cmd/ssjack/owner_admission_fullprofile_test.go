package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func ownerAdmissionAcceptance(t *testing.T, manager *ownerdb.Manager, directory string) {
	t.Helper()
	before, err := manager.Snapshot()
	if err != nil || before.CipherDigest == ([32]byte{}) || before.Status.Database.Pending || before.Status.Database.Revision != before.Status.Database.SavedRevision {
		t.Fatal("initial coordinator snapshot has no consistent saved receipt")
	}
	destination := filepath.Join(t.TempDir(), "not-written.zip")
	archive := filepath.Join(t.TempDir(), "not-read.zip")
	cases := map[string]func(uint64) error{
		"edit": func(revision uint64) error {
			return manager.EditAt(revision, func(*vault.Vault) error { t.Fatal("stale edit callback executed"); return nil })
		},
		"link": func(revision uint64) error {
			return manager.LinkAt(revision, directory, []byte("synthetic-unused-master"))
		},
		"export": func(revision uint64) error {
			return manager.ExportAt(revision, ownerdb.ExportRequest{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: destination})
		},
		"inspect": func(revision uint64) error {
			return manager.InspectImportAt(revision, archive, []byte("synthetic-unused-password"))
		},
		"retry": manager.RetryDatabaseAt,
		"abort": manager.AbortImportAt,
	}
	for action, apply := range cases {
		t.Run("stale-"+action, func(t *testing.T) {
			if err := apply(before.Status.Database.Revision + 1); !errors.Is(err, vault.ErrOwnerRevision) {
				t.Fatal("stale owner command did not refuse before publication")
			}
			after, err := manager.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("stale admission changed metadata, import state, busy state or persistence receipt")
			}
			if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("stale export touched its destination")
			}
		})
	}
}
