package ownerdb

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestCopiedOwnerMaterialIsIndependentlyOwned(t *testing.T) {
	original := &vault.OwnerStore{Directory: "fixture", StoreID: "fixture", Master: []byte("synthetic master"), Pending: &vault.OwnerIntent{ID: "fixture", Versions: map[string]string{"object": "version"}, Change: vault.OwnerChange{Value: []byte("synthetic pending value")}}}
	owned := copyLink(original)
	owned.Pending.Versions["object"] = "changed"
	clearLink(owned)
	if !bytes.Equal(original.Master, []byte("synthetic master")) || !bytes.Equal(original.Pending.Change.Value, []byte("synthetic pending value")) || original.Pending.Versions["object"] != "version" {
		t.Fatal("coordinator copies borrowed private buffers or version metadata")
	}
	if !bytes.Equal(owned.Master, make([]byte, len(owned.Master))) || !bytes.Equal(owned.Pending.Change.Value, make([]byte, len(owned.Pending.Change.Value))) {
		t.Fatal("coordinator cleanup did not clear owned private material")
	}
	clearLink(original)
}

func TestExportRequestOwnsItsSelectionAndRejectsConcurrentRequests(t *testing.T) {
	m := &Manager{db: &vault.Session{}, jobs: make(chan string, 1), changed: make(chan struct{})}
	request := ExportRequest{Selection: vault.ExportSelection{Servers: map[string][]string{"server": {"deploy"}}}, Destination: "synthetic-export.zip"}
	if err := m.Export(request); err != nil {
		if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
			return
		}
		t.Fatal(err)
	}
	request.Selection.Servers["server"][0] = "changed"
	delete(request.Selection.Servers, "server")
	if !m.busy || m.exportRequest == nil || m.exportRequest.Selection.Servers["server"][0] != "deploy" || <-m.jobs != ":export" {
		t.Fatal("queued export borrowed caller scope metadata")
	}
	if err := m.Export(ExportRequest{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "another.zip"}); err == nil {
		t.Fatal("concurrent export bypassed the single owner worker")
	}
}

func TestInvalidExportNeverQueuesOrPublishes(t *testing.T) {
	m := &Manager{jobs: make(chan string, 1), changed: make(chan struct{})}
	for _, request := range []ExportRequest{
		{},
		{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "synthetic.zip", PlaintextConfirmation: "yes"},
		{Selection: vault.ExportSelection{GlobalSecrets: true}, Destination: "synthetic.zip"},
	} {
		if err := m.Export(request); err == nil || m.busy || len(m.jobs) != 0 {
			t.Fatal("invalid or unauthenticated export queued work")
		}
	}
}

func TestCipherDigestChecksOnlyBoundedRegularCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database")
	encoded := []byte("synthetic ciphertext fixture")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := cipherDigest(path)
	if err != nil || digest != sha256.Sum256(encoded) {
		t.Fatal("ciphertext revision check changed or misidentified bytes")
	}
	if _, err := cipherDigest(filepath.Dir(path)); err == nil {
		t.Fatal("ciphertext checker accepted a directory")
	}
	if _, err := cipherDigest(path + "-missing"); err == nil {
		t.Fatal("ciphertext checker accepted a missing database")
	}
}
