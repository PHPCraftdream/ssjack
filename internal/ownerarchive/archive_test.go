package ownerarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func fixture(t *testing.T) (*Archive, appstoreref.Ref) {
	t.Helper()
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	database, err := json.Marshal(map[string]any{"version": 2, "targets": map[string]any{}, "servers": map[string]any{}, "secrets": map[string]any{"01000000000000000000000000000000": map[string]string{"name": "token", "server_id": "", "ref": string(encoded)}}})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(archive.Close)
	return archive, ref
}

func TestArchiveRequiresExactCompleteSelectedValues(t *testing.T) {
	a, ref := fixture(t)
	path := filepath.Join(t.TempDir(), "export.zip")
	if err := a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err == nil {
		t.Fatal("metadata-only export pretended to include values")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("incomplete export touched destination")
	}
	if err := a.Add("02000000000000000000000000000000", ref, []byte("synthetic")); err == nil {
		t.Fatal("export accepted an unselected alias")
	}
	if err := a.Add("01000000000000000000000000000000", ref, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := a.Add("01000000000000000000000000000000", ref, []byte("replacement")); err == nil {
		t.Fatal("export silently replaced a selected value")
	}
	if err := a.WriteEncrypted(context.Background(), path, nil); err == nil {
		t.Fatal("encrypted export accepted no authenticated key")
	}
}

func TestPlaintextArchivePreservesBytesAndNeverOverwrites(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("private-file runtime unavailable")
	}
	a, ref := fixture(t)
	value := []byte{'a', 0, '\n', 255, 'z'}
	if err := a.Add("01000000000000000000000000000000", ref, value); err != nil {
		t.Fatal(err)
	}
	clear(value)
	path := filepath.Join(t.TempDir(), "export.zip")
	if err := a.WritePlaintext(context.Background(), path, "yes"); err == nil {
		t.Fatal("plaintext export accepted implicit confirmation")
	}
	if err := a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("export permissions are not private")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	files := make(map[string][]byte)
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name] = body
	}
	if len(files) != 3 || !bytes.Equal(files["secrets/01000000000000000000000000000000.bin"], []byte{'a', 0, '\n', 255, 'z'}) || !bytes.Equal(files["database.json"], a.database) {
		t.Fatal("export lost selected metadata or exact value bytes")
	}
	var index manifest
	if err := json.Unmarshal(files["manifest.json"], &index); err != nil || index.Format != "ssjack-owner-export-v1" || len(index.Secrets) != 1 {
		t.Fatal("export omitted its complete inventory")
	}
	for _, record := range []fileRecord{index.Database, index.Secrets["01000000000000000000000000000000"]} {
		body, exists := files[record.Name]
		digest := sha256.Sum256(body)
		if !exists || record.Length != len(body) || record.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("manifest did not bind the actual exported file bytes")
		}
	}
	if err := a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err == nil {
		t.Fatal("export overwrote an existing artifact")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused overwrite changed the existing artifact")
	}
}

func TestArchiveCancellationAndCleanup(t *testing.T) {
	a, ref := fixture(t)
	if err := a.Add("01000000000000000000000000000000", ref, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "cancelled.zip")
	if err := a.WritePlaintext(ctx, path, "EXPORT PLAINTEXT"); err == nil {
		t.Fatal("cancelled export succeeded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pre-cancelled export created output")
	}
	owned := a.values["01000000000000000000000000000000"]
	a.Close()
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("archive close retained owned values")
	}
	if err := a.Add("01000000000000000000000000000000", ref, nil); err == nil {
		t.Fatal("closed export accepted new material")
	}
}

func TestArchiveRejectsLinkedUnlockMaterial(t *testing.T) {
	if _, err := New([]byte(`{"version":2,"targets":{},"servers":{},"secrets":{},"owner_store":{"master":"synthetic"}}`)); err == nil {
		t.Fatal("export accepted linked store unlock material")
	}
}
