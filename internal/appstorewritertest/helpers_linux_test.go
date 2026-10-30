//go:build linux

package appstorewritertest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

func deriveMaster(t *testing.T, ctx context.Context, store [16]byte) *appstorecrypto.Master {
	t.Helper()
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	copy(raw[12:28], store[:])
	raw[28] = 9
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint32(raw[72:76], 1)
	raw[208] = 7
	for i := 0; i < 4; i++ {
		if _, err := rand.Read(raw[80+i*32 : 112+i*32]); err != nil {
			t.Fatal(err)
		}
	}
	header, err := appstoreheader.Parse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	master, err := appstorecrypto.Derive(ctx, header, []byte("synthetic integration passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	return master
}

func checkBurnState(t *testing.T, ctx context.Context, root string, transport *appstoreanchortls.Writer, expected appstoreanchorstate.State, snapshot [16]byte, marker []byte) {
	t.Helper()
	reply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := reply.State()
	if !ok || actual != expected {
		t.Fatal("anchor state mutated")
	}
	checkJournalLength(t, root, 40)
	checkQuarantine(t, root, snapshot, marker)
	checkNoEntries(t, root, "snapshots")
	if _, err := os.Stat(filepath.Join(root, "pointer.bin")); !os.IsNotExist(err) {
		t.Fatalf("unexpected pointer: %v", err)
	}
}

func checkQuarantine(t *testing.T, root string, snapshot [16]byte, marker []byte) {
	t.Helper()
	candidatePath := filepath.Join(root, "candidates", fmt.Sprintf("%x.bin", snapshot))
	if _, err := os.Stat(candidatePath); !os.IsNotExist(err) {
		t.Fatalf("candidate survived burn: %v", err)
	}
	quarantinePath := filepath.Join(root, "quarantine", fmt.Sprintf("%x.bin", snapshot))
	got, err := os.ReadFile(quarantinePath)
	if err != nil || !bytes.Equal(got, marker) || sha256.Sum256(got) != sha256.Sum256(marker) {
		t.Fatalf("quarantined candidate changed: %v", err)
	}
}

func checkJournalLength(t *testing.T, root string, length int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "journal.bin"))
	if err != nil || len(data) != length {
		t.Fatalf("journal length: %d, want %d: %v", len(data), length, err)
	}
}

func checkNoEntries(t *testing.T, root, kind string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, kind))
	if err != nil || len(entries) != 0 {
		t.Fatalf("%s entries: %d, %v", kind, len(entries), err)
	}
}
