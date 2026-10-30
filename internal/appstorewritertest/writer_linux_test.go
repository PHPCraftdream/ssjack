//go:build linux

package appstorewritertest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func TestSnapshotWriterFullKDF(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("set SSJACK_TEST_FULL_KDF=1 for four real 1-GiB Argon2id derivations")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	f := makeCredentials(t)
	_, transport, _ := startService(t, f)
	store := storeID()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	directory, err := appstorefile.Open(root, store)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	copy(raw[12:28], store[:])
	copy(raw[28:44], make([]byte, 16))
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
	defer master.Close()
	writer, err := appstorecrypto.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	// This is the synthetic original source input (never extracted plaintext or writer staging).
	sourcePath := filepath.Join(t.TempDir(), "synthetic-original")
	source, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2*1024*1024+17)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	if _, err := source.Write(payload); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	if _, err := source.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	commit, err := writer.Write(ctx, []appstorecrypto.SnapshotObject{{ObjectID: [16]byte{2}, MediaType: "text/plain", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	if !commit.State.Valid() || commit.State.Sequence() != 1 || len(commit.Refs) != 1 || commit.EncodedHash == ([32]byte{}) {
		t.Fatal("unexpected committed snapshot")
	}
	path := filepath.Join(rootPath, "snapshots", fmt.Sprintf("%x.bin", commit.State.CommittedSnapshotID()))
	encoded, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	check, err := master.CheckSnapshot(ctx, encoded, appstorecrypto.ExpectedSnapshot{StoreID: store, SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	closeErr := encoded.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	before := commit.State
	if !check.Valid() || !check.Catalog().Valid() || len(check.Catalog().Entries()) != 1 || check.Catalog().Entries()[0].Length() != 2*1024*1024+17 {
		t.Fatalf("snapshot verification failed")
	}
	txn := commit.State.CommittedTransactionID()
	intentPath := filepath.Join(rootPath, "intents", hex.EncodeToString(txn[:])+".bin")
	intentRaw, err := os.ReadFile(intentPath)
	if err != nil || len(intentRaw) != appstoreanchorrequest.IntentSize {
		t.Fatalf("durable intent: %v", err)
	}
	intent, err := appstoreanchorrequest.ParseIntent(intentRaw, store)
	if err != nil {
		t.Fatalf("parse durable intent: %v", err)
	}
	req, ok := intent.Request()
	proposed, present := req.ProposedState()
	if !ok || !present || proposed != commit.State || req.Operation() != 3 {
		t.Fatal("durable intent state mismatch")
	}
	gotExpected, present := req.ExpectedStateHash()
	if !present || gotExpected != [32]byte(intentRaw[24:56]) || [32]byte(intentRaw[280:312]) != commit.EncodedHash {
		t.Fatal("durable intent hash mismatch")
	}
	journalFile, err := os.Open(filepath.Join(rootPath, "journal.bin"))
	if err != nil {
		t.Fatal(err)
	}
	journal := make([]byte, 40)
	_, err = journalFile.Read(journal)
	closeErr = journalFile.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read 40-byte journal: %v %v", err, closeErr)
	}
	entry, err := appstorejournal.ParseEntry(journal, 0)
	if err != nil || entry.TransactionID() != txn || entry.SnapshotID() != commit.State.CommittedSnapshotID() {
		t.Fatal("journal entry mismatch")
	}
	original, err := os.ReadFile(path)
	if err != nil || len(original) == 0 || sha256.Sum256(original) != commit.EncodedHash {
		t.Fatalf("committed ciphertext: %v", err)
	}
	pointer, err := os.ReadFile(filepath.Join(rootPath, "pointer.bin"))
	if err != nil || len(pointer) != 64 {
		t.Fatalf("pointer: %v", err)
	}
	if err := os.Rename(path, filepath.Join(rootPath, "candidates", fmt.Sprintf("%x.bin", commit.State.CommittedSnapshotID()))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(rootPath, "pointer.bin")); err != nil {
		t.Fatal(err)
	}
	fixed, err := writer.Recover(ctx)
	if err != nil || fixed.State != before || fixed.EncodedHash != commit.EncodedHash {
		t.Fatalf("pointer recovery: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("recovery changed committed ciphertext")
	}
	pointer, err = os.ReadFile(filepath.Join(rootPath, "pointer.bin"))
	if err != nil || len(pointer) != 64 {
		t.Fatalf("recovered pointer: %v", err)
	}
	if _, err := source.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	second, err := writer.Write(ctx, []appstorecrypto.SnapshotObject{{ObjectID: [16]byte{3}, MediaType: "text/plain", Source: source}})
	if err != nil || second.State.Sequence() != 2 || second.EncodedHash == ([32]byte{}) {
		t.Fatalf("second commit: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("first committed ciphertext was not retained")
	}
	if len(second.Refs) != 1 {
		t.Fatal("second commit reference missing")
	}
	secondPath := filepath.Join(rootPath, "snapshots", fmt.Sprintf("%x.bin", second.State.CommittedSnapshotID()))
	if _, err := os.Stat(secondPath); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	badPath := secondPath
	bad, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	secondCiphertext, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatal(err)
	}
	bad[len(bad)-1] ^= 1
	if err := os.WriteFile(badPath, bad, 0600); err != nil {
		t.Fatal(err)
	}
	anchoredReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchored, _ := anchoredReply.State()
	if _, err := writer.Write(ctx, []appstorecrypto.SnapshotObject{{ObjectID: [16]byte{4}, MediaType: "text/plain", Source: source}}); err == nil {
		t.Fatal("tampered history accepted")
	}
	unchangedReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, _ := unchangedReply.State()
	if unchanged != anchored || unchanged.Sequence() != 2 {
		t.Fatal("tampering advanced anchor")
	}
	if err := os.WriteFile(badPath, secondCiphertext, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Recover(ctx); err != nil {
		t.Fatalf("recover restored seq2: %v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err := writer.Write(cancelled, []appstorecrypto.SnapshotObject{{ObjectID: [16]byte{5}, MediaType: "text/plain", Source: source}}); err == nil {
		t.Fatal("cancelled write succeeded")
	}
	finalReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	final, _ := finalReply.State()
	if final != anchored || final.Sequence() != 2 {
		t.Fatal("cancelled write advanced anchor")
	}
	recovered, err := writer.Recover(ctx)
	if err != nil || recovered.State != anchored {
		t.Fatalf("idempotent recovery: %v", err)
	}
	state, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := state.State()
	if !ok || actual != anchored || actual.Sequence() != 2 {
		t.Fatal("anchor and snapshot state disagree")
	}
}
