//go:build linux

package appstorewritertest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func TestOriginalIntentReplayAfterRestart(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("set SSJACK_TEST_FULL_KDF=1 for real Argon2id derivation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	f := makeCredentials(t)
	_, transportA, _ := startService(t, f)
	store := storeID()
	master := deriveMaster(t, ctx, store)
	defer master.Close()
	rootAPath := t.TempDir()
	if err := os.Chmod(rootAPath, 0700); err != nil {
		t.Fatal(err)
	}
	rootA, err := os.Open(rootAPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rootA.Close()
	directoryA, err := appstorefile.Open(rootA, store)
	if err != nil {
		t.Fatal(err)
	}
	defer directoryA.Close()
	writerA, err := appstorecrypto.NewSnapshotWriter(directoryA, transportA, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writerA.Write(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	txn := commit.State.CommittedTransactionID()
	snapshot := commit.State.CommittedSnapshotID()
	intentPathA := filepath.Join(rootAPath, "intents", hex.EncodeToString(txn[:])+".bin")
	originalIntent, err := os.ReadFile(intentPathA)
	if err != nil || len(originalIntent) != appstoreanchorrequest.IntentSize {
		t.Fatalf("original intent: %v", err)
	}
	intent, err := appstoreanchorrequest.ParseIntent(originalIntent, store)
	if err != nil {
		t.Fatal(err)
	}
	reqOriginal, ok := intent.Request()
	originalState, hasState := reqOriginal.ProposedState()
	if !ok || !hasState || originalState != commit.State {
		t.Fatal("original intent does not contain writer commit")
	}
	journalOriginal, err := os.ReadFile(filepath.Join(rootAPath, "journal.bin"))
	if err != nil || len(journalOriginal) != 40 {
		t.Fatalf("original journal: %v", err)
	}
	entry, err := appstorejournal.ParseEntry(journalOriginal, 0)
	if err != nil || entry.TransactionID() != txn {
		t.Fatalf("original journal entry: %v", err)
	}
	cipherPathA := filepath.Join(rootAPath, "snapshots", fmt.Sprintf("%x.bin", snapshot))
	ciphertext, err := os.ReadFile(cipherPathA)
	if err != nil || sha256.Sum256(ciphertext) != commit.EncodedHash {
		t.Fatalf("original ciphertext: %v", err)
	}

	_, transportB, _ := startService(t, f)
	genesisReply, err := transportB.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	genesis, ok := genesisReply.State()
	if !ok || genesis.Sequence() != 0 {
		t.Fatal("service B is not at genesis")
	}
	reservation, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	reservedReply, _, err := transportB.Submit(ctx, reservation)
	if err != nil || reservedReply.Outcome() != appstoreanchorreply.Committed {
		t.Fatalf("reserve original entry: %v", err)
	}
	confirmed, err := transportB.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reserved, ok := confirmed.State()
	wantReserved, okRequest := reservation.ProposedState()
	expectedHash, hasExpected := reqOriginal.ExpectedStateHash()
	if !ok || !okRequest || reserved != wantReserved || !hasExpected || reserved.Hash() != expectedHash || reserved.Sequence() != 0 || reserved.JournalCount() != 1 || confirmed.ServiceVersion() != 1 {
		t.Fatal("service B reservation does not match original intent")
	}

	rootBPath := t.TempDir()
	if err := os.Chmod(rootBPath, 0700); err != nil {
		t.Fatal(err)
	}
	rootB, err := os.Open(rootBPath)
	if err != nil {
		t.Fatal(err)
	}
	directoryB, err := appstorefile.Open(rootB, store)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := directoryB.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.AppendJournal(entry.Bytes(), 0); err != nil {
		t.Fatal(err)
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.SyncCandidate(snapshot); err != nil {
		t.Fatal(err)
	}
	var rawIntent [appstoreanchorrequest.IntentSize]byte
	copy(rawIntent[:], originalIntent)
	if err := tx.CreateIntent(txn, rawIntent); err != nil {
		t.Fatal(err)
	}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directoryB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rootB.Close(); err != nil {
		t.Fatal(err)
	}
	rootB, err = os.Open(rootBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rootB.Close()
	directoryB, err = appstorefile.Open(rootB, store)
	if err != nil {
		t.Fatal(err)
	}
	defer directoryB.Close()
	writerB, err := appstorecrypto.NewSnapshotWriter(directoryB, transportB, master)
	if err != nil {
		t.Fatal(err)
	}
	beforeRaw, err := os.ReadFile(filepath.Join(rootBPath, "intents", hex.EncodeToString(txn[:])+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	beforeJournal, err := os.ReadFile(filepath.Join(rootBPath, "journal.bin"))
	if err != nil {
		t.Fatal(err)
	}
	cipherPathB := filepath.Join(rootBPath, "candidates", fmt.Sprintf("%x.bin", snapshot))
	beforeCipher, err := os.ReadFile(cipherPathB)
	if err != nil {
		t.Fatal(err)
	}
	first, err := writerB.Recover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != commit.State || first.EncodedHash != commit.EncodedHash || len(first.Refs) != 0 {
		t.Fatal("replay result differs from original commit")
	}
	finalReply, err := transportB.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	final, ok := finalReply.State()
	if !ok || final.Sequence() != 1 || finalReply.ServiceVersion() != 2 || final != originalState {
		t.Fatal("replay did not commit exact original proposed state")
	}
	checkBytes := func(path string, want []byte) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("durable bytes changed: %v", err)
		}
	}
	checkBytes(filepath.Join(rootBPath, "intents", hex.EncodeToString(txn[:])+".bin"), beforeRaw)
	checkBytes(filepath.Join(rootBPath, "journal.bin"), beforeJournal)
	checkBytes(filepath.Join(rootBPath, "snapshots", fmt.Sprintf("%x.bin", snapshot)), beforeCipher)
	second, err := writerB.Recover(ctx)
	if err != nil || second.State != first.State || second.EncodedHash != first.EncodedHash {
		t.Fatalf("second recovery: %v", err)
	}
	again, err := transportB.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	againState, ok := again.State()
	if !ok || againState != final || againState.Sequence() != 1 || again.ServiceVersion() != 2 {
		t.Fatal("second recovery changed anchor state")
	}
}
