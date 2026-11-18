package snapshotstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

func mustProposedState(t *testing.T, req appstoreanchorrequest.Request) appstoreanchorstate.State {
	t.Helper()
	state, ok := req.ProposedState()
	if !ok {
		t.Fatal("commit request has no proposed state")
	}
	return state
}
func TestWriterScopedSuffixBurnAndOrphanQuarantine(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	genesis, err := writerRead(ctx, transport, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	var snapshot, transaction [16]byte
	snapshot[0], transaction[0] = 2, 3
	entry, err := appstorejournal.NewEntry(0, snapshot, transaction)
	if err != nil {
		t.Fatal(err)
	}
	entryBytes := entry.Bytes()
	if err = tx.AppendJournal(entryBytes, 0); err != nil {
		t.Fatal(err)
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := []byte{1, 2, 3}
	if _, err = candidate.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	if err = candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tx.SyncCandidate(snapshot); err != nil {
		t.Fatal(err)
	}
	state, err := writerReconcileReservations(ctx, tx, transport, genesis)
	if err != nil {
		t.Fatal(err)
	}
	if state.JournalCount() != 1 || state.Sequence() != 0 {
		t.Fatalf("burned state count=%d sequence=%d", state.JournalCount(), state.Sequence())
	}
	journal, err := tx.Journal()
	if err != nil {
		t.Fatal(err)
	}
	var got [40]byte
	if _, err = io.ReadFull(journal, got[:]); err != nil {
		t.Fatal(err)
	}
	journal.Close()
	if !bytes.Equal(got[:], entryBytes[:]) {
		t.Fatal("reservation journal entry changed")
	}
	if f, e := tx.OpenCandidate(snapshot); !errors.Is(e, appstorefile.ErrMissing) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("candidate survived quarantine: %v", e)
	}
	quarantined, err := tx.OpenNamed("quarantine", "02000000000000000000000000000000.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer quarantined.Close()
	recovered, err := io.ReadAll(quarantined)
	if err != nil || !bytes.Equal(recovered, ciphertext) {
		t.Fatalf("quarantined ciphertext: %x %v", recovered, err)
	}
	repeated, err := writerReconcileReservations(ctx, tx, transport, state)
	if err != nil || repeated.Bytes() != state.Bytes() {
		t.Fatalf("repeat changed state: %v", err)
	}
}

func TestNewSecretObjectCopiesAndCloses(t *testing.T) {
	id := [16]byte{1}
	input := []byte("secret")
	obj, closeSecret, err := NewSecretObject(id, "text/plain", input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	copyBytes, err := obj.memory.takeCopy()
	if err != nil || !bytes.Equal(copyBytes, []byte("secret")) {
		t.Fatal("secret was not copied")
	}
	clear(copyBytes)
	closeSecret()
	closeSecret()
	if _, err = obj.memory.takeCopy(); err == nil {
		t.Fatal("closed secret remained readable")
	}
}

func TestNewSecretObjectRejectsOversize(t *testing.T) {
	if _, _, err := NewSecretObject([16]byte{1}, "application/octet-stream", make([]byte, maxRAMSecretSize+1)); err == nil {
		t.Fatal("oversize secret accepted")
	}
}

func TestWriterRAMSnapshotRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, _ := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic RAM writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	payloads := [][]byte{[]byte("RAM secret"), make([]byte, 16384), make([]byte, 0)}
	for i := range payloads {
		for j := range payloads[i] {
			payloads[i][j] = byte((i+17)*29 + j%251)
		}
	}
	objects := make([]SnapshotObject, len(payloads))
	closures := make([]func(), len(payloads))
	for i, payload := range payloads {
		var id [16]byte
		id[15] = byte(i + 1)
		objects[i], closures[i], err = NewSecretObject(id, "text/plain", payload)
		if err != nil {
			t.Fatal(err)
		}
		defer closures[i]()
	}
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, present := anchor.State()
	if !present || state != commit.State || state.CommittedFileHash() != commit.EncodedHash {
		t.Fatal("committed anchor differs")
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	file, err := tx.OpenSnapshot(state.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	check, checkErr := master.CheckSnapshot(ctx, file, masterkey.ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: state.CommittedSnapshotID(), EncodedHash: state.CommittedFileHash()})
	closeErr := file.Close()
	if checkErr != nil || closeErr != nil || !check.Valid() {
		t.Fatalf("independent snapshot check: %v", checkErr)
	}
	entries := check.Catalog().Entries()
	if len(entries) != len(objects) {
		t.Fatalf("catalog count %d", len(entries))
	}
	for i, entry := range entries {
		if entry.ObjectID() != objects[i].ObjectID || entry.Length() != uint64(len(payloads[i])) {
			t.Fatalf("catalog entry %d", i)
		}
	}
	if len(commit.Refs) != len(entries) {
		t.Fatalf("commit refs: %d", len(commit.Refs))
	}
	for i, ref := range commit.Refs {
		if ref.ObjectID() != objects[i].ObjectID || ref.SnapshotID() != state.CommittedSnapshotID() || ref.VersionID() != entries[i].VersionID() {
			t.Fatalf("commit ref %d", i)
		}
	}
	encoded, err := tx.OpenSnapshot(state.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	defer encoded.Close()
	var raw [appstoreheader.Size]byte
	if _, err = io.ReadFull(encoded, raw[:]); err != nil {
		t.Fatal(err)
	}
	encodedHeader, err := appstoreheader.Parse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), raw[:]...)
	var payloadOffset uint64
	for index := uint32(0); index < encodedHeader.ChunkCount(); index++ {
		var prefix [12]byte
		if _, err = io.ReadFull(encoded, prefix[:]); err != nil {
			t.Fatal(err)
		}
		wire = append(wire, prefix[:]...)
		n := binary.BigEndian.Uint32(prefix[4:8])
		sealedN := binary.BigEndian.Uint32(prefix[8:12])
		if binary.BigEndian.Uint32(prefix[:4]) != index || sealedN != n+16000 {
			t.Fatal("record prefix")
		}
		sealed := make([]byte, sealedN)
		if _, err = io.ReadFull(encoded, sealed); err != nil {
			t.Fatal(err)
		}
		wire = append(wire, sealed...)
		plain, openErr := masterkey.OpenRecord(master, ctx, encodedHeader, index, false, sealed)
		clear(sealed)
		if openErr != nil {
			t.Fatal(openErr)
		}
		start := 0
		if index == 0 {
			start = 1 << 20
		}
		for pos := start; pos < len(plain); pos++ {
			offset := payloadOffset + uint64(pos-start)
			object := 0
			for object < len(payloads) && offset >= uint64(len(payloads[object])) {
				offset -= uint64(len(payloads[object]))
				object++
			}
			if object >= len(payloads) || plain[pos] != payloads[object][offset] {
				clear(plain)
				t.Fatal("decrypted RAM bytes differ")
			}
		}
		payloadOffset += uint64(len(plain) - start)
		if payloadOffset > encodedHeader.PlaintextSize()-appstorecatalog.Size {
			clear(plain)
			t.Fatal("decrypted payload exceeds declared plaintext")
		}
	}
	var footer [12]byte
	if _, err = io.ReadFull(encoded, footer[:]); err != nil {
		t.Fatal(err)
	}
	wire = append(wire, footer[:]...)
	final := make([]byte, binary.BigEndian.Uint64(footer[4:]))
	if _, err = io.ReadFull(encoded, final); err != nil {
		t.Fatal(err)
	}
	wire = append(wire, final...)
	if payloadOffset != uint64(len(payloads[0])+len(payloads[1])) || sha256.Sum256(wire) != commit.EncodedHash {
		t.Fatal("encoded payload length or hash oracle mismatch")
	}
}

func TestRAMWriteFirstCanceledBeforeMutationPreservesAnchor(t *testing.T) {
	transport, _, directory, h, _, _ := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	verifyCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	master, err := derive(context.Background(), h, []byte("synthetic RAM failure fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	before, err := transport.Read(verifyCtx)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, beforePresent := before.State()
	var id [16]byte
	id[15] = 31
	object, release, err := NewSecretObject(id, "text/plain", []byte("RAM cancellation test"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = writer.WriteFirst(ctx, []SnapshotObject{object}); err == nil {
		t.Fatal("canceled WriteFirst succeeded")
	}
	after, err := transport.Read(verifyCtx)
	if err != nil {
		t.Fatal(err)
	}
	afterState, afterPresent := after.State()
	if beforePresent != afterPresent || (beforePresent && beforeState != afterState) {
		t.Fatal("canceled WriteFirst changed anchor")
	}
}

func TestRAMWriteFirstClosedInputPreservesAnchor(t *testing.T) {
	transport, _, directory, h, _, _ := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	master, err := derive(ctx, h, []byte("synthetic RAM closed-input fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	before, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, beforePresent := before.State()
	var id [16]byte
	id[15] = 32
	object, release, err := NewSecretObject(id, "text/plain", []byte("closed RAM input"))
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err = writer.WriteFirst(ctx, []SnapshotObject{object}); err == nil {
		t.Fatal("WriteFirst accepted closed RAM input")
	}
	after, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	afterState, afterPresent := after.State()
	if beforePresent != afterPresent || (beforePresent && beforeState != afterState) {
		t.Fatal("closed-input rejection changed anchor")
	}
}

func TestRAMWriteFirstReaderRoleRejectsReservation(t *testing.T) {
	transport, _, directory, h, _, _ := writerFixtureWithFault(t, appstoreanchorcore.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	master, err := derive(ctx, h, []byte("synthetic RAM reader-role fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	before, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, beforePresent := before.State()
	var id [16]byte
	id[15] = 33
	object, release, err := NewSecretObject(id, "text/plain", []byte("reader must not write"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = writer.WriteFirst(ctx, []SnapshotObject{object}); err == nil {
		t.Fatal("reader role accepted WriteFirst")
	}
	after, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	afterState, afterPresent := after.State()
	if beforePresent != afterPresent || (beforePresent && beforeState != afterState) {
		t.Fatal("reader-role rejection changed anchor")
	}
}

func TestInstallationWriterEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	directory, store, binding := installationWriterFixture(t)
	password := []byte("synthetic installation writer fixture")
	encoded, err := masterkey.NewInstallationWith(ctx, binding.Header, password, binding, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Install(encoded); err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := UnlockInstallationWith(ctx, loaded, password, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	defer installation.Close()
	if err = store.VerifyUnchanged(digest); err != nil {
		t.Fatal(err)
	}
	dev, ino, err := store.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if !installation.DirectoryMatches(dev, ino) {
		t.Fatal("directory identity check")
	}
	otherPath := t.TempDir()
	if err = os.Chmod(otherPath, 0700); err != nil {
		t.Fatal(err)
	}
	otherStore, err := appstoreentry.Open(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherStore.Close()
	otherRoot, err := os.Open(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	otherDirectory, err := appstorefile.Open(otherRoot, binding.Header.StoreID())
	_ = otherRoot.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer otherDirectory.Close()
	otherDev, otherIno, err := otherStore.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if installation.DirectoryMatches(otherDev, otherIno) {
		t.Fatal("accepted different directory identity")
	}
	if _, rejectedTransport, writerErr := installation.Writer(otherDirectory); writerErr == nil || rejectedTransport != nil {
		if rejectedTransport != nil {
			_ = rejectedTransport.Close()
		}
		t.Fatalf("writer accepted different directory: transport=%v err=%v", rejectedTransport, writerErr)
	}
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	secret := []byte("synthetic acceptance secret; never runtime credentials")
	var objectID [16]byte
	objectID[15] = 9
	object, release, err := NewSecretObject(objectID, "text/plain", secret)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	commit, err := writer.WriteFirst(ctx, []SnapshotObject{object})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, ok := anchor.State()
	if !ok || state != commit.State || state.CommittedFileHash() != commit.EncodedHash {
		t.Fatal("committed state differs from independent transport read")
	}
	var secondID [16]byte
	secondID[15] = 10
	secondObject, secondRelease, err := NewSecretObject(secondID, "text/plain", []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	defer secondRelease()
	if _, err = writer.WriteFirst(ctx, []SnapshotObject{secondObject}); err != ErrWriterRejected {
		t.Fatalf("second first write: %v", err)
	}
	unchanged, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unchangedState, ok := unchanged.State()
	if !ok || unchangedState != commit.State {
		t.Fatal("rejected first write changed anchor")
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	snapshot, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	check, err := installation.CheckSnapshot(ctx, snapshot, masterkey.ExpectedSnapshot{StoreID: binding.Header.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	_ = snapshot.Close()
	if err != nil || !check.Valid() {
		t.Fatalf("check snapshot: %v", err)
	}
	entries := check.Catalog().Entries()
	if len(entries) != 1 || entries[0].ObjectID() != objectID || entries[0].Length() != uint64(len(secret)) {
		t.Fatal("catalog does not match committed secret")
	}
	encodedSnapshot, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	defer encodedSnapshot.Close()
	if _, err = encodedSnapshot.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	fullSnapshot, err := io.ReadAll(encodedSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	fullSnapshotHash := sha256.Sum256(fullSnapshot)
	if fullSnapshotHash != commit.EncodedHash || fullSnapshotHash != state.CommittedFileHash() || bytes.Contains(fullSnapshot, secret) {
		t.Fatal("snapshot hash or confidentiality check")
	}
	if _, err = encodedSnapshot.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var raw [appstoreheader.Size]byte
	if _, err = io.ReadFull(encodedSnapshot, raw[:]); err != nil {
		t.Fatal(err)
	}
	h, err := appstoreheader.Parse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	var offset uint64
	for index := uint32(0); index < h.ChunkCount(); index++ {
		var prefix [12]byte
		if _, err = io.ReadFull(encodedSnapshot, prefix[:]); err != nil {
			t.Fatal(err)
		}
		n := binary.BigEndian.Uint32(prefix[8:])
		sealed := make([]byte, n)
		if _, err = io.ReadFull(encodedSnapshot, sealed); err != nil {
			t.Fatal(err)
		}
		plain, e := masterkey.OpenRecord(installation.master, ctx, h, index, false, sealed)
		clear(sealed)
		if e != nil {
			t.Fatal(e)
		}
		start := 0
		if index == 0 {
			start = 1048576
		}
		if offset+uint64(len(plain)-start) > uint64(len(secret)) || !bytes.Equal(plain[start:], secret[offset:offset+uint64(len(plain)-start)]) {
			clear(plain)
			t.Fatal("opened record payload mismatch")
		}
		offset += uint64(len(plain) - start)
		clear(plain)
	}
	if offset != uint64(len(secret)) {
		t.Fatal("opened payload length mismatch")
	}
	if len(commit.Refs) != 1 || commit.Refs[0].StoreID() != binding.Header.StoreID() || commit.Refs[0].ObjectID() != objectID || commit.Refs[0].VersionID() != entries[0].VersionID() || commit.Refs[0].SnapshotID() != commit.State.CommittedSnapshotID() {
		t.Fatal("unexpected committed references")
	}
	placeholder, err := appstoreplaceholder.Encode(commit.Refs[0])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := appstoreplaceholder.Parse(placeholder)
	if err != nil || parsed != commit.Refs[0] {
		t.Fatalf("placeholder round-trip: %v", err)
	}
}

func TestInstallationRoundTripTamperAndClose(t *testing.T) {
	h, b := testBinding(t)
	password := []byte("installation passphrase")
	encoded, err := masterkey.NewInstallationWith(context.Background(), h, password, b, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, b.PrivateDER) {
		t.Fatal("private key leaked")
	}
	u, err := UnlockInstallationWith(context.Background(), encoded, password, installationDerive)
	if err != nil {
		t.Fatal(err)
	}
	assertBindingEqual(t, u.binding, b)
	if u.Header() != h {
		t.Fatal("header mismatch")
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if !u.master.Closed() || len(u.binding.PrivateDER) != 0 {
		t.Fatal("close retained master or private DER")
	}
	if _, err = UnlockInstallationWith(context.Background(), encoded, []byte("wrong passphrase"), installationDerive); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	for _, index := range []int{0, 8, installationMagicLength + 12, installationMagicLength + appstoreheader.Size + 16, len(encoded) - 1} {
		bad := append([]byte(nil), encoded...)
		bad[index] ^= 1
		if _, err = UnlockInstallationWith(context.Background(), bad, password, installationDerive); err == nil {
			t.Fatalf("tamper at %d accepted", index)
		}
	}
}
