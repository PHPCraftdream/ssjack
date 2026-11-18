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
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/anchorfixture"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

var (
	writerFixture               = anchorfixture.WriterFixture
	writerFixtureWithCredential = anchorfixture.WriterFixtureWithCredential
	writerFixtureWithFault      = anchorfixture.WriterFixtureWithFault
)

const installationMagicLength = len("SSINST01")

func header(t *testing.T) appstoreheader.Header {
	t.Helper()
	return anchorfixture.Header(t)
}

func fake(password, salt []byte) []byte { return anchorfixture.FakeKDF(password, salt) }

func derive(ctx context.Context, h appstoreheader.Header, passphrase []byte, fn masterkey.KDF) (*masterkey.Master, error) {
	return masterkey.DeriveHeld(ctx, h, passphrase, fn)
}

func installationDerive(ctx context.Context, h appstoreheader.Header, p []byte) (*masterkey.Master, error) {
	return masterkey.DeriveWith(ctx, h, p, func(password, salt []byte) []byte {
		input := append(append([]byte(nil), password...), salt...)
		sum := sha256.Sum256(input)
		clear(input)
		return append([]byte(nil), sum[:]...)
	})
}

func installationWriterFixture(t *testing.T) (*appstorefile.Directory, *appstoreentry.Store, masterkey.Binding) {
	t.Helper()
	directory, store, parts := anchorfixture.InstallationAnchor(t)
	return directory, store, masterkey.Binding(parts)
}

func testBinding(t *testing.T) (appstoreheader.Header, masterkey.Binding) {
	t.Helper()
	h, parts := anchorfixture.TestBinding(t)
	return h, masterkey.Binding(parts)
}

func assertBindingEqual(t *testing.T, got, want masterkey.Binding) {
	t.Helper()
	if got.Endpoint != want.Endpoint || got.Header != want.Header || got.DirectoryDev != want.DirectoryDev || got.DirectoryIno != want.DirectoryIno || !bytes.Equal(got.PrivateDER, want.PrivateDER) || !bytes.Equal(got.ServiceKey, want.ServiceKey) || len(got.RootsDER) != len(want.RootsDER) || len(got.CertificateDER) != len(want.CertificateDER) {
		t.Fatal("binding fields differ")
	}
	for i := range want.RootsDER {
		if !bytes.Equal(got.RootsDER[i], want.RootsDER[i]) {
			t.Fatal("root certificate differs")
		}
	}
	for i := range want.CertificateDER {
		if !bytes.Equal(got.CertificateDER[i], want.CertificateDER[i]) {
			t.Fatal("certificate chain differs")
		}
	}
}

func TestWriterMutateReconcilesLostReplyBeforeRetry(t *testing.T) {
	transport, _, _, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	genesis, err := appstoreanchorstate.Genesis(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	var snapshotID, transactionID [16]byte
	snapshotID[0], transactionID[0] = 11, 12
	entry, err := appstorejournal.NewEntry(0, snapshotID, transactionID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	proposed, ok := request.ProposedState()
	if !ok {
		t.Fatal("reservation has no proposed state")
	}
	fault.Target = proposed
	fault.Drop.Store(true)
	fault.Armed.Store(true)
	before := fault.Accepted.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := writerMutate(ctx, transport, request, genesis)
	if err != nil {
		t.Fatalf("lost-reply reconciliation failed: %v", err)
	}
	if result != proposed {
		t.Fatal("lost-reply reconciliation returned unexpected state")
	}
	if delta := fault.Accepted.Load() - before; delta != 2 {
		t.Fatalf("accepted connections: %d, want 2", delta)
	}
	if !fault.Dropped.Load() {
		t.Fatal("service response was not dropped after durable mutation")
	}
	actual, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, present := actual.State()
	if !present || state.Sequence() != 0 || state.JournalCount() != 1 || actual.ServiceVersion() != 1 || state != proposed {
		t.Fatal("anchor does not match committed proposal")
	}
	if fault.Armed.Load() {
		t.Fatal("fault remained armed after response drop")
	}
}

func TestWriterScopedPayloadRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic scoped writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	payloads := [][]byte{make([]byte, 17), make([]byte, appstoreheader.ChunkSize+31)}
	for i := range payloads {
		for j := range payloads[i] {
			payloads[i][j] = byte((i+7)*31 + j%251)
		}
	}
	objects := make([]SnapshotObject, 2)
	for i, p := range payloads {
		f, e := os.CreateTemp(t.TempDir(), "source-")
		if e != nil {
			t.Fatal(e)
		}
		if e = f.Chmod(0600); e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(p); e != nil {
			t.Fatal(e)
		}
		if _, e = f.Seek(0, io.SeekStart); e != nil {
			t.Fatal(e)
		}
		var id [16]byte
		id[15] = byte(i + 1)
		objects[i] = SnapshotObject{ObjectID: id, MediaType: "text/plain", Source: f}
		defer f.Close()
	}
	w, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := w.Write(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	if commit.State.Sequence() != 1 {
		t.Fatalf("sequence: %d", commit.State.Sequence())
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	stateReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchor, present := stateReply.State()
	if !present || anchor != commit.State {
		t.Fatal("anchor differs from commit")
	}
	f, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	check, err := master.CheckSnapshot(ctx, f, masterkey.ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	closeErr := f.Close()
	if err != nil || closeErr != nil || !check.Valid() {
		t.Fatalf("snapshot check: %v", err)
	}
	entries := check.Catalog().Entries()
	if len(entries) != 2 {
		t.Fatalf("catalog entries: %d", len(entries))
	}
	for i, ent := range entries {
		if ent.ObjectID() != objects[i].ObjectID || ent.Length() != uint64(len(payloads[i])) {
			t.Fatalf("catalog entry %d", i)
		}
	}
	if len(commit.Refs) != 2 {
		t.Fatalf("refs: %d", len(commit.Refs))
	}
	for i, ref := range commit.Refs {
		if ref.ObjectID() != objects[i].ObjectID {
			t.Fatalf("ref %d", i)
		}
	}
	encoded, err := tx.OpenSnapshot(commit.State.CommittedSnapshotID())
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
	var payloadOffset uint64
	for index := uint32(0); index < encodedHeader.ChunkCount(); index++ {
		var prefix [12]byte
		if _, err = io.ReadFull(encoded, prefix[:]); err != nil {
			t.Fatal(err)
		}
		gotIndex, n, sealedN := binary.BigEndian.Uint32(prefix[:4]), binary.BigEndian.Uint32(prefix[4:8]), binary.BigEndian.Uint32(prefix[8:])
		if gotIndex != index || sealedN != n+16000 {
			t.Fatal("encoded record prefix")
		}
		sealed := make([]byte, sealedN)
		if _, err = io.ReadFull(encoded, sealed); err != nil {
			t.Fatal(err)
		}
		plain, e := masterkey.OpenRecord(master, ctx, encodedHeader, index, false, sealed)
		clear(sealed)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(plain)
		start := uint64(0)
		if index == 0 {
			start = 1048576
		}
		for pos := start; pos < uint64(len(plain)); pos++ {
			global := payloadOffset + pos - start
			var source int
			var local uint64
			if global < uint64(len(payloads[0])) {
				source, local = 0, global
			} else {
				source, local = 1, global-uint64(len(payloads[0]))
			}
			if global >= uint64(len(payloads[0])+len(payloads[1])) || plain[pos] != payloads[source][local] {
				t.Fatal("decoded payload differs")
			}
		}
		payloadOffset += uint64(len(plain)) - start
	}
	if payloadOffset != uint64(len(payloads[0])+len(payloads[1])) {
		t.Fatal("payload length")
	}
}

func TestWriterScopedRejectedTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Reader)
	master, err := derive(ctx, h, []byte("synthetic rejected writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	w, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(ctx, nil); !errors.Is(err, ErrWriterRejected) {
		t.Fatalf("rejection: %v", err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	anchorReply, err := transport.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, present := anchorReply.State()
	if !present {
		t.Fatal("anchor state is absent")
	}
	if state.Sequence() != 0 {
		t.Fatalf("anchor sequence: %d", state.Sequence())
	}
	journal, err := tx.Journal()
	if err != nil {
		t.Fatal(err)
	}
	journalStat, err := appstorefile.Stat(journal)
	closeErr := journal.Close()
	if err != nil || closeErr != nil || journalStat.Size != 40 {
		t.Fatalf("journal size: %d, %v", journalStat.Size, err)
	}
}

func TestWriterScopedCanceledAndBusy(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelCtx()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic cancel writer fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	w, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = w.Write(cancelled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(ctx, nil); !errors.Is(err, masterkey.ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	if _, err = w.Recover(ctx); !errors.Is(err, masterkey.ErrBusy) {
		t.Fatalf("recovery busy: %v", err)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriterScopedRejectedRequestCollision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, backend, _, h, credentialID := writerFixtureWithCredential(t, appstoreanchorcore.Writer)
	genesis, err := writerRead(ctx, transport, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot, transaction [16]byte
	snapshot[0], transaction[0] = 8, 9
	entry, err := appstorejournal.NewEntry(0, snapshot, transaction)
	if err != nil {
		t.Fatal(err)
	}
	request, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	raw := request.Bytes()
	copy(raw[48:80], bytes.Repeat([]byte{0x77}, 32))
	collision, err := appstoreanchorcore.Parse(raw, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := appstoreanchorcore.NewGrant(h.StoreID(), credentialID, appstoreanchorcore.Writer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.Execute(collision, grant)
	if err != nil || result.Outcome() != appstoreanchorreply.Conflict {
		t.Fatalf("seed request-ID collision: outcome %v, error %v", result.Outcome(), err)
	}
	if _, err = writerMutate(ctx, transport, request, genesis); !errors.Is(err, ErrWriterRejected) {
		t.Fatalf("rejected request collision was not terminal: %v", err)
	}
	after, err := writerRead(ctx, transport, h.StoreID())
	if err != nil || after.Bytes() != genesis.Bytes() {
		t.Fatalf("rejected request changed anchor state: %v", err)
	}
}

func TestWriterScopedIntentRestartReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic scoped restart fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	anchor, err := writerRead(ctx, transport, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot, transaction [16]byte
	snapshot[0], transaction[0] = 9, 10
	entry, err := appstorejournal.NewEntry(anchor.JournalCount(), snapshot, transaction)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := appstoreanchorrequest.PlanReservation(anchor, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.AppendJournal(entry.Bytes(), anchor.JournalCount()); err != nil {
		t.Fatal(err)
	}
	reserved, err := writerMutate(ctx, transport, reserve, anchor)
	if err != nil {
		t.Fatal(err)
	}

	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	store := h.StoreID()
	copy(raw[12:28], store[:])
	copy(raw[28:44], snapshot[:])
	parent := anchor.CommittedSnapshotID()
	copy(raw[44:60], parent[:])
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], appstorecatalog.Size)
	binary.BigEndian.PutUint32(raw[72:76], 1)
	_, salts, _ := masterkey.Context(master)
	for i := range salts {
		copy(raw[80+i*32:112+i*32], salts[i][:])
	}
	raw[208] = 1
	header, err := appstoreheader.Parse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sealHash, err := sealWriterSnapshot(master, ctx, header, nil, candidate)
	closeErr := candidate.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("test-only snapshot seal: %v %v", err, closeErr)
	}
	if err = tx.SyncCandidate(snapshot); err != nil {
		t.Fatal(err)
	}
	pinned, err := tx.OpenCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	check, checkErr := masterkey.CheckSnapshotHeld(master, ctx, pinned, masterkey.ExpectedSnapshot{StoreID: store, SnapshotID: snapshot, EncodedHash: sealHash})
	closeErr = pinned.Close()
	if checkErr != nil || closeErr != nil || !check.Valid() || len(check.Catalog().Entries()) != 0 {
		t.Fatalf("test-only candidate verification: %v %v", checkErr, closeErr)
	}
	commitRequest, err := appstoreanchorrequest.PlanCommit(reserve, sealHash)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := appstoreanchorrequest.NewIntent(commitRequest)
	if err != nil {
		t.Fatal(err)
	}
	intentBytes := intent.Bytes()
	if err = tx.CreateIntent(transaction, intentBytes); err != nil {
		t.Fatal(err)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh writer state/master models process restart; retain real directory and TLS fixture.
	restartedMaster, err := derive(ctx, h, []byte("synthetic scoped restart fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedMaster.Close()
	restarted, err := NewSnapshotWriter(directory, transport, restartedMaster)
	if err != nil {
		t.Fatal(err)
	}
	first, err := restarted.Recover(ctx)
	if err != nil || first.State.Bytes() != mustProposedState(t, commitRequest).Bytes() {
		t.Fatalf("intent replay: %v", err)
	}
	if first.EncodedHash != sealHash {
		t.Fatal("replay changed candidate ciphertext hash")
	}
	tx, err = directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	gotIntent, err := tx.LoadIntent(transaction)
	if err != nil || !bytes.Equal(gotIntent[:], intentBytes[:]) {
		t.Fatalf("intent bytes changed: %v", err)
	}
	journal, err := tx.Journal()
	if err != nil {
		t.Fatal(err)
	}
	journalStat, err := appstorefile.Stat(journal)
	_ = journal.Close()
	if err != nil || journalStat.Size != appstorejournal.Size {
		t.Fatalf("journal appended during replay: size=%d err=%v", journalStat.Size, err)
	}
	_ = tx.Close()
	second, err := restarted.Recover(ctx)
	if err != nil || second.State.Bytes() != first.State.Bytes() {
		t.Fatalf("repeat recovery: %v", err)
	}
	if reserved.Sequence() != 0 || first.State.Sequence() != 1 || second.State.Sequence() != 1 {
		t.Fatalf("replayed state sequence: reserved=%d first=%d second=%d", reserved.Sequence(), first.State.Sequence(), second.State.Sequence())
	}
}

func TestWriterScopedSourceRevisionFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic scoped source revision"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	anchor, err := writerRead(ctx, transport, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot, transaction [16]byte
	snapshot[0], transaction[0] = 9, 11
	entry, err := appstorejournal.NewEntry(0, snapshot, transaction)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := appstoreanchorrequest.PlanReservation(anchor, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.AppendJournal(entry.Bytes(), 0); err != nil {
		t.Fatal(err)
	}
	reserved, err := writerMutate(ctx, transport, reserve, anchor)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.CreateTemp(t.TempDir(), "synthetic-source-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = source.Write([]byte("original synthetic")); err != nil {
		t.Fatal(err)
	}
	prepared, total, err := prepareWriterObjects(ctx, []SnapshotObject{{ObjectID: [16]byte{1}, Source: source, MediaType: "bin"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.WriteAt([]byte("!"), int64(len("original synthetic"))); err != nil {
		t.Fatal(err)
	}
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	store := h.StoreID()
	copy(raw[12:28], store[:])
	copy(raw[28:44], snapshot[:])
	parent := anchor.CommittedSnapshotID()
	copy(raw[44:60], parent[:])
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], total)
	binary.BigEndian.PutUint32(raw[72:76], 2)
	_, salts, _ := masterkey.Context(master)
	for i := range salts {
		copy(raw[80+i*32:112+i*32], salts[i][:])
	}
	raw[208] = 1
	header, err := appstoreheader.Parse(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	_, sealErr := sealWriterSnapshot(master, ctx, header, prepared, candidate)
	closeErr := candidate.Close()
	if !errors.Is(sealErr, masterkey.ErrRecord) || closeErr != nil {
		t.Fatalf("revision mismatch: %v %v", sealErr, closeErr)
	}
	if err = tx.SyncCandidate(snapshot); err != nil {
		t.Fatal(err)
	}
	reopened, err := tx.OpenCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := appstorefile.Stat(reopened)
	closeErr = reopened.Close()
	if err != nil || closeErr != nil || rev.Size != 0 {
		t.Fatalf("candidate not empty: %+v %v %v", rev, err, closeErr)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Recover(ctx); !errors.Is(err, ErrWriterBurned) {
		t.Fatalf("recover burned reservation: %v", err)
	}
	state, err := writerRead(ctx, transport, h.StoreID())
	if err != nil || state.Sequence() != 0 || state.JournalCount() != 1 || reserved.Sequence() != 0 {
		t.Fatalf("unexpected anchor state: %v", err)
	}
}

func TestWriterScopedCanceledReservationBurned(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic scoped cancellation"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	anchor, err := writerRead(ctx, transport, h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot, transaction [16]byte
	snapshot[0], transaction[0] = 7, 12
	entry, err := appstorejournal.NewEntry(0, snapshot, transaction)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := appstoreanchorrequest.PlanReservation(anchor, entry)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.AppendJournal(entry.Bytes(), 0); err != nil {
		t.Fatal(err)
	}
	reserved, err := writerMutate(ctx, transport, reserve, anchor)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := []byte("synthetic partial ciphertext")
	if _, err = candidate.Write(ciphertext); err != nil {
		t.Fatal(err)
	}
	if err = candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tx.SyncCandidate(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = tx.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, err = writer.Recover(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recovery: %v", err)
	}
	if _, err = writer.Recover(ctx); !errors.Is(err, ErrWriterBurned) {
		t.Fatalf("fresh recovery: %v", err)
	}
	state, err := writerRead(ctx, transport, h.StoreID())
	if err != nil || state.Sequence() != 0 || state.JournalCount() != 1 || reserved.Sequence() != 0 {
		t.Fatalf("anchor changed: %v", err)
	}
	quarantine, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer quarantine.Close()
	f, err := quarantine.OpenNamed("quarantine", "07000000000000000000000000000000.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("quarantine content mismatch: %v", err)
	}
}
