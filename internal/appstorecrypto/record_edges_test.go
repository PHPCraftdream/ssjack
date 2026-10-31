package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
)

func nativeConsumerFixture(t *testing.T) (string, [32]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exact-reference-consumer")
	command := exec.Command("go", "build", "-o", path, "../appstoresink/testdata/consumer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic consumer: %v\n%s", err, output)
	}
	program, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, sha256.Sum256(program)
}
func boundNativeConsumer(t *testing.T, path string, artifact [32]byte, reference appstoreref.Ref, encoded [32]byte) *appstoresink.Consumer {
	t.Helper()
	program, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := appstoresink.New(appstoresink.Config{Program: program, Binding: appstoresink.Binding{Reference: reference, EncodedHash: encoded, ArtifactHash: artifact, Target: [32]byte{3}, Revision: [32]byte{4}, Purpose: [32]byte{5}, ExpiresAt: time.Now().Add(time.Hour)}})
	_ = program.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })
	return consumer
}
func TestPrivateCurrentReferenceToFixedNativeConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	path, artifact := nativeConsumerFixture(t)
	master, err := derive(ctx, h, []byte("synthetic current delivery"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	objects := make([]SnapshotObject, 2)
	for index, length := range []int{17, appstoreheader.ChunkSize + 19} {
		source, err := os.CreateTemp(t.TempDir(), "synthetic-input-")
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		payload := make([]byte, length)
		for offset := range payload {
			if index == 0 {
				payload[offset] = 0x99
			} else {
				payload[offset] = byte(offset % 251)
			}
		}
		if _, err = source.Write(payload); err != nil {
			t.Fatal(err)
		}
		clear(payload)
		objects[index] = SnapshotObject{ObjectID: [16]byte{byte(index + 1)}, MediaType: "bin", Source: source}
	}
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, objects)
	if err != nil {
		t.Fatal(err)
	}
	if len(commit.Refs) != 2 {
		t.Fatal("missing exact references")
	}
	selected := commit.Refs[1]
	consumer := boundNativeConsumer(t, path, artifact, selected, commit.EncodedHash)
	placeholder, err := appstoreplaceholder.Encode(selected)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := appstoreplaceholder.Parse(placeholder)
	if err != nil || requested != selected {
		t.Fatalf("placeholder identity: %v", err)
	}
	otherPlaceholder, err := appstoreplaceholder.Encode(commit.Refs[0])
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := appstoreplaceholder.Parse(otherPlaceholder)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := master.deliverCurrent(ctx, directory, fault.reader, otherRequest, consumer)
	if !errors.Is(err, appstoresink.ErrDenied) || denied.MayHaveDelivered || denied.Complete {
		t.Fatalf("placeholder escaped fixed binding: %+v %v", denied, err)
	}
	result, err := master.deliverCurrent(ctx, directory, fault.reader, requested, consumer)
	if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != appstoreheader.ChunkSize+19 {
		t.Fatalf("exact native receipt: %+v %v", result, err)
	}
	wrongVersion := selected.VersionID()
	wrongVersion[0] ^= 1
	if wrongVersion == ([16]byte{}) {
		wrongVersion[1] = 1
	}
	wrong, err := appstoreref.New(selected.StoreID(), selected.ObjectID(), wrongVersion, selected.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	wrongConsumer := boundNativeConsumer(t, path, artifact, wrong, commit.EncodedHash)
	result, err = master.deliverCurrent(ctx, directory, fault.reader, wrong, wrongConsumer)
	if !errors.Is(err, appstoreref.ErrNotFound) || result.MayHaveDelivered || result.Complete {
		t.Fatalf("wrong version released: %+v %v", result, err)
	}
	if _, err := writer.Write(ctx, nil); err != nil {
		t.Fatal(err)
	}
	historical := boundNativeConsumer(t, path, artifact, selected, commit.EncodedHash)
	result, err = master.deliverCurrent(ctx, directory, fault.reader, selected, historical)
	if err == nil || result.MayHaveDelivered || result.Complete {
		t.Fatalf("historical reference substituted current: %+v %v", result, err)
	}
}

func TestSecondPassTagFailureStopsBeforeAffectedChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	path, artifact := nativeConsumerFixture(t)
	master, err := derive(ctx, h, []byte("synthetic partial handoff"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	source, err := os.CreateTemp(t.TempDir(), "synthetic-partial-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	payload := make([]byte, appstoreheader.ChunkSize+19)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := source.Write(payload); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, []SnapshotObject{{ObjectID: [16]byte{1}, MediaType: "bin", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	release, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	pinned, err := master.pinSnapshot(ctx, tx, ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash})
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	entry, err := appstoreref.FindMetadata(commit.Refs[0], pinned.state.checked.Catalog())
	if err != nil {
		t.Fatal(err)
	}
	consumer := boundNativeConsumer(t, path, artifact, commit.Refs[0], commit.EncodedHash)
	session, err := consumer.Begin(ctx, commit.Refs[0], commit.EncodedHash, entry.Length())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := pinned.recheck(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate a change after preflight, independently of the immutable-spool assumption.
	offset := int64(appstoreheader.Size + 2*(12+appstoreheader.ChunkSize+16000) + 12)
	var corrupt [1]byte
	if _, err := pinned.state.file.ReadAt(corrupt[:], offset); err != nil {
		t.Fatal(err)
	}
	corrupt[0] ^= 1
	if _, err := pinned.state.file.WriteAt(corrupt[:], offset); err != nil {
		t.Fatal(err)
	}
	result, err := master.streamPinnedObject(ctx, pinned, entry, session)
	if !errors.Is(err, ErrAuthentication) || result.Complete || !result.MayHaveDelivered || result.Bytes != appstoreheader.ChunkSize {
		t.Fatalf("partial chunk boundary: %+v %v", result, err)
	}
}

func TestPinnedSnapshotPrivateCiphertextAndSharedClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic pinned snapshot"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	release, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	expected := ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash}
	pinned, err := master.pinSnapshot(ctx, tx, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	if !pinned.state.checked.Valid() {
		t.Fatal("missing complete verification")
	}
	if _, err := appstorefile.StatTemporary(pinned.state.file); err != nil {
		t.Fatal(err)
	}
	if _, err := appstorefile.Stat(pinned.state.file); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatalf("spool must be anonymous: %v", err)
	}
	original, err := tx.OpenSnapshot(expected.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	mutable, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", original.Fd()), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mutable.WriteAt([]byte{0x7f}, 0); err != nil {
		t.Fatal(err)
	}
	if err = mutable.Close(); err != nil {
		t.Fatal(err)
	}
	if err = pinned.recheck(ctx); err != nil {
		t.Fatalf("source mutation affected private spool: %v", err)
	}
	if other, err := master.pinSnapshot(ctx, tx, expected); err == nil {
		_ = other.close()
		t.Fatal("changed source was accepted")
	}
	alias := *pinned
	if err = pinned.close(); err != nil {
		t.Fatal(err)
	}
	if err = alias.recheck(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("copied handle after close: %v", err)
	}
	if err = alias.close(); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedSnapshotHashCheckBeyondRevision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h := writerFixture(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic pinned hash"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	writer, err := NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	release, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	expected := ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: commit.State.CommittedSnapshotID(), EncodedHash: commit.EncodedHash}
	pinned, err := master.pinSnapshot(ctx, tx, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	if _, err = pinned.state.file.WriteAt([]byte{0x7f}, 0); err != nil {
		t.Fatal(err)
	}
	// Remove the revision mismatch so this assertion independently requires the full hash.
	pinned.state.revision, err = appstorefile.StatTemporary(pinned.state.file)
	if err != nil {
		t.Fatal(err)
	}
	if err = pinned.recheck(ctx); !errors.Is(err, ErrSnapshot) {
		t.Fatalf("changed spool hash accepted: %v", err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err = pinned.recheck(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recheck: %v", err)
	}
}

func TestRecordAdmissionClosedBusyAndScope(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic record-admission fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	plain := finalRecord(h)
	for _, row := range []struct {
		ctx   context.Context
		h     appstoreheader.Header
		index uint32
		final bool
		data  []byte
	}{
		{nil, h, ^uint32(0), true, plain},
		{context.Background(), appstoreheader.Header{}, ^uint32(0), true, plain},
		{context.Background(), h, 0, true, plain},
		{context.Background(), h, ^uint32(0), false, plain},
		{context.Background(), h, 1, false, plain},
		{context.Background(), h, ^uint32(0), true, plain[:47]},
		{context.Background(), h, ^uint32(0), true, append(append([]byte(nil), plain...), 0)},
	} {
		out, err := m.sealRecord(row.ctx, row.h, row.index, row.final, row.data)
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatalf("invalid record context admitted: %v", err)
		}
	}
	for _, size := range []int{16047, 16049} {
		out, err := m.openRecord(context.Background(), h, ^uint32(0), true, make([]byte, size))
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatal("wrong ciphertext size admitted")
		}
	}
	for _, offset := range []int{12, 80} {
		raw := h.Bytes()
		raw[offset] ^= 0x80
		other, err := appstoreheader.Parse(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		out, err := m.sealRecord(context.Background(), other, ^uint32(0), true, plain)
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatal("foreign master context admitted")
		}
	}
	m.state.mu.Lock()
	out, err := m.sealRecord(context.Background(), h, ^uint32(0), true, plain)
	m.state.mu.Unlock()
	if !errors.Is(err, ErrBusy) || out != nil {
		t.Fatal("busy master admitted another record")
	}
	m.Close()
	for _, closed := range []*Master{nil, {}, m} {
		out, err := closed.sealRecord(context.Background(), h, ^uint32(0), true, plain)
		if !errors.Is(err, ErrClosed) || out != nil {
			t.Fatal("closed/zero master encrypted")
		}
	}
}

func TestRecordCancellationAndFinalFields(t *testing.T) {
	h := header(t)
	m, err := derive(context.Background(), h, []byte("synthetic cancelled-record fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	plain := finalRecord(h)
	for _, offset := range []int{0, 4, 12} {
		bad := append([]byte(nil), plain...)
		bad[offset] ^= 1
		out, err := m.sealRecord(context.Background(), h, ^uint32(0), true, bad)
		if !errors.Is(err, ErrRecord) || out != nil {
			t.Fatal("invalid final fields encrypted")
		}
	}
	ciphertext := oracleSeal(t, m.state.key, h, ^uint32(0), true, 48, 0, plain)
	for _, sealing := range []bool{true, false} {
		input := plain
		if !sealing {
			input = ciphertext
		}
		before := append([]byte(nil), input...)
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		out, err := m.transformRecord(ctx, h, ^uint32(0), true, input, sealing, func(uint32) {
			calls++
			if m.state.mu.TryLock() {
				m.state.mu.Unlock()
				t.Error("record did not protect owned key")
			}
			cancel()
		})
		cancel()
		if !errors.Is(err, context.Canceled) || out != nil || calls != 1 || !bytes.Equal(input, before) {
			t.Fatal("cancellation published partial bytes or changed caller input")
		}
		ctx, cancel = context.WithCancel(context.Background())
		cancel()
		out, err = m.transformRecord(ctx, h, ^uint32(0), true, input, sealing, nil)
		if !errors.Is(err, context.Canceled) || out != nil {
			t.Fatal("already cancelled record started")
		}
	}
	for _, position := range []int{0, len(ciphertext) - 1} {
		bad := append([]byte(nil), ciphertext...)
		bad[position] ^= 1
		out, err := m.openRecord(context.Background(), h, ^uint32(0), true, bad)
		if !errors.Is(err, ErrAuthentication) || out != nil {
			t.Fatal("outer ciphertext tampering admitted")
		}
	}
	clear(ciphertext)
}

type snapshotReads struct {
	reader  *bytes.Reader
	largest int
}

func (r *snapshotReads) Read(p []byte) (int, error) {
	if len(p) > r.largest {
		r.largest = len(p)
	}
	return r.reader.Read(p)
}

type snapshotFailure struct{ header [220]byte }

func (r snapshotFailure) Read(p []byte) (int, error) {
	return copy(p, r.header[:]), errors.New("private read error must not escape")
}

func noSnapshot(t *testing.T, out SnapshotCheck, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || out.Valid() || out.Header().Valid() || out.Catalog().Valid() || out.EncodedHash() != ([32]byte{}) {
		t.Fatalf("invalid snapshot exposed metadata: %v", err)
	}
}

func TestWholeSnapshotPhaseOneMetadata(t *testing.T) {
	h := recordHeader(t, 1048579)
	m, err := derive(context.Background(), h, []byte("synthetic snapshot fixture"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	wire, expected := snapshotWire(t, m, h, false, false)
	r := &snapshotReads{reader: bytes.NewReader(wire)}
	checked, err := m.CheckSnapshot(context.Background(), r, expected)
	if err != nil || !checked.Valid() || checked.EncodedHash() != expected.EncodedHash || checked.Header().SnapshotID() != expected.SnapshotID || r.largest > 32768 {
		t.Fatalf("phase-one metadata/read bound: %v", err)
	}
	entries := checked.Catalog().Entries()
	if len(entries) != 1 || entries[0].ObjectID()[0] != 3 || entries[0].VersionID()[0] != 4 || entries[0].Length() != 3 || entries[0].MediaType() != "bin" {
		t.Fatal("verified catalog/spans not preserved after plaintext cleanup")
	}
	clear(wire)
	if checked.Catalog().Entries()[0].MediaType() != "bin" || checked.Header().StoreID() != expected.StoreID {
		t.Fatal("snapshot metadata aliases input")
	}
}

func TestWholeSnapshotFailuresReleaseNothing(t *testing.T) {
	h := recordHeader(t, 1048579)
	m, err := derive(context.Background(), h, []byte("synthetic snapshot failures"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	wire, expected := snapshotWire(t, m, h, false, false)
	for _, offset := range []int{0, 12, 28, 232} {
		bad := append([]byte(nil), wire...)
		bad[offset] ^= 1
		want := ErrSnapshot
		if offset == 232 {
			want = ErrAuthentication
		}
		out, err := m.CheckSnapshot(context.Background(), bytes.NewReader(bad), expected)
		noSnapshot(t, out, err, want)
	}
	for _, bad := range [][]byte{wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		out, err := m.CheckSnapshot(context.Background(), bytes.NewReader(bad), expected)
		noSnapshot(t, out, err, ErrSnapshot)
	}
	wrong := expected
	wrong.EncodedHash[0] ^= 1
	out, err := m.CheckSnapshot(context.Background(), bytes.NewReader(wire), wrong)
	noSnapshot(t, out, err, ErrSnapshot)
	wrong = expected
	wrong.EncodedHash = [32]byte{}
	out, err = m.CheckSnapshot(context.Background(), bytes.NewReader(wire), wrong)
	noSnapshot(t, out, err, ErrSnapshot)
	out, err = m.CheckSnapshot(context.Background(), nil, expected)
	noSnapshot(t, out, err, ErrSnapshotRead)
	out, err = m.CheckSnapshot(context.Background(), snapshotFailure{header: h.Bytes()}, expected)
	noSnapshot(t, out, err, ErrSnapshotRead)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err = m.CheckSnapshot(ctx, bytes.NewReader(wire), expected)
	noSnapshot(t, out, err, context.Canceled)
	wrongMaster, err := derive(context.Background(), h, []byte("different synthetic snapshot passphrase"), fake)
	if err != nil {
		t.Fatal(err)
	}
	out, err = wrongMaster.CheckSnapshot(context.Background(), bytes.NewReader(wire), expected)
	wrongMaster.Close()
	noSnapshot(t, out, err, ErrAuthentication)
	for _, variant := range [][2]bool{{true, false}, {false, true}} {
		bad, pinned := snapshotWire(t, m, h, variant[0], variant[1])
		out, err := m.CheckSnapshot(context.Background(), bytes.NewReader(bad), pinned)
		noSnapshot(t, out, err, ErrSnapshot)
		clear(bad)
	}
	m.Close()
	out, err = m.CheckSnapshot(context.Background(), bytes.NewReader(wire), expected)
	noSnapshot(t, out, err, ErrClosed)
	clear(wire)
}

func TestDerivationOperationBudgetBeforeKDFAndAfterCancel(t *testing.T) {
	h := header(t)
	held, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	calls := 0
	m, err := deriveAdmitted(context.Background(), h, []byte("synthetic budget fixture"), func(p, salt []byte) []byte { calls++; return fake(p, salt) })
	held()
	if !errors.Is(err, ErrBusy) || m != nil || calls != 0 {
		t.Fatal("denied derivation reached KDF")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, err = deriveAdmitted(ctx, h, []byte("synthetic budget fixture"), func(p, salt []byte) []byte {
		calls++
		cancel()
		release, err := appstorebudget.TryAcquire(h.StoreID())
		if release != nil {
			release()
		}
		if !errors.Is(err, appstorebudget.ErrBusy) {
			t.Error("cancel revoked a still-running operation")
		}
		return fake(p, salt)
	})
	if !errors.Is(err, context.Canceled) || m != nil || calls != 1 {
		t.Fatal("cancelled derivation published a master")
	}
	available, err := appstorebudget.TryAcquire(h.StoreID())
	if err != nil {
		t.Fatal("cancelled derivation leaked operation budget")
	}
	available()
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
	master.state.mu.Lock()
	salts := master.state.salts
	master.state.mu.Unlock()
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
	sealHash, err := master.sealWriterSnapshot(ctx, header, nil, candidate)
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
	check, checkErr := master.checkSnapshot(ctx, pinned, ExpectedSnapshot{StoreID: store, SnapshotID: snapshot, EncodedHash: sealHash})
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
	master.state.mu.Lock()
	salts := master.state.salts
	master.state.mu.Unlock()
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
	_, sealErr := master.sealWriterSnapshot(ctx, header, prepared, candidate)
	closeErr := candidate.Close()
	if !errors.Is(sealErr, ErrRecord) || closeErr != nil {
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
	check, checkErr := master.CheckSnapshot(ctx, file, ExpectedSnapshot{StoreID: h.StoreID(), SnapshotID: state.CommittedSnapshotID(), EncodedHash: state.CommittedFileHash()})
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
		plain, openErr := master.openRecord(ctx, encodedHeader, index, false, sealed)
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
