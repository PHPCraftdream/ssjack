package appstorecrypto

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

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
