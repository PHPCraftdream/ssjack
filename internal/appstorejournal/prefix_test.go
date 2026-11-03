package appstorejournal_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func rejectPrefix(t *testing.T, expected appstoreanchorstate.State, r io.Reader, want error) {
	t.Helper()
	p, err := appstorejournal.InspectPrefix(expected, r)
	if !errors.Is(err, want) || p != (appstorejournal.Prefix{}) {
		t.Fatalf("failure exposed prefix metadata: %v", err)
	}
}

func TestExactPrefixPreservesUntrustedSuffix(t *testing.T) {
	s, b, head := chain(t)
	suffix := []byte("untrusted crash suffix")
	r := bytes.NewReader(append(append([]byte(nil), b...), suffix...))
	p, err := appstorejournal.InspectPrefix(s, r)
	if err != nil || !p.Valid() || p.StoreID() != id(1) || p.StateHash() != s.Hash() || p.Head() != head || p.Count() != 2 || p.ConsumedBytes() != 80 || r.Len() != len(suffix) {
		t.Fatalf("prefix count/head/suffix: %v", err)
	}
	remaining, _ := io.ReadAll(r)
	if !bytes.Equal(remaining, suffix) {
		t.Fatal("untrusted suffix consumed or changed")
	}
	clear(b)
	returned := p.Head()
	returned[0] ^= 1
	if p.Head() != head {
		t.Fatal("prefix aliases accessor bytes")
	}
	g, err := appstoreanchorstate.Genesis(id(1))
	if err != nil {
		t.Fatal(err)
	}
	r = bytes.NewReader(suffix)
	p, err = appstorejournal.InspectPrefix(g, r)
	if err != nil || !p.Valid() || p.Count() != 0 || p.Head() != initialHead(id(1)) || r.Len() != len(suffix) {
		t.Fatalf("genesis prefix consumed suffix: %v", err)
	}
	if (appstorejournal.Prefix{}).Valid() {
		t.Fatal("zero prefix claims admission")
	}
}

func TestPrefixOrderIntegrityAndTruncation(t *testing.T) {
	s, original, _ := chain(t)
	for name, mutate := range map[string]func([]byte){
		"first-index":        func(b []byte) { binary.BigEndian.PutUint64(b[:8], 1) },
		"duplicate-index":    func(b []byte) { binary.BigEndian.PutUint64(b[40:48], 0) },
		"skipped-index":      func(b []byte) { binary.BigEndian.PutUint64(b[40:48], 2) },
		"snapshot-zero":      func(b []byte) { clear(b[8:24]) },
		"transaction-zero":   func(b []byte) { clear(b[24:40]) },
		"snapshot-change":    func(b []byte) { b[8] ^= 1 },
		"transaction-change": func(b []byte) { b[24] ^= 1 },
		"reordered":          func(b []byte) { first := append([]byte(nil), b[:40]...); copy(b[:40], b[40:80]); copy(b[40:80], first) },
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), original...)
			mutate(b)
			rejectPrefix(t, s, bytes.NewReader(b), appstorejournal.ErrInvalid)
		})
	}
	for _, end := range []int{0, 1, 39, 40, 79} {
		rejectPrefix(t, s, bytes.NewReader(original[:end]), appstorejournal.ErrInvalid)
	}
	wrongHead := s.JournalHead()
	wrongHead[0] ^= 1
	rejectPrefix(t, state(t, id(1), 2, wrongHead), bytes.NewReader(original), appstorejournal.ErrInvalid)
	rejectPrefix(t, state(t, id(2), 2, s.JournalHead()), bytes.NewReader(original), appstorejournal.ErrInvalid)
}

type countedReader struct {
	r                               io.Reader
	limit, calls, largest, received int
}

func (r *countedReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > r.largest {
		r.largest = len(p)
	}
	if r.limit > 0 && len(p) > r.limit {
		p = p[:r.limit]
	}
	n, err := r.r.Read(p)
	r.received += n
	return n, err
}

type noProgress struct{ calls int }

func (r *noProgress) Read([]byte) (int, error) { r.calls++; return 0, nil }

type fullError struct{ data []byte }

func (r *fullError) Read(p []byte) (int, error) {
	return copy(p, r.data), errors.New("private I/O detail must not escape")
}

func TestPrefixReadBoundsAndOperationalErrors(t *testing.T) {
	s, b, head := chain(t)
	r := &countedReader{r: bytes.NewReader(b), limit: 3}
	p, err := appstorejournal.InspectPrefix(s, r)
	if err != nil || p.Head() != head || r.received != 80 || r.largest > 40 {
		t.Fatalf("short read bound: %v", err)
	}
	rejectPrefix(t, appstoreanchorstate.State{}, bytes.NewReader(b), appstorejournal.ErrInvalid)
	rejectPrefix(t, s, nil, appstorejournal.ErrUnavailable)
	z := &noProgress{}
	rejectPrefix(t, s, z, appstorejournal.ErrUnavailable)
	if z.calls != 1 {
		t.Fatal("no-progress reader retried")
	}
	p, err = appstorejournal.InspectPrefix(s, &fullError{data: b[:40]})
	if err != appstorejournal.ErrUnavailable || p != (appstorejournal.Prefix{}) {
		t.Fatal("full read plus I/O failure exposed data or raw error")
	}
	maximum := state(t, id(1), 1048576, [32]byte(bytes.Repeat([]byte{7}, 32)))
	r = &countedReader{r: bytes.NewReader(nil)}
	rejectPrefix(t, maximum, r, appstorejournal.ErrInvalid)
	if r.calls != 1 || r.largest != 40 || r.received != 0 {
		t.Fatal("maximum count caused unbounded reads before first entry")
	}
}
