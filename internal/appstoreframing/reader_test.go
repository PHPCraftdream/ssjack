package appstoreframing_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreframing"
)

type measuredReader struct {
	r                               io.Reader
	limit, calls, received, largest int
}

func (r *measuredReader) Read(p []byte) (int, error) {
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

type zeroReader struct{ calls int }

func (r *zeroReader) Read([]byte) (int, error) { r.calls++; return 0, nil }

type failingReader struct {
	data         []byte
	at, position int
}

func (r *failingReader) Read(p []byte) (int, error) {
	failure := errors.New("private reader detail must not escape")
	if r.position >= r.at {
		return 0, failure
	}
	if len(p) > r.at-r.position {
		p = p[:r.at-r.position]
	}
	n := copy(p, r.data[r.position:])
	r.position += n
	if r.position == r.at {
		return n, failure
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

type finalEOFReader struct{ data []byte }

func (r *finalEOFReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestShortReadsAndFixedReadBound(t *testing.T) {
	w := fixture(t, 1048593)
	r := &measuredReader{r: bytes.NewReader(w.data), limit: 17}
	info, err := appstoreframing.Inspect(r)
	if err != nil || info.TranscriptHash() != w.transcript || r.largest > 32768 || r.received != len(w.data) {
		t.Fatalf("short reads/fixed bound: %v, largest %d, read %d", err, r.largest, r.received)
	}
	info, err = appstoreframing.Inspect(&finalEOFReader{data: w.data})
	if err != nil || info.TranscriptHash() != w.transcript {
		t.Fatalf("full read with EOF is valid: %v", err)
	}
}

func TestOperationalErrorsReturnNoMetadata(t *testing.T) {
	w := fixture(t, 1048576)
	for _, at := range []int{1, 220, 232, w.bodies[0] + 1, w.final, w.final + 12, len(w.data)} {
		info, err := appstoreframing.Inspect(&failingReader{data: w.data, at: at})
		if !errors.Is(err, appstoreframing.ErrUnavailable) || info != (appstoreframing.Info{}) || strings.Contains(err.Error(), "private reader detail") {
			t.Fatalf("I/O error at %d leaked a result or detail: %v", at, err)
		}
	}
	reject(t, nil, appstoreframing.ErrUnavailable)
	z := &zeroReader{}
	reject(t, z, appstoreframing.ErrUnavailable)
	if z.calls != 1 {
		t.Fatal("no-progress reader was retried")
	}
	z = &zeroReader{}
	reject(t, io.MultiReader(bytes.NewReader(w.data), z), appstoreframing.ErrUnavailable)
	if z.calls != 1 {
		t.Fatal("no-progress EOF probe was retried")
	}
}

func TestHeaderRejectionAndMaximumWithoutBodyAllocation(t *testing.T) {
	b := header(t, 1048576)
	b[0] = 0
	r := &measuredReader{r: bytes.NewReader(b)}
	reject(t, r, appstoreframing.ErrInvalid)
	if r.calls != 1 || r.received != 220 {
		t.Fatal("malformed header reached body processing")
	}
	b = header(t, 1099511627776)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, 1048576)
	b = binary.BigEndian.AppendUint32(b, 1064576)
	r = &measuredReader{r: bytes.NewReader(b)}
	reject(t, r, appstoreframing.ErrInvalid)
	if r.received != 232 || r.largest > 32768 {
		t.Fatalf("maximum header requested payload-sized reads: %d", r.largest)
	}
}
