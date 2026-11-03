package driverframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, nil }

type invalidReader struct{ n int }

func (r invalidReader) Read([]byte) (int, error) { return r.n, nil }

type invalidWriter struct{ n int }

func (w invalidWriter) Write([]byte) (int, error) { return w.n, nil }

type errorWriter struct {
	n   int
	err error
}

func (w errorWriter) Write(p []byte) (int, error) { return w.n, w.err }

type sequenceReader struct {
	chunks [][]byte
	errs   []error
}

func (r *sequenceReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	chunk, err := r.chunks[0], r.errs[0]
	r.chunks, r.errs = r.chunks[1:], r.errs[1:]
	return copy(p, chunk), err
}

type pipeReader struct{ r *io.PipeReader }

func (p pipeReader) Read(b []byte) (int, error) { return p.r.Read(b) }

func TestRoundTripAndShortWrites(t *testing.T) {
	want := bytes.Repeat([]byte{0xa5}, MaxPayload)
	w := new(shortWriter)
	if err := Write(w, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(bytes.NewReader(w.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("payload mismatch")
	}
}

func TestBoundsAndIncompleteFrames(t *testing.T) {
	for _, n := range []uint32{0, MaxPayload + 1, ^uint32(0)} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if _, err := Read(bytes.NewReader(h[:])); !errors.Is(err, ErrLength) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	for _, raw := range [][]byte{{1, 2}, {0, 0, 0, 3, 1, 2}} {
		if _, err := Read(bytes.NewReader(raw)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%v", err)
		}
	}
	if err := Write(io.Discard, nil); !errors.Is(err, ErrLength) {
		t.Fatal(err)
	}
	if err := Write(io.Discard, make([]byte, MaxPayload+1)); !errors.Is(err, ErrLength) {
		t.Fatal(err)
	}
}

func TestTrailingAndDuplicateFrames(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := Write(&b, []byte("second")); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(b.Bytes())
	if got, err := Read(r); err != nil || string(got) != "first" {
		t.Fatalf("%q %v", got, err)
	}
	if err := RequireEOF(r); !errors.Is(err, ErrTrailing) {
		t.Fatal(err)
	}
	if err := RequireEOF(bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestPipeBlockingAndClosure(t *testing.T) {
	pr, pw := io.Pipe()
	want := []byte("actual pipe roundtrip")
	writeDone := make(chan error, 1)
	go func() { writeDone <- Write(pw, want); _ = pw.Close() }()
	got, err := Read(pr)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%q %v", got, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := RequireEOF(pr); err != nil {
		t.Fatal(err)
	}
}

func TestReadNoProgressAndInvalidCounts(t *testing.T) {
	for _, r := range []io.Reader{zeroReader{}, invalidReader{n: -1}, invalidReader{n: 5}} {
		_, err := Read(r)
		if r == nil || err == nil {
			t.Fatal("expected read failure")
		}
		if _, ok := r.(zeroReader); ok && !errors.Is(err, ErrNoProgress) {
			t.Fatal(err)
		}
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 1)
	for _, r := range []io.Reader{zeroReader{}, invalidReader{n: -1}, invalidReader{n: 2}} {
		_, err := Read(io.MultiReader(bytes.NewReader(header[:]), r))
		if err == nil {
			t.Fatal("expected payload read failure")
		}
		if _, ok := r.(zeroReader); ok && !errors.Is(err, ErrNoProgress) {
			t.Fatal(err)
		}
	}
}

func TestReadErrorsPreservePartialProgress(t *testing.T) {
	testErr := errors.New("read failed")
	for _, tc := range []struct {
		err  error
		want error
	}{{io.EOF, io.ErrUnexpectedEOF}, {testErr, testErr}} {
		r := &sequenceReader{chunks: [][]byte{{0, 0}, {}}, errs: []error{nil, tc.err}}
		_, err := Read(r)
		if !errors.Is(err, tc.want) {
			t.Fatalf("got %v want %v", err, tc.want)
		}
	}
}

func TestReadFullAndFrameEOFWithBytes(t *testing.T) {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], 1)
	// A complete section accompanied by EOF is complete; the frame still needs payload.
	r := &sequenceReader{chunks: [][]byte{h[:], {'x'}}, errs: []error{io.EOF, io.EOF}}
	got, err := Read(r)
	if err != nil || string(got) != "x" {
		t.Fatalf("%q %v", got, err)
	}
	// Header EOF completes the header, but no payload means an incomplete frame.
	r = &sequenceReader{chunks: [][]byte{h[:], {}}, errs: []error{io.EOF, io.EOF}}
	if _, err = Read(r); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	// A complete payload returned with EOF succeeds.
	r = &sequenceReader{chunks: [][]byte{h[:], {'y'}}, errs: []error{nil, io.EOF}}
	got, err = Read(r)
	if err != nil || string(got) != "y" {
		t.Fatalf("%q %v", got, err)
	}
	// Non-EOF error accompanying bytes is preserved after the bytes are consumed.
	boom := errors.New("partial read error")
	r = &sequenceReader{chunks: [][]byte{{0, 0, 0, 1}, {'z'}}, errs: []error{nil, boom}}
	if _, err = Read(r); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestInvalidReaderAndWriterCounts(t *testing.T) {
	if _, err := Read(invalidReader{n: 5}); err == nil {
		t.Fatal("invalid header count accepted")
	}
	for _, n := range []int{-1, 5} {
		if err := Write(invalidWriter{n: n}, []byte("x")); err == nil {
			t.Fatalf("invalid write count %d accepted", n)
		}
	}
}

func TestWriteErrorAfterPartialBytes(t *testing.T) {
	boom := errors.New("write failed")
	if err := Write(errorWriter{n: 2, err: boom}, []byte("x")); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := Write(errorWriter{n: 4, err: boom}, []byte("x")); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestSingleByteTrailing(t *testing.T) {
	if err := RequireEOF(bytes.NewReader([]byte{0x7f})); !errors.Is(err, ErrTrailing) {
		t.Fatal(err)
	}
}

func TestIncompleteHeaderEOFIsEOF(t *testing.T) {
	if _, err := Read(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestNoProgress(t *testing.T) {
	if err := Write(zeroWriter{}, []byte{1}); !errors.Is(err, ErrNoProgress) {
		t.Fatal(err)
	}
	if err := RequireEOF(zeroReader{}); !errors.Is(err, ErrNoProgress) {
		t.Fatal(err)
	}
}
