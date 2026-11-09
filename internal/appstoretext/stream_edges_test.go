package appstoretext

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"
)

type streamReadFunc func([]byte) (int, error)

func (f streamReadFunc) Read(p []byte) (int, error) { return f(p) }

type streamWriteFunc func([]byte) (int, error)

func (f streamWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestStreamIOAndCancellation(t *testing.T) {
	mappings := []Mapping{{Reference: fixture(t, 1), Value: []byte("secret")}}
	limits := StreamLimits{Input: MaxText, Output: MaxText}
	failure := errors.New("synthetic I/O failure")
	for _, writer := range []io.Writer{
		streamWriteFunc(func([]byte) (int, error) { return 0, nil }),
		streamWriteFunc(func([]byte) (int, error) { return 0, failure }),
	} {
		err := ReplaceStream(context.Background(), bytes.NewReader([]byte("text")), writer, mappings, false, limits)
		if !errors.Is(err, failure) && !errors.Is(err, io.ErrShortWrite) {
			t.Fatal("failed stream writer was reported as complete")
		}
	}
	for _, reader := range []io.Reader{
		streamReadFunc(func([]byte) (int, error) { return 0, failure }),
		streamReadFunc(func([]byte) (int, error) { return 0, nil }),
		streamReadFunc(func(p []byte) (int, error) { return len(p) + 1, nil }),
	} {
		var output bytes.Buffer
		err := ReplaceStream(context.Background(), reader, &output, mappings, false, limits)
		if err == nil || output.Len() != 0 {
			t.Fatal("invalid stream reader was reported as complete")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader := &chunkReader{data: []byte("text"), step: 1}
	cancel()
	if err := ReplaceStream(ctx, reader, io.Discard, mappings, false, limits); !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatal("cancelled stream read input")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	writer := streamWriteFunc(func(p []byte) (int, error) { cancel(); return len(p), nil })
	if err := ReplaceStream(ctx, bytes.NewReader([]byte("text")), writer, mappings, false, limits); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation during final write was reported as success")
	}
}

func TestStreamValidatesBeforeIO(t *testing.T) {
	r := fixture(t, 1)
	valid := []Mapping{{Reference: r, Value: []byte("secret")}}
	for _, mappings := range [][]Mapping{
		nil,
		{{Reference: r, Value: nil}},
		{{Reference: r, Value: []byte("$ssjack")}},
		{valid[0], valid[0]},
		{{Reference: r, Value: bytes.Repeat([]byte("a"), MaxText)}, {Reference: fixture(t, 9), Value: []byte("b")}},
	} {
		reader := &chunkReader{data: []byte("text"), step: 1}
		if err := ReplaceStream(context.Background(), reader, io.Discard, mappings, false, StreamLimits{Input: MaxText, Output: MaxText}); !errors.Is(err, ErrInvalid) || reader.calls != 0 {
			t.Fatal("invalid mappings reached the stream reader")
		}
	}
	for _, limits := range []StreamLimits{{Input: 0, Output: 1}, {Input: 1, Output: 0}, {Input: math.MaxInt64, Output: 1}} {
		reader := &chunkReader{data: []byte("text"), step: 1}
		if err := ReplaceStream(context.Background(), reader, io.Discard, valid, false, limits); !errors.Is(err, ErrInvalid) || reader.calls != 0 {
			t.Fatal("invalid quota reached the stream reader")
		}
	}
}

func TestStreamWritesBoundedChunks(t *testing.T) {
	mappings := []Mapping{{Reference: fixture(t, 1), Value: bytes.Repeat([]byte("x"), MaxText)}}
	input := placeholder(t, mappings[0].Reference)
	var written int64
	writer := streamWriteFunc(func(p []byte) (int, error) {
		if len(p) > streamChunk {
			t.Fatal("stream emitted an unbounded write")
		}
		for _, value := range p {
			if value != 'x' {
				t.Fatal("stream changed replacement bytes")
			}
		}
		written += int64(len(p))
		return len(p), nil
	})
	if err := ReplaceStream(context.Background(), bytes.NewReader(input), writer, mappings, false, StreamLimits{Input: int64(len(input)), Output: MaxText}); err != nil || written != MaxText {
		t.Fatal("maximum mapped value did not stream through bounded writes")
	}
}
