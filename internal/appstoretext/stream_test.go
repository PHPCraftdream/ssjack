package appstoretext

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type chunkReader struct {
	data  []byte
	step  int
	calls int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	r.calls++
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(r.data), r.step)
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestStreamMatchesLiteralEngineAcrossChunks(t *testing.T) {
	a, b := fixture(t, 1), fixture(t, 9)
	mappings := []Mapping{{Reference: a, Value: []byte("aba")}, {Reference: b, Value: []byte("ab")}}
	forward := append([]byte("prefix="), placeholder(t, a)...)
	forward = append(forward, placeholder(t, b)...)
	forward = append(forward, []byte(";unchanged\x00\xff")...)
	for _, reverse := range []bool{false, true} {
		input := forward
		if reverse {
			input = []byte("ababa;abaab;unchanged\x00\xff")
		}
		want, err := Replace(input, mappings, reverse)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range []int{1, 2, 7, 64, streamChunk} {
			reader := &chunkReader{data: input, step: step}
			var output bytes.Buffer
			err := ReplaceStream(context.Background(), reader, &output, mappings, reverse, StreamLimits{Input: MaxText, Output: MaxText})
			if err != nil || !bytes.Equal(output.Bytes(), want) {
				t.Fatal("streaming changed literal replacement semantics")
			}
		}
	}
}

func TestStreamLargeRoundtripAndBufferBoundary(t *testing.T) {
	r := fixture(t, 1)
	p := placeholder(t, r)
	mappings := []Mapping{{Reference: r, Value: []byte("synthetic-token")}}
	input := bytes.Repeat([]byte("."), 2*MaxText+streamChunk-1)
	input = append(input, p...)
	input = append(input, []byte(";tail")...)
	var deployed, restored bytes.Buffer
	limits := StreamLimits{Input: int64(len(input)), Output: int64(len(input))}
	if err := ReplaceStream(context.Background(), &chunkReader{data: input, step: streamChunk}, &deployed, mappings, false, limits); err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte("."), 2*MaxText+streamChunk-1), []byte("synthetic-token;tail")...)
	if !bytes.Equal(deployed.Bytes(), want) {
		t.Fatal("large deployment changed unselected bytes or a boundary match")
	}
	limits.Input = int64(deployed.Len())
	if err := ReplaceStream(context.Background(), &chunkReader{data: deployed.Bytes(), step: 7}, &restored, mappings, true, limits); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), input) {
		t.Fatal("large reverse copy lost an exact versioned placeholder")
	}
}

func TestStreamAmbiguityGuardDoesNotSkipRawBytes(t *testing.T) {
	r := fixture(t, 1)
	p := placeholder(t, r)
	for _, value := range [][]byte{[]byte("prefix{"), []byte("{"), []byte("secret")} {
		mappings := []Mapping{{Reference: r, Value: value}}
		input := append([]byte("prefix"), p...)
		if _, err := Replace(input, mappings, true); err == nil {
			t.Fatal("invalid counterfactual fixture")
		}
		for _, step := range []int{1, 2, 7, len(p) - 1, streamChunk} {
			var output bytes.Buffer
			if err := ReplaceStream(context.Background(), &chunkReader{data: input, step: step}, &output, mappings, true, StreamLimits{Input: MaxText, Output: MaxText}); !errors.Is(err, ErrInvalid) {
				t.Fatal("streaming skipped a registered placeholder inside consumed raw bytes")
			}
		}
	}
}

func TestStreamRejectsLateAmbiguityAfterTentativeOutput(t *testing.T) {
	r := fixture(t, 1)
	input := append(bytes.Repeat([]byte("."), 2*MaxText), placeholder(t, r)...)
	mappings := []Mapping{{Reference: r, Value: []byte("secret")}}
	var output bytes.Buffer
	err := ReplaceStream(context.Background(), bytes.NewReader(input), &output, mappings, true, StreamLimits{Input: int64(len(input)), Output: int64(len(input))})
	if !errors.Is(err, ErrInvalid) || output.Len() == 0 {
		t.Fatal("late ambiguity did not reject tentative streamed output")
	}
}

func TestStreamLongValueAcrossReads(t *testing.T) {
	r := fixture(t, 1)
	value := bytes.Repeat([]byte("x"), MaxText)
	mappings := []Mapping{{Reference: r, Value: value}}
	input := append([]byte("."), value...)
	input = append(input, '.')
	want := append([]byte("."), placeholder(t, r)...)
	want = append(want, '.')
	var output bytes.Buffer
	err := ReplaceStream(context.Background(), &chunkReader{data: input, step: 8192}, &output, mappings, true, StreamLimits{Input: int64(len(input)), Output: MaxText})
	if err != nil || !bytes.Equal(output.Bytes(), want) {
		t.Fatal("large value split across reads did not match exactly once")
	}
}

func TestStreamExactQuotas(t *testing.T) {
	r := fixture(t, 1)
	mappings := []Mapping{{Reference: r, Value: []byte("secret")}}
	for _, limits := range []StreamLimits{{Input: 3, Output: 3}, {Input: 2, Output: 3}, {Input: 3, Output: 2}} {
		var output bytes.Buffer
		err := ReplaceStream(context.Background(), bytes.NewReader([]byte("...")), &output, mappings, false, limits)
		if limits.Input == 3 && limits.Output == 3 {
			if err != nil || output.String() != "..." {
				t.Fatal("exact stream quota was refused")
			}
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatal("stream quota overflow was accepted")
		}
	}
	var output bytes.Buffer
	if err := ReplaceStream(context.Background(), bytes.NewReader(nil), &output, mappings, true, StreamLimits{Input: 1, Output: 1}); err != nil || output.Len() != 0 {
		t.Fatal("empty reverse stream changed")
	}
}
