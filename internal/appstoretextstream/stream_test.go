package appstoretextstream

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

type tinyReader struct {
	input io.Reader
	step  int
}

func (r tinyReader) Read(p []byte) (int, error) {
	if len(p) > r.step {
		p = p[:r.step]
	}
	return r.input.Read(p)
}

type stalledReader struct{}

func (stalledReader) Read([]byte) (int, error) { return 0, nil }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type cancelledReader struct {
	input  io.Reader
	cancel context.CancelFunc
}

func (r cancelledReader) Read(p []byte) (int, error) {
	n, err := r.input.Read(p)
	r.cancel()
	return n, err
}

func wire(t *testing.T, values ...frame) []byte {
	t.Helper()
	var out []byte
	for _, value := range values {
		encoded, err := encodeFrame(value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, encoded...)
	}
	return out
}

func TestBoundedFramesRoundTripBeyondV1Limit(t *testing.T) {
	input := bytes.Repeat([]byte("synthetic text \xe2\x82\xac\n"), 140000)
	for _, step := range []int{1, 7, ChunkSize} {
		var encoded, output bytes.Buffer
		if err := Encode(context.Background(), tinyReader{input: bytes.NewReader(input), step: step}, &encoded, "operation-1", uint64(len(input))); err != nil {
			t.Fatal(err)
		}
		if err := Decode(context.Background(), tinyReader{input: bytes.NewReader(encoded.Bytes()), step: step}, &output, "operation-1", uint64(len(input))); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(output.Bytes(), input) {
			t.Fatal("frame boundaries changed the document")
		}
	}
}

func TestCompletionIsRequiredAndMustBeLast(t *testing.T) {
	data := frame{Type: "data", OperationID: "op", Sequence: 0, Data: base64.StdEncoding.EncodeToString([]byte("copy"))}
	complete := frame{Type: "complete", OperationID: "op", Sequence: 1, Bytes: 4, Frames: 1}
	valid := wire(t, data, complete)
	cases := [][]byte{
		wire(t, data),
		append(append([]byte(nil), valid...), '\n'),
		append(append([]byte(nil), valid...), wire(t, complete)...),
		wire(t, data, frame{Type: "complete", OperationID: "op", Sequence: 1, Bytes: 3, Frames: 1}),
		wire(t, data, frame{Type: "complete", OperationID: "op", Sequence: 1, Bytes: 4, Frames: 2}),
		valid[:len(valid)-1],
	}
	for _, encoded := range cases {
		var tentative bytes.Buffer
		if err := Decode(context.Background(), bytes.NewReader(encoded), &tentative, "op", 16); err == nil {
			t.Fatal("incomplete or trailing stream was accepted")
		}
		if tentative.Len() == 0 {
			t.Fatal("late-error fixture did not exercise tentative output")
		}
	}
	var empty bytes.Buffer
	if err := Encode(context.Background(), strings.NewReader(""), &empty, "op", 1); err != nil {
		t.Fatal(err)
	}
	if err := Decode(context.Background(), &empty, io.Discard, "op", 1); err != nil {
		t.Fatal(err)
	}
}

func TestClosedSchemasOperationSequenceAndCanonicalBase64(t *testing.T) {
	for _, encoded := range []string{
		`{"type":"data","operation_id":"op","sequence":0,"data":"YQ==","approved":true}`,
		`{"type":"data","operation_id":"op","sequence":0,"sequence":0,"data":"YQ=="}`,
		`{"type":"data","operation_id":"other","sequence":0,"data":"YQ=="}`,
		`{"type":"data","operation_id":"op","sequence":1,"data":"YQ=="}`,
		`{"type":"data","operation_id":"op","sequence":0,"data":"YR=="}`,
		`{"type":"data","operation_id":"op","sequence":0,"data":""}`,
		`{"type":"complete","operation_id":"op","sequence":0,"bytes":null,"frames":0}`,
	} {
		input := encoded + "\n"
		if strings.Contains(encoded, `"type":"data"`) {
			count := uint64(1)
			if strings.Contains(encoded, `"data":""`) {
				count = 0
			}
			input += string(wire(t, frame{Type: "complete", OperationID: "op", Sequence: 1, Bytes: count, Frames: 1}))
		}
		if err := Decode(context.Background(), strings.NewReader(input), io.Discard, "op", 16); err == nil {
			t.Fatal("malformed private frame was accepted")
		}
	}
}

func TestQuotasNoProgressAndShortWrites(t *testing.T) {
	if err := Encode(context.Background(), strings.NewReader("over"), io.Discard, "op", 3); err == nil {
		t.Fatal("encoder exceeded decoded quota")
	}
	if err := Encode(context.Background(), stalledReader{}, io.Discard, "op", 3); err == nil {
		t.Fatal("stalled source did not terminate")
	}
	if err := Encode(context.Background(), strings.NewReader("value"), shortWriter{}, "op", 16); err == nil {
		t.Fatal("encoder ignored a short write")
	}
	oversized := strings.Repeat(" ", MaxWireFrame+1) + "\n"
	if err := Decode(context.Background(), strings.NewReader(oversized), io.Discard, "op", 16); err == nil {
		t.Fatal("decoder accepted an oversized frame")
	}
	encoded := wire(t, frame{Type: "data", OperationID: "op", Sequence: 0, Data: "dmFsdWU="}, frame{Type: "complete", OperationID: "op", Sequence: 1, Bytes: 5, Frames: 1})
	if err := Decode(context.Background(), bytes.NewReader(encoded), io.Discard, "op", 4); err == nil {
		t.Fatal("decoder exceeded decoded quota")
	}
	if err := Decode(context.Background(), bytes.NewReader(encoded), shortWriter{}, "op", 16); err == nil {
		t.Fatal("decoder ignored a short write")
	}
}

func TestCancellationDuringReadDoesNotWriteAnotherChunk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var encoded bytes.Buffer
	err := Encode(ctx, cancelledReader{input: strings.NewReader("value"), cancel: cancel}, &encoded, "op", 16)
	if !errors.Is(err, context.Canceled) || encoded.Len() != 0 {
		t.Fatal("cancelled encode emitted a new frame")
	}
	ctx, cancel = context.WithCancel(context.Background())
	var decoded bytes.Buffer
	input := wire(t, frame{Type: "data", OperationID: "op", Sequence: 0, Data: "dmFsdWU="}, frame{Type: "complete", OperationID: "op", Sequence: 1, Bytes: 5, Frames: 1})
	err = Decode(ctx, cancelledReader{input: bytes.NewReader(input), cancel: cancel}, &decoded, "op", 16)
	if !errors.Is(err, context.Canceled) || decoded.Len() != 0 {
		t.Fatal("cancelled decode emitted another payload chunk")
	}
}
