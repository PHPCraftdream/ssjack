//go:build linux && amd64

package declarativeslice

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type chunkReader struct {
	data []byte
	step int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(r.data)
	if n > r.step {
		n = r.step
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("source read failed")
}

func TestReadTextSelectionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"empty", nil, true},
		{"one byte", []byte("x"), false},
		{"exact maximum", bytes.Repeat([]byte("x"), maxDocument), false},
		{"over maximum", bytes.Repeat([]byte("x"), maxDocument+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readTextSelection(&chunkReader{data: append([]byte(nil), tc.input...), step: 137})
			if (err != nil) != tc.wantErr {
				t.Fatalf("readTextSelection error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && !bytes.Equal(got, tc.input) {
				t.Fatal("bounded selection differs from source")
			}
			clear(got)
		})
	}
	if _, err := readTextSelection(failingReader{}); err == nil {
		t.Fatal("source error accepted")
	}
	if _, err := readTextSelection(nil); err == nil {
		t.Fatal("nil source accepted")
	}
}
