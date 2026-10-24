package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

func TestFraming(t *testing.T) {
	var out shortWriter
	want := Auth{Session: "session", EnvToken: "a", DiskToken: "b"}
	if err := Write(&out, want); err != nil {
		t.Fatal(err)
	}
	var got Auth
	if err := Read(&out, &got); err != nil || got != want {
		t.Fatalf("got %+v, error %v", got, err)
	}
}

func TestRejectInvalidFrames(t *testing.T) {
	for _, size := range []uint32{0, MaxFrame + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if err := Read(bytes.NewReader(header[:]), new(Auth)); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	if err := Read(bytes.NewReader([]byte{0, 0, 0, 5, '{'}), new(Auth)); err == nil {
		t.Fatal("accepted a truncated message")
	}
	if err := Write(io.Discard, strings.Repeat("x", MaxFrame)); err == nil {
		t.Fatal("accepted an oversized message")
	}
}

func TestTokens(t *testing.T) {
	a, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomToken()
	if err != nil || len(a) != 64 || len(b) != 64 || a == b {
		t.Fatal("tokens must be independent 256-bit values")
	}
}
