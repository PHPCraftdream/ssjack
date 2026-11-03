package application

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSecretWriterEveryBoundary(t *testing.T) {
	secret := strings.Repeat("0123456789abcdef", 4)
	input := []byte("prefix\x00" + secret + secret + "suffix\xff")
	want := []byte("prefix\x00******suffix\xff")
	for split := 0; split <= len(input); split++ {
		var output bytes.Buffer
		w := newSecretWriter(&output, secret)
		for _, part := range [][]byte{input[:split], input[split:]} {
			if n, err := w.Write(part); n != len(part) || err != nil {
				t.Fatalf("split %d: write %d, %v", split, n, err)
			}
			if len(w.pending) >= len(secret) {
				t.Fatal("retained more than one incomplete match")
			}
		}
		if err := w.flush(); err != nil || !bytes.Equal(output.Bytes(), want) {
			t.Fatalf("split %d: output mismatch, %v", split, err)
		}
		if err := w.flush(); err != nil || !bytes.Equal(output.Bytes(), want) {
			t.Fatal("flush was not idempotent")
		}
		if _, err := w.Write([]byte(secret)); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("accepted output after final flush")
		}
	}
}

func TestSecretWriterBytewiseAndUnmatched(t *testing.T) {
	secret := strings.Repeat("abc123", 10)
	input := []byte(strings.Repeat("other\x00", 100) + secret + secret[:len(secret)-1])
	var output bytes.Buffer
	w := newSecretWriter(&output, secret)
	for _, value := range input {
		if _, err := w.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.flush(); err != nil {
		t.Fatal(err)
	}
	want := bytes.ReplaceAll(input, []byte(secret), []byte("***"))
	if !bytes.Equal(output.Bytes(), want) {
		t.Fatal("bytewise or incomplete final match changed unrelated bytes")
	}
}

type outputFunc func([]byte) (int, error)

func (f outputFunc) Write(data []byte) (int, error) { return f(data) }

func TestSecretWriterOutputErrors(t *testing.T) {
	failure := errors.New("sink failed")
	for _, sink := range []io.Writer{
		outputFunc(func([]byte) (int, error) { return 0, failure }),
		outputFunc(func([]byte) (int, error) { return 0, nil }),
	} {
		w := newSecretWriter(sink, "secret")
		if _, err := w.Write([]byte("long unrelated output")); err == nil {
			t.Fatal("sink failure was lost")
		}
		if err := w.flush(); err == nil {
			t.Fatal("flush lost the sink failure")
		}
	}
	w := newSecretWriter(outputFunc(func([]byte) (int, error) { return 0, failure }), "secret")
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.flush(); !errors.Is(err, failure) {
		t.Fatal("trailing sink failure was lost")
	}
}
