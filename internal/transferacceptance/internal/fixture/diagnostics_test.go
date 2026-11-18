//go:build linux || darwin

package fixture

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type fixedResultWriter struct {
	n   int
	err error
}

func (w fixedResultWriter) Write(p []byte) (int, error) { return w.n, w.err }

func TestDiagnosticWriterForwardsAndCapturesAcceptedBytes(t *testing.T) {
	var downstream bytes.Buffer
	capture := newDiagnosticBuffer(3)
	writer := &diagnosticWriter{downstream: &downstream, capture: capture}

	n, err := writer.Write([]byte("hello"))
	if n != 5 || err != nil {
		t.Fatalf("Write() = (%d, %v), want (5, nil)", n, err)
	}
	if got := downstream.String(); got != "hello" {
		t.Fatalf("downstream = %q, want %q", got, "hello")
	}
	if got := string(capture.snapshot()); got != "hel" {
		t.Fatalf("captured prefix = %q, want %q", got, "hel")
	}
}

func TestDiagnosticWriterPropagatesShortWriteAndError(t *testing.T) {
	wantErr := errors.New("write failed")
	capture := newDiagnosticBuffer(8)
	writer := &diagnosticWriter{downstream: fixedResultWriter{n: 2, err: wantErr}, capture: capture}

	n, err := writer.Write([]byte("data"))
	if n != 2 || err != wantErr {
		t.Fatalf("Write() = (%d, %v), want (2, %v)", n, err, wantErr)
	}
	if got := string(capture.snapshot()); got != "da" {
		t.Fatalf("captured prefix = %q, want %q", got, "da")
	}
}

func TestFormatExecDiagnosticEscapesNonprintableBytes(t *testing.T) {
	got := formatExecDiagnostic(2, execDiagnosticSnapshot{
		script: []byte{'s', '\n', 0xff},
		stdout: []byte("o\ré"),
		stderr: []byte("err\x00"),
		exit:   -1,
	})
	for _, raw := range []string{"\n", "\r", "\x00", "é", string([]byte{0xff})} {
		if strings.Contains(got, raw) {
			t.Fatalf("diagnostic contains raw nonprintable data %q: %q", raw, got)
		}
	}
	for _, escaped := range []string{`script="s\n\xff"`, `exit=-1`, `stdout="o\r\u00e9"`, `stderr="err\x00"`} {
		if !strings.Contains(got, escaped) {
			t.Fatalf("diagnostic %q does not contain %q", got, escaped)
		}
	}
}
