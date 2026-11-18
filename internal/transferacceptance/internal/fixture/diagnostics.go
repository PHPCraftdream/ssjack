//go:build linux || darwin

package fixture

import (
	"io"
	"strconv"
	"sync"
)

const (
	execDiagnosticLimit       = 256
	execDiagnosticScriptLimit = 1024
	execDiagnosticOutputLimit = 4096
)

type execDiagnostic struct {
	script []byte
	stdout *diagnosticBuffer
	stderr *diagnosticBuffer
	exit   int
}

type execDiagnosticSnapshot struct {
	script []byte
	stdout []byte
	stderr []byte
	exit   int
}

type diagnosticBuffer struct {
	mu     sync.Mutex
	limit  int
	prefix []byte
}

func newDiagnosticBuffer(limit int) *diagnosticBuffer {
	return &diagnosticBuffer{limit: limit, prefix: make([]byte, 0, limit)}
}

func (b *diagnosticBuffer) append(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - len(b.prefix)
	if remaining <= 0 {
		return
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	b.prefix = append(b.prefix, p...)
}

func (b *diagnosticBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.prefix...)
}

type diagnosticWriter struct {
	mu         sync.Mutex
	downstream io.Writer
	capture    *diagnosticBuffer
}

func (w *diagnosticWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.downstream.Write(p)
	if n > 0 && n <= len(p) {
		w.capture.append(p[:n])
	}
	return n, err
}

func formatExecDiagnostic(index int, d execDiagnosticSnapshot) string {
	return "remote exec " + strconv.Itoa(index) + ": script=" + strconv.QuoteToASCII(string(d.script)) +
		" exit=" + strconv.Itoa(d.exit) +
		" stdout=" + strconv.QuoteToASCII(string(d.stdout)) +
		" stderr=" + strconv.QuoteToASCII(string(d.stderr))
}
