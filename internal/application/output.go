package application

import (
	"bytes"
	"io"
	"sync"
)

type secretWriter struct {
	mu      sync.Mutex
	output  io.Writer
	secret  []byte
	pending []byte
	err     error
	closed  bool
}

func newSecretWriter(output io.Writer, secret string) *secretWriter {
	return &secretWriter{output: output, secret: []byte(secret)}
}

func (w *secretWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	w.pending = append(w.pending, data...)
	for len(w.secret) > 0 {
		index := bytes.Index(w.pending, w.secret)
		if index < 0 {
			break
		}
		w.emit(w.pending[:index])
		w.emit([]byte("***"))
		w.pending = w.pending[index+len(w.secret):]
	}
	keep := max(0, len(w.secret)-1)
	if len(w.pending) > keep {
		n := len(w.pending) - keep
		w.emit(w.pending[:n])
		w.pending = append([]byte(nil), w.pending[n:]...)
	}
	if w.err != nil {
		return 0, w.err
	}
	return len(data), nil
}

func (w *secretWriter) emit(data []byte) {
	if w.err != nil || len(data) == 0 {
		return
	}
	for len(data) > 0 {
		n, err := w.output.Write(data)
		if err != nil {
			w.err = err
			return
		}
		if n <= 0 || n > len(data) {
			w.err = io.ErrShortWrite
			return
		}
		data = data[n:]
	}
}

func (w *secretWriter) flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	w.emit(w.pending)
	clear(w.pending)
	w.pending = nil
	clear(w.secret)
	w.secret = nil
	return w.err
}
