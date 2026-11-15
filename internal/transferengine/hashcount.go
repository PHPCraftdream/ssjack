package transferengine

import (
	"crypto/sha256"
	"hash"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func limitExceeded() error {
	return transfercore.Fail(transfercore.ClassLimit, msgLimitExceeded)
}

// hashingReader hashes and counts what is actually read from the local source
// while it streams to the remote side, and fails the stream once the byte
// limit is crossed so an over-limit transfer cannot complete.
type hashingReader struct {
	src    io.Reader
	max    int64
	onRead func(int64) // optional streaming progress hook

	// mu guards the fields below: the SSH stdin copy goroutine may still be
	// reading after the remote call has returned.
	mu  sync.Mutex
	h   hash.Hash
	n   int64
	err error
}

func newHashingReader(src io.Reader, max int64) *hashingReader {
	return &hashingReader{src: src, h: sha256.New(), max: max}
}

func (r *hashingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	failed := r.err
	r.mu.Unlock()
	if failed != nil {
		return 0, failed
	}
	n, err := r.src.Read(p)
	if n > 0 {
		r.mu.Lock()
		_, _ = r.h.Write(p[:n])
		r.n += int64(n)
		total := r.n
		if total > r.max {
			r.err = limitExceeded()
			failed = r.err
		}
		r.mu.Unlock()
		if failed != nil {
			return n, failed
		}
		if r.onRead != nil {
			r.onRead(total)
		}
	}
	return n, err
}

func (r *hashingReader) count() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *hashingReader) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *hashingReader) digest() [32]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [32]byte
	copy(out[:], r.h.Sum(nil))
	return out
}

// hashingWriter hashes and counts what is actually written into the local
// staging payload while the remote stream arrives. A chunk that would exceed
// the byte limit is not written and fails the stream.
type hashingWriter struct {
	dst     io.Writer
	h       hash.Hash
	n       int64
	max     int64
	err     error
	onWrite func(int64) // optional streaming progress hook
}

func newHashingWriter(dst io.Writer, max int64) *hashingWriter {
	return &hashingWriter{dst: dst, h: sha256.New(), max: max}
}

func (w *hashingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.n > w.max-int64(len(p)) {
		w.err = limitExceeded()
		return 0, w.err
	}
	n, err := w.dst.Write(p)
	if n > 0 {
		_, _ = w.h.Write(p[:n])
		w.n += int64(n)
		if w.onWrite != nil {
			w.onWrite(w.n)
		}
	}
	if err != nil {
		w.err = err
		return n, err
	}
	return n, nil
}

func (w *hashingWriter) digest() [32]byte {
	var out [32]byte
	copy(out[:], w.h.Sum(nil))
	return out
}
