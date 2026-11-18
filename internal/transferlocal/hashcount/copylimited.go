// Package hashcount hashes and bounds the bytes of a copy in one pass.
package hashcount

import (
	"crypto/sha256"
	"hash"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Counter is a streaming writer that hashes and counts what passes
// through it so every copy path can verify and bound bytes in one pass.
type Counter struct {
	dst io.Writer // may be nil
	h   hash.Hash
	n   int64
}

// New returns a Counter that forwards to dst (may be nil).
func New(dst io.Writer) *Counter {
	return &Counter{dst: dst, h: sha256.New()}
}

func (c *Counter) Write(p []byte) (int, error) {
	if _, err := c.h.Write(p); err != nil {
		return 0, err
	}
	if c.dst != nil {
		if _, err := c.dst.Write(p); err != nil {
			return 0, err
		}
	}
	c.n += int64(len(p))
	return len(p), nil
}

func (c *Counter) Sum() [32]byte {
	var out [32]byte
	copy(out[:], c.h.Sum(nil))
	return out
}

func (c *Counter) Count() int64 {
	return c.n
}

// CopyLimited copies src into dst, returning the byte count and SHA-256 of
// what was read and written. A chunk that would exceed max is not written.
func CopyLimited(dst io.Writer, src io.Reader, max int64) (int64, [32]byte, error) {
	if max < 0 {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassInternal, "copy limit is invalid")
	}
	c := New(dst)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if c.Count()+int64(n) > max {
				return c.Count(), c.Sum(), transfercore.Fail(transfercore.ClassLimit, "transfer exceeds the configured limits")
			}
			if _, werr := c.Write(buf[:n]); werr != nil {
				return c.Count(), c.Sum(), transfercore.Fail(transfercore.ClassInternal, "destination could not be written")
			}
		}
		if err == io.EOF {
			return c.Count(), c.Sum(), nil
		}
		if err != nil {
			return c.Count(), c.Sum(), transfercore.Fail(transfercore.ClassInternal, "source could not be read")
		}
	}
}
