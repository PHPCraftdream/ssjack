//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"io"
	"testing"
)

func newCapture() *reverseCapture {
	return &reverseCapture{data: make([]byte, reverseTextLimit)}
}

func TestReverseCaptureBoundsAndSeal(t *testing.T) {
	t.Run("exact limit", func(t *testing.T) {
		c := newCapture()
		data := bytes.Repeat([]byte{'x'}, reverseTextLimit)
		if n, err := c.Write(data); n != len(data) || err != nil {
			t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(data))
		}
		if len(c.data) != reverseTextLimit || c.length != reverseTextLimit {
			t.Fatalf("data length/length = %d/%d, want %d/%d", len(c.data), c.length, reverseTextLimit, reverseTextLimit)
		}
		n, overflow := c.seal()
		if overflow || n != len(data) || !bytes.Equal(c.data[:n], data) {
			t.Fatal("seal did not return the exact captured input")
		}
	})

	t.Run("overflow and sealed writer", func(t *testing.T) {
		c := newCapture()
		prefix := []byte("prefix")
		if n, err := c.Write(prefix); n != len(prefix) || err != nil {
			t.Fatalf("prefix Write() = (%d, %v)", n, err)
		}
		before := append([]byte(nil), c.data[:c.length]...)
		huge := make([]byte, reverseTextLimit+1)
		if n, err := c.Write(huge); n != 0 || err != io.ErrShortWrite {
			t.Fatalf("overflow Write() = (%d, %v), want (0, %v)", n, err, io.ErrShortWrite)
		}
		if !c.overflow {
			t.Fatal("overflow was not latched")
		}
		if !bytes.Equal(c.data[:c.length], before) {
			t.Fatal("overflow changed captured bytes")
		}
		if n, err := c.Write([]byte("fit")); n != 3 || err != nil {
			t.Fatalf("fitting Write() after overflow = (%d, %v), want (3, nil)", n, err)
		}
		n, overflow := c.seal()
		if n != len(prefix)+3 || !overflow {
			t.Fatalf("seal() = (%d, %v), want (%d, true)", n, overflow, len(prefix)+3)
		}
		sealed := append([]byte(nil), c.data[:n]...)
		if !bytes.Equal(sealed, []byte("prefixfit")) {
			t.Fatalf("sealed data = %q, want %q", sealed, "prefixfit")
		}
		if n, err := c.Write([]byte("after seal")); n != 0 || err != io.ErrClosedPipe {
			t.Fatalf("Write after seal = (%d, %v), want (0, %v)", n, err, io.ErrClosedPipe)
		}
		if !bytes.Equal(c.data[:n], sealed) {
			t.Fatal("write after seal changed captured bytes")
		}
	})

	t.Run("chunk boundary", func(t *testing.T) {
		c := newCapture()
		for _, chunk := range [][]byte{[]byte("before syn"), []byte("thetic-secret after")} {
			if n, err := c.Write(chunk); n != len(chunk) || err != nil {
				t.Fatalf("Write(%q) = (%d, %v)", chunk, n, err)
			}
		}
		n, overflow := c.seal()
		if overflow {
			t.Fatal("unexpected overflow")
		}
		if want := []byte("before synthetic-secret after"); !bytes.Equal(c.data[:n], want) {
			t.Fatalf("sealed data = %q, want %q", c.data[:n], want)
		}
	})
}
