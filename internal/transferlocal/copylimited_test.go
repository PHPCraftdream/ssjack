package transferlocal

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCopyLimitedExactCopy(t *testing.T) {
	data := make([]byte, 96*1024+17)
	for i := range data {
		data[i] = byte(i*31 ^ i>>2)
	}
	data[0] = 0x00
	data[1] = 0xff
	var dst bytes.Buffer
	n, digest, err := CopyLimited(&dst, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Fatalf("copied %d bytes, want %d", n, len(data))
	}
	if digest != sha256.Sum256(data) {
		t.Fatal("digest mismatch")
	}
	if !bytes.Equal(dst.Bytes(), data) {
		t.Fatal("destination bytes differ")
	}
}

func TestCopyLimitedExceedsLimit(t *testing.T) {
	data := []byte("exceeds-limit-payload-0123456789")
	var dst bytes.Buffer
	_, _, err := CopyLimited(&dst, bytes.NewReader(data), 4)
	requireClass(t, err, "limit", string(data))
	if int64(dst.Len()) > 4 {
		t.Fatalf("destination received %d bytes, max 4", dst.Len())
	}
}

func TestCopyLimitedEmptySource(t *testing.T) {
	var dst bytes.Buffer
	n, digest, err := CopyLimited(&dst, bytes.NewReader(nil), 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || dst.Len() != 0 {
		t.Fatalf("copied %d bytes from an empty source", n)
	}
	if digest != sha256.Sum256(nil) {
		t.Fatal("digest of empty copy is wrong")
	}
}

func TestCopyLimitedZeroMax(t *testing.T) {
	var dst bytes.Buffer
	_, _, err := CopyLimited(&dst, bytes.NewReader([]byte("data")), 0)
	requireClass(t, err, "limit")
	if dst.Len() != 0 {
		t.Fatalf("destination received %d bytes with max 0", dst.Len())
	}
}
