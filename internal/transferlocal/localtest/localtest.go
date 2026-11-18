// Package localtest holds the test helpers shared by the transferlocal packages.
package localtest

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// TempDir returns a symlink-free temp directory (t.TempDir resolved through
// filepath.EvalSymlinks, because ParseRoot refuses symlinked ancestor paths,
// which t.TempDir has on darwin).
func TempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// WriteFile creates parent directories and writes content.
func WriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

// RequireClass fatals unless err is a *transfercore.Error of exactly class
// and its message contains none of the secrets.
func RequireClass(t *testing.T, err error, class transfercore.Class, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, got nil", class)
	}
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T: %v", err, err)
	}
	if e.Class != class {
		t.Fatalf("expected class %s, got %s: %s", class, e.Class, e.Message)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(e.Message, secret) {
			t.Fatalf("error message leaks a secret: %s", e.Message)
		}
	}
}

// RequireNoPath fatals unless os.Lstat reports the path does not exist.
func RequireNoPath(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		t.Fatalf("path unexpectedly exists: %s", path)
	}
}

// TarEntry is one entry of an in-memory tar fixture.
type TarEntry struct {
	Header *tar.Header
	Body   []byte
}

// TarArchive builds a tar archive in memory from the given entries.
func TarArchive(t *testing.T, entries []TarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		hdr := entry.Header
		if hdr.Format == 0 {
			fixed := *hdr
			fixed.Format = tar.FormatPAX
			hdr = &fixed
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(entry.Body) > 0 {
			if _, err := tw.Write(entry.Body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// PatchFirstHeaderSize overwrites the size field (offset 124, 11 octal
// digits + NUL) of the FIRST 512-byte header block of a single-entry archive
// and recomputes the header checksum so the modified archive stays valid.
func PatchFirstHeaderSize(t *testing.T, archive []byte, size int64) []byte {
	t.Helper()
	if len(archive) < 512 {
		t.Fatalf("archive too short: %d bytes", len(archive))
	}
	out := append([]byte(nil), archive...)
	var octal [11]byte
	remaining := size
	for i := 10; i >= 0; i-- {
		octal[i] = byte('0' + remaining%8)
		remaining /= 8
	}
	if remaining != 0 {
		t.Fatalf("size does not fit in 11 octal digits: %d", size)
	}
	copy(out[124:135], octal[:])
	out[135] = 0
	first := out[:512]
	for i := 148; i < 156; i++ {
		first[i] = ' '
	}
	sum := uint32(0)
	for _, b := range first {
		sum += uint32(b)
	}
	var chk [8]byte
	copy(chk[:], fmt.Sprintf("%06o", sum))
	chk[6] = 0
	chk[7] = ' '
	copy(out[148:156], chk[:])
	return out
}

// RegEntry is a regular-file tar entry of size bytes of 'x'.
func RegEntry(name string, size int) TarEntry {
	return TarEntry{
		Header: &tar.Header{Name: name, Mode: 0644, Size: int64(size), Format: tar.FormatUSTAR},
		Body:   bytes.Repeat([]byte("x"), size),
	}
}

// DirEntry is a directory tar entry.
func DirEntry(name string) TarEntry {
	return TarEntry{Header: &tar.Header{Name: name + "/", Mode: 0755, Typeflag: tar.TypeDir, Format: tar.FormatUSTAR}}
}
