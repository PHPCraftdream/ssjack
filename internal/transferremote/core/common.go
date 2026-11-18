package core

import (
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// CountingReader counts bytes read from src.
type CountingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *CountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// CountingWriter counts bytes written to w.
type CountingWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *CountingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// StatHashCommand returns the one-file command that prints the GNU
// sha256sum line "<64 hex>  <path>" for the probed hash variant.
func StatHashCommand(hash string) string {
	switch hash {
	case HashShasum:
		return `out=$(shasum -a 256 < "$path") || exit 24
hash=${out%% *}
[ "$out" = "$hash  -" ] || exit 24
printf '%s  %s\n' "$hash" "$path"`
	case HashSha256q:
		return `hash=$(sha256 -q "$path") || exit 24
printf '%s  %s\n' "$hash" "$path"`
	default:
		return `sha256sum "$path"`
	}
}

// ParseStatOutput strictly parses "size\n<64 hex>  name\n".
func ParseStatOutput(data []byte, path string) (int64, [32]byte, error) {
	malformed := ListingError(transfercore.ClassIntegrity, "unexpected remote file listing")
	s := string(data)
	if !strings.HasSuffix(s, "\n") {
		return 0, [32]byte{}, malformed
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) != 2 {
		return 0, [32]byte{}, malformed
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[0]), 10, 64)
	if err != nil || size < 0 || !allDigits(strings.TrimSpace(lines[0])) {
		return 0, [32]byte{}, malformed
	}
	hashLine := lines[1]
	if len(hashLine) < 67 {
		return 0, [32]byte{}, malformed
	}
	var hash [32]byte
	raw, err := hex.DecodeString(hashLine[0:64])
	if err != nil || len(raw) != 32 {
		return 0, [32]byte{}, malformed
	}
	copy(hash[:], raw)
	if hashLine[64:66] != "  " || hashLine[66:] != path {
		return 0, [32]byte{}, malformed
	}
	return size, hash, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ListingError builds a local parse error with no remote exit code.
func ListingError(class transfercore.Class, message string) *transfercore.Error {
	return Classed(class, message, -1)
}

const (
	PerlRenameCommand = `perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' --`
	PerlLinkCommand   = `perl -e 'exit(link($ARGV[0], $ARGV[1]) ? 0 : 1)' --`
)

// PublicationTemplate keeps the original GNU command templates byte-for-byte
// when mv -T is functional. On fallback targets only fixed command literals
// are substituted; caller-controlled paths remain quoted shell arguments.
func PublicationTemplate(template string, caps Caps) string {
	if caps.MvT {
		return template
	}
	template = strings.ReplaceAll(template, `mv -T -f`, PerlRenameCommand)
	template = strings.ReplaceAll(template, `mv -T`, PerlRenameCommand)
	template = strings.ReplaceAll(template, `ln "$src" "$dst"`, PerlLinkCommand+` "$src" "$dst"`)
	return template
}

// NewCountingReader returns a CountingReader over r.
func NewCountingReader(r io.Reader) *CountingReader { return &CountingReader{r: r} }

// Count returns the bytes read so far.
func (c *CountingReader) Count() int64 { return c.n.Load() }

// NewCountingWriter returns a CountingWriter over w.
func NewCountingWriter(w io.Writer) *CountingWriter { return &CountingWriter{w: w} }

// Count returns the bytes written so far.
func (c *CountingWriter) Count() int64 { return c.n.Load() }
