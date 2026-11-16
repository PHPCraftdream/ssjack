package transferremote

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// countingReader counts bytes read from src.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// countingWriter counts bytes written to w.
type countingWriter struct {
	w io.Writer
	n atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

// writeFileTemplate creates the file via `cat >` with mode 0666 minus the
// remote umask; with the execute bit `chmod +x` adds the x bits. The file
// lives in the 0700 staging directory until publication; no ownership or
// special bits are ever set.
const writeFileTemplate = `set -eu
path=%s
if [ -e "$path" ] || [ -L "$path" ]; then
	exit 22
fi
cat > "$path" || exit 24
`

// writeFileExecSuffix is appended to writeFileTemplate when executable.
const writeFileExecSuffix = "\nchmod +x \"$path\" || exit 24\n"

// WriteFile streams src into a fresh file at path and returns the byte count.
func (r *remoteRunner) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	if err := checkRemotePath(path, r.limits); err != nil {
		return 0, err
	}
	command := fmt.Sprintf(writeFileTemplate, shellQuote(path))
	if executable {
		command += writeFileExecSuffix
	}
	cr := &countingReader{r: src}
	err := r.execute(ctx, command, cr, io.Discard)
	return cr.n.Load(), err
}

// statHashCommand returns the one-file command that prints the GNU
// sha256sum line "<64 hex>  <path>" for the probed hash variant.
func statHashCommand(hash string) string {
	switch hash {
	case hashShasum:
		return `shasum -a 256 "$path"`
	case hashSha256q:
		return `hash=$(sha256 -q "$path") || exit 24
printf '%s  %s\n' "$hash" "$path"`
	default:
		return `sha256sum "$path"`
	}
}

// statFileTemplate reports size and SHA-256 of a regular file.
const statFileTemplate = `set -eu
path=%s
if [ -L "$path" ] || [ ! -f "$path" ]; then
	exit 21
fi
wc -c < "$path"
%s
`

// StatFile returns the size and SHA-256 of a remote regular file. Symlinks
// and non-regular files are refused (exit 21).
func (r *remoteRunner) StatFile(ctx context.Context, path string) (int64, [32]byte, error) {
	if err := r.ready(); err != nil {
		return 0, [32]byte{}, err
	}
	if err := checkRemotePath(path, r.limits); err != nil {
		return 0, [32]byte{}, err
	}
	data, err := r.runListed(ctx, fmt.Sprintf(statFileTemplate, shellQuote(path), statHashCommand(r.capabilities().hash)), 8192)
	if err != nil {
		return 0, [32]byte{}, err
	}
	return parseStatOutput(data, path)
}

// parseStatOutput strictly parses "size\n<64 hex>  name\n".
func parseStatOutput(data []byte, path string) (int64, [32]byte, error) {
	malformed := listingError(transfercore.ClassIntegrity, "unexpected remote file listing")
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

// readFileTemplate streams a regular file; symlinks and non-regular files are
// refused (exit 21 -> ClassRefusedPath).
const readFileTemplate = `set -eu
path=%s
if [ -L "$path" ] || [ ! -f "$path" ]; then
	exit 21
fi
cat "$path" || exit 24
`

// ReadFile streams a remote regular file into dst and returns the byte count.
func (r *remoteRunner) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	if err := checkRemotePath(path, r.limits); err != nil {
		return 0, err
	}
	cw := &countingWriter{w: dst}
	err := r.execute(ctx, fmt.Sprintf(readFileTemplate, shellQuote(path)), nil, cw)
	return cw.n.Load(), err
}
