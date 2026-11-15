// Package lifelog records the MCP bridge lifecycle as fixed, secret-free events.
package lifelog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Env carries the log path from the keeper to the MCP bridge it launches.
const Env = "SSJACK_LIFECYCLE_LOG"

const (
	maxFile  = 1 << 20
	maxLine  = 512
	maxValue = 64
)

var writeMu sync.Mutex

// Log is diagnostic only: nothing reads it back to make a decision. A nil Log
// records nothing.
type Log struct {
	path, prefix string
}

// Path is the per-project log file next to the installed UI plugin.
func Path(root string) string {
	return filepath.Join(root, ".claude", "ssjack", "lifecycle.log")
}

// New binds a log to one process role. The session is recorded only as a short
// digest, enough to match keeper and bridge lines.
func New(path, role, session string) *Log {
	if !filepath.IsAbs(path) || filepath.Base(path) != "lifecycle.log" {
		return nil
	}
	digest := sha256.Sum256([]byte(session))
	return &Log{path: filepath.Clean(path), prefix: " pid=" + strconv.Itoa(os.Getpid()) + " role=" + clean(role) + " sid=" + hex.EncodeToString(digest[:4])}
}

// Event appends one line: a fixed name and key=value pairs whose values are
// reduced to a closed alphabet, so no free text reaches the file.
func (l *Log) Event(name string, pairs ...string) {
	if l == nil {
		return
	}
	var line strings.Builder
	line.WriteString(time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	line.WriteString(l.prefix)
	line.WriteString(" event=" + clean(name))
	for i := 0; i+1 < len(pairs); i += 2 {
		line.WriteString(" " + clean(pairs[i]) + "=" + clean(pairs[i+1]))
	}
	text := line.String()
	if len(text) > maxLine {
		text = text[:maxLine]
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	if os.MkdirAll(filepath.Dir(l.path), 0700) != nil {
		return
	}
	if info, err := os.Lstat(l.path); err == nil {
		if !info.Mode().IsRegular() {
			return
		}
		if info.Size() > maxFile {
			_ = os.Rename(l.path, l.path+".1")
		}
	}
	file, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return
	}
	_, _ = file.WriteString(text + "\n")
	_ = file.Close()
}

func clean(value string) string {
	if len(value) > maxValue {
		value = value[:maxValue]
	}
	out := []byte(value)
	for i, c := range out {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == ':':
		default:
			out[i] = '_'
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return string(out)
}

// Cause reduces an error to a fixed class; the error text is never recorded.
func Cause(err error) string {
	var network net.Error
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, net.ErrClosed), errors.Is(err, os.ErrClosed):
		return "closed"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.Errno(10054)):
		return "reset"
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.Errno(10061)):
		return "refused"
	case errors.Is(err, syscall.EPIPE):
		return "pipe"
	case errors.As(err, &network) && network.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

// Millis formats an elapsed time for a field.
func Millis(since time.Time) string {
	return strconv.FormatInt(time.Since(since).Milliseconds(), 10)
}
