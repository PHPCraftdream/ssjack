// Package flakediag collects size/digest/timing evidence for flaky-test
// diagnostics. Test-only helper; failure-only output, no secrets by design.
package flakediag

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

// GoroutineDump renders the goroutine profile (debug=2), truncated to limit
// bytes. limit<=0 defaults to 64 KiB.
func GoroutineDump(limit int) string {
	if limit <= 0 {
		limit = 64 * 1024
	}
	var buf bytes.Buffer
	if p := pprof.Lookup("goroutine"); p != nil {
		_ = p.WriteTo(&buf, 2)
	} else {
		buf.WriteString("goroutine profile unavailable")
	}
	full := buf.Len()
	if full <= limit {
		return buf.String()
	}
	return fmt.Sprintf("%s\n...truncated (full %d bytes)", buf.String()[:limit], full)
}

// Tail returns the last limit bytes of s; when truncated the result is
// prefixed with a marker. limit<=0 defaults to 16 KiB. Decoration is bounded
// so the result never exceeds limit+128 bytes.
func Tail(s string, limit int) string {
	if limit <= 0 {
		limit = 16 * 1024
	}
	if len(s) <= limit {
		return s
	}
	return "\n...[earlier bytes truncated]\n" + s[len(s)-limit:]
}

// Short is a secret-free digest: first 6 bytes of sha256, hex-encoded.
func Short(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// OnFailure registers cleanup diagnostics: render runs after the test body
// and only when the test has failed, so it must be cheap and must not
// depend on state torn down before cleanup. If render panics, the panic
// message is logged instead of propagating.
func OnFailure(t *testing.T, render func() string) {
	onFailureSince(t, time.Now(), render)
}

func onFailureSince(t *testing.T, started time.Time, render func() string) {
	t.Cleanup(func() {
		logFailure(t.Failed(), t.Logf, func() string { return EnvironmentLine(t, started) }, render)
	})
}

func logFailure(failed bool, logf func(string, ...any), environment, render func() string) {
	if !failed {
		return
	}
	env := environment()
	defer func() {
		if r := recover(); r != nil {
			logf("failure diagnostics:\n%s\nrender panicked: %v", env, r)
		}
	}()
	logf("failure diagnostics:\n%s\n%s", env, render())
}

// Join renders evidence lines with a trailing newline per non-empty part.
func Join(parts ...string) string {
	var sb strings.Builder
	for _, p := range parts {
		if p != "" {
			sb.WriteString(p)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
