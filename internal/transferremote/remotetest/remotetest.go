// Package remotetest holds the test helpers shared by the transferremote packages.
package remotetest

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// FakeRunner records every command and produces scripted responses.
type FakeRunner struct {
	mu       sync.Mutex
	commands []string
	Respond  func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

// Run matches remote.StreamRunner, so construct remotes with New(f.Run, ...).
func (f *FakeRunner) Run(ctx context.Context, target, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	if f.Respond != nil {
		return f.Respond(command, stdin, stdout, stderr)
	}
	return 0, nil
}

// Recorded returns a copy of the commands run so far.
func (f *FakeRunner) Recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// ExpectClass asserts err is a *transfercore.Error with the wanted class.
func ExpectClass(t *testing.T, err error, want transfercore.Class) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with class %q, got nil", want)
	}
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T: %v", err, err)
	}
	if e.Class != want {
		t.Fatalf("expected class %q, got %q (message %q)", want, e.Class, e.Message)
	}
}

// ExpectCode asserts the *transfercore.Error exit code matches want.
func ExpectCode(t *testing.T, err error, want int) {
	t.Helper()
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T: %v", err, err)
	}
	if e.ExitCode != want {
		t.Fatalf("expected exit code %d, got %d", want, e.ExitCode)
	}
}

// QuotedIn asserts the command contains raw single-quoted, and that a raw
// value containing a quote itself never appears unquoted in the command.
func QuotedIn(t *testing.T, command, raw string) {
	t.Helper()
	q := "'" + strings.ReplaceAll(raw, "'", `'\''`) + "'"
	if !strings.Contains(command, q) {
		t.Fatalf("command does not contain quoted %q; got:\n%s", raw, command)
	}
	if strings.Contains(raw, "'") && strings.Contains(command, raw) {
		t.Fatalf("command contains the raw caller text %q unquoted:\n%s", raw, command)
	}
}

// DrainReader reads r fully and fails the test on error.
func DrainReader(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading stream: %v", err)
	}
	return data
}

// SampleLimits returns the default transfer limits.
func SampleLimits() transfercore.Limits {
	return transfercore.DefaultLimits()
}

// WantErr asserts class, fixed message and exit code in one go.
func WantErr(t *testing.T, err error, want transfercore.Class, msg string, code int) {
	t.Helper()
	ExpectClass(t, err, want)
	ExpectCode(t, err, code)
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T", err)
	}
	if msg != "" && e.Message != msg {
		t.Fatalf("expected message %q, got %q", msg, e.Message)
	}
}

// ExpectExit runs op against a fake that answers with the exit code.
func ExpectExit(t *testing.T, code int, op func(*FakeRunner)) {
	t.Helper()
	f := &FakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return code, nil
	}}
	op(f)
}

var Payload = []byte("hello \x00\xff binary\npayload bytes\n")

// AsideName extracts the quoted `old=` value from a dir-overwrite command
// and returns its final path component.
func AsideName(t *testing.T, cmd string) string {
	t.Helper()
	i := strings.Index(cmd, "old='")
	if i < 0 {
		t.Fatalf("command has no old= quoted assignment:\n%s", cmd)
	}
	rest := cmd[i+len("old='"):]
	end := strings.Index(rest, "'")
	if end < 0 {
		t.Fatalf("unterminated old= quote:\n%s", cmd)
	}
	val := rest[:end]
	return val[strings.LastIndex(val, "/")+1:]
}
