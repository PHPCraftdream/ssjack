package transferremote

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// fakeRunner records every command and produces scripted responses.
type fakeRunner struct {
	mu       sync.Mutex
	commands []string
	respond  func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error)
}

// run matches remote.StreamRunner, so construct remotes with New(f.run, ...).
func (f *fakeRunner) run(ctx context.Context, target, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	if f.respond != nil {
		return f.respond(command, stdin, stdout, stderr)
	}
	return 0, nil
}

// recorded returns a copy of the commands run so far.
func (f *fakeRunner) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// expectClass asserts err is a *transfercore.Error with the wanted class.
func expectClass(t *testing.T, err error, want transfercore.Class) {
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

// expectCode asserts the *transfercore.Error exit code matches want.
func expectCode(t *testing.T, err error, want int) {
	t.Helper()
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T: %v", err, err)
	}
	if e.ExitCode != want {
		t.Fatalf("expected exit code %d, got %d", want, e.ExitCode)
	}
}

// quotedIn asserts the command contains raw single-quoted, and that a raw
// value containing a quote itself never appears unquoted in the command.
func quotedIn(t *testing.T, command, raw string) {
	t.Helper()
	q := shellQuote(raw)
	if !strings.Contains(command, q) {
		t.Fatalf("command does not contain quoted %q; got:\n%s", raw, command)
	}
	if strings.Contains(raw, "'") && strings.Contains(command, raw) {
		t.Fatalf("command contains the raw caller text %q unquoted:\n%s", raw, command)
	}
}

// drainReader reads r fully and fails the test on error.
func drainReader(t *testing.T, r io.Reader) []byte {
	t.Helper()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading stream: %v", err)
	}
	return data
}

// sampleLimits returns the default transfer limits.
func sampleLimits() transfercore.Limits {
	return transfercore.DefaultLimits()
}

// testWantErr asserts class, fixed message and exit code in one go.
func testWantErr(t *testing.T, err error, want transfercore.Class, msg string, code int) {
	t.Helper()
	expectClass(t, err, want)
	expectCode(t, err, code)
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T", err)
	}
	if msg != "" && e.Message != msg {
		t.Fatalf("expected message %q, got %q", msg, e.Message)
	}
}

// testExitCase is one remote-exit-code -> class expectation.
type testExitCase struct {
	code int
	want transfercore.Class
}

// testExpectExit runs op against a fake that answers with the exit code.
func testExpectExit(t *testing.T, code int, op func(*fakeRunner)) {
	t.Helper()
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return code, nil
	}}
	op(f)
}

var testPayload = []byte("hello \x00\xff binary\npayload bytes\n")
