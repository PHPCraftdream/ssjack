package transferremote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain", `'plain'`},
		{"it's", `'it'\''s'`},
		{"", `''`},
		{"a b/c $(d)", `'a b/c $(d)'`},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCheckRemotePath(t *testing.T) {
	limits := sampleLimits()
	for _, p := range []string{"/a/b", "/a b/c"} {
		if err := checkRemotePath(p, limits); err != nil {
			t.Errorf("checkRemotePath(%q) = %v, want nil", p, err)
		}
	}
	deep := "/" + strings.Repeat("a/", 65) + "z"
	for _, p := range []string{
		"a/b", "/a/../b", "/a//b", "/", "/a/b/", "/a/b\\c", "/a\nb", "/a\tb",
		"/a\x00b", "", "/" + strings.Repeat("a", 2000), deep,
	} {
		err := checkRemotePath(p, limits)
		expectClass(t, err, transfercore.ClassRefusedPath)
	}
}

func TestClassErrorMapping(t *testing.T) {
	cases := []struct {
		code int
		want transfercore.Class
		msg  string
	}{
		{20, transfercore.ClassUnsupportedRemote, msgUnsupported},
		{126, transfercore.ClassUnsupportedRemote, msgUnsupported},
		{127, transfercore.ClassUnsupportedRemote, msgUnsupported},
		{21, transfercore.ClassRefusedPath, msgRefused},
		{22, transfercore.ClassExists, msgExists},
		{23, transfercore.ClassIntegrity, msgIntegrity},
		{24, transfercore.ClassRemoteFailed, msgRemoteFailed},
		{25, transfercore.ClassRemoteFailed, msgRemoteFailed},
		{1, transfercore.ClassRemoteFailed, msgRemoteFailed},
		{255, transfercore.ClassRemoteFailed, msgRemoteFailed},
		{-1, transfercore.ClassRemoteFailed, msgRemoteFailed},
	}
	for _, c := range cases {
		err := classError(c.code)
		expectClass(t, err, c.want)
		expectCode(t, err, c.code)
		var e *transfercore.Error
		if !errors.As(err, &e) || e.Message != c.msg {
			t.Errorf("code %d: message = %q, want %q", c.code, e.Message, c.msg)
		}
	}
}

func TestExecuteCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// Success wins over late cancellation.
	f1 := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, err := io.WriteString(stdout, "SSJACK-CAPS sha256sum t gnu\n")
		return 0, err
	}}
	r1 := New(f1.run, "t", sampleLimits())
	if err := r1.Probe(cancelled); err != nil {
		t.Fatalf("Probe with cancelled context and success = %v, want nil", err)
	}

	// A failed exit code under a cancelled context is ClassCancelled.
	f2 := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 21, nil
	}}
	r2 := New(f2.run, "t", sampleLimits())
	testWantErr(t, r2.Probe(cancelled), transfercore.ClassCancelled, msgCancelled, -1)

	// A transport error under a cancelled context is ClassCancelled.
	f3 := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 0, errors.New("connection lost")
	}}
	r3 := New(f3.run, "t", sampleLimits())
	testWantErr(t, r3.Probe(cancelled), transfercore.ClassCancelled, msgCancelled, -1)

	// A transport error on a live context is ClassRemoteFailed.
	r4 := New(f3.run, "t", sampleLimits())
	testWantErr(t, r4.Probe(context.Background()), transfercore.ClassRemoteFailed, msgTransport, -1)

	// A failed exit code on a live context keeps its class and exit code.
	r5 := New(f2.run, "t", sampleLimits())
	testWantErr(t, r5.Probe(context.Background()), transfercore.ClassRefusedPath, msgRefused, 21)
}

func TestStderrBounded(t *testing.T) {
	marker := bytes.Repeat([]byte("STDERR-MARKER"), 5325)[:64*1024]
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := stderr.Write(marker); err != nil {
			t.Errorf("writing stderr: %v", err)
		}
		return 24, nil
	}}
	r := New(f.run, "t", sampleLimits())
	_, err := r.WriteFile(context.Background(), "/dest/f", strings.NewReader("x"), false)
	testWantErr(t, err, transfercore.ClassRemoteFailed, msgRemoteFailed, 24)
	if strings.Contains(err.Error(), "STDERR-MARKER") {
		t.Errorf("error message leaked stderr content: %q", err.Error())
	}

	// An oversized stderr does not hide the exit code: 21 stays ClassRefusedPath.
	f2 := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := stderr.Write(marker); err != nil {
			t.Errorf("writing stderr: %v", err)
		}
		return 21, nil
	}}
	r2 := New(f2.run, "t", sampleLimits())
	_, err = r2.WriteFile(context.Background(), "/dest/f", strings.NewReader("x"), false)
	testWantErr(t, err, transfercore.ClassRefusedPath, msgRefused, 21)

	// stderrSink accepts every write, keeps at most stderrLimit bytes.
	var sink stderrSink
	chunk := bytes.Repeat([]byte("a"), 10*1024)
	for i := 0; i < 3; i++ {
		n, werr := sink.Write(chunk)
		if werr != nil || n != len(chunk) {
			t.Fatalf("stderrSink write returned (%d, %v), want (%d, nil)", n, werr, len(chunk))
		}
	}
	if sink.buf.Len() != stderrLimit {
		t.Errorf("stderrSink kept %d bytes, want %d", sink.buf.Len(), stderrLimit)
	}

	// boundedWriter is the listing-sink contract: an oversized write is
	// rejected, the overflow flag is set and runListed yields ClassLimit.
	var buf bytes.Buffer
	b := &boundedWriter{w: &buf, remaining: 4096}
	big := bytes.Repeat([]byte("a"), 10*1024)
	n, werr := b.Write(big)
	if werr == nil || !errors.Is(werr, errListingOverflow) {
		t.Errorf("oversized write error = %v, want overflow sentinel", werr)
	}
	if n != 0 {
		t.Errorf("oversized write reported %d bytes written, want 0", n)
	}
	if !b.overflow {
		t.Errorf("overflow flag not set after oversized write")
	}
	if buf.Len() != 0 {
		t.Errorf("underlying buffer has %d bytes after rejected write, want 0", buf.Len())
	}

	// A bounded listing that overflows yields ClassLimit with exit code 0.
	f3 := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := stdout.Write(bytes.Repeat([]byte("z"), 9000)); err != nil {
			return 0, err
		}
		return 0, nil
	}}
	r3 := New(f3.run, "t", sampleLimits())
	_, _, err = r3.StatFile(context.Background(), "/dest/f")
	testWantErr(t, err, transfercore.ClassLimit, msgLimit, 0)
}

func TestReadyChecks(t *testing.T) {
	r := New(nil, "t", sampleLimits())
	testWantErr(t, r.Probe(context.Background()), transfercore.ClassInternal, msgInternalRunner, -1)

	f := &fakeRunner{}
	r2 := New(f.run, "t", transfercore.Limits{})
	testWantErr(t, r2.Probe(context.Background()), transfercore.ClassInternal, msgInternalLimits, -1)
	if got := len(f.recorded()); got != 0 {
		t.Errorf("%d commands run with unready remote, want 0", got)
	}
}

func TestStagingNamePattern(t *testing.T) {
	a, err := newStagingName()
	if err != nil {
		t.Fatalf("newStagingName: %v", err)
	}
	b, err := newStagingName()
	if err != nil {
		t.Fatalf("newStagingName: %v", err)
	}
	if a == b {
		t.Errorf("two staging names are equal: %q", a)
	}
	for _, n := range []string{a, b} {
		if !validStagingName(n) {
			t.Errorf("validStagingName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{
		"wrong-prefix-0123456789abcdef",
		stagingPrefix + "0123456789abcdef0",
		stagingPrefix + "ABCDEF0123456789",
		stagingPrefix + "0123456789abcdeg",
	} {
		if validStagingName(n) {
			t.Errorf("validStagingName(%q) = true, want false", n)
		}
	}
}
