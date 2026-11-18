package core

import (
	"bytes"
	"errors"
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
		if got := ShellQuote(c.in); got != c.want {
			t.Errorf("ShellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCheckRemotePath(t *testing.T) {
	limits := sampleLimits()
	for _, p := range []string{"/a/b", "/a b/c"} {
		if err := CheckRemotePath(p, limits); err != nil {
			t.Errorf("CheckRemotePath(%q) = %v, want nil", p, err)
		}
	}
	deep := "/" + strings.Repeat("a/", 65) + "z"
	for _, p := range []string{
		"a/b", "/a/../b", "/a//b", "/", "/a/b/", "/a/b\\c", "/a\nb", "/a\tb",
		"/a\x00b", "", "/" + strings.Repeat("a", 2000), deep,
	} {
		err := CheckRemotePath(p, limits)
		expectClass(t, err, transfercore.ClassRefusedPath)
	}
}

func TestClassErrorMapping(t *testing.T) {
	cases := []struct {
		code int
		want transfercore.Class
		msg  string
	}{
		{20, transfercore.ClassUnsupportedRemote, MsgUnsupported},
		{126, transfercore.ClassUnsupportedRemote, MsgUnsupported},
		{127, transfercore.ClassUnsupportedRemote, MsgUnsupported},
		{21, transfercore.ClassRefusedPath, MsgRefused},
		{22, transfercore.ClassExists, MsgExists},
		{23, transfercore.ClassIntegrity, MsgIntegrity},
		{24, transfercore.ClassRemoteFailed, MsgRemoteFailed},
		{25, transfercore.ClassRemoteFailed, MsgRemoteFailed},
		{1, transfercore.ClassRemoteFailed, MsgRemoteFailed},
		{255, transfercore.ClassRemoteFailed, MsgRemoteFailed},
		{-1, transfercore.ClassRemoteFailed, MsgRemoteFailed},
	}
	for _, c := range cases {
		err := ClassError(c.code)
		expectClass(t, err, c.want)
		expectCode(t, err, c.code)
		var e *transfercore.Error
		if !errors.As(err, &e) || e.Message != c.msg {
			t.Errorf("code %d: message = %q, want %q", c.code, e.Message, c.msg)
		}
	}
}

func TestStderrSinkAndBoundedWriter(t *testing.T) {
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

}

func TestStagingNamePattern(t *testing.T) {
	a, err := NewStagingName()
	if err != nil {
		t.Fatalf("newStagingName: %v", err)
	}
	b, err := NewStagingName()
	if err != nil {
		t.Fatalf("newStagingName: %v", err)
	}
	if a == b {
		t.Errorf("two staging names are equal: %q", a)
	}
	for _, n := range []string{a, b} {
		if !ValidStagingName(n) {
			t.Errorf("ValidStagingName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{
		"wrong-prefix-0123456789abcdef",
		StagingPrefix + "0123456789abcdef0",
		StagingPrefix + "ABCDEF0123456789",
		StagingPrefix + "0123456789abcdeg",
	} {
		if ValidStagingName(n) {
			t.Errorf("ValidStagingName(%q) = true, want false", n)
		}
	}
}
