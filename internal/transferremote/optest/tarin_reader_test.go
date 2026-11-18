package optest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferremote"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/tree"
)

var errTarInTestSource = errors.New("secret-marker: source read failed")

type tarInOneShotErrorReader struct {
	data           []byte
	err            error
	done           bool
	combineWithEOF bool
}

func (r *tarInOneShotErrorReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		if r.combineWithEOF && len(r.data) == 0 {
			r.done = true
			return n, r.err
		}
		return n, nil
	}
	if !r.done {
		r.done = true
		return 0, r.err
	}
	return 0, io.EOF
}

func TestTarInTracksOneShotSourceErrors(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{name: "before 1024", data: bytes.Repeat([]byte{0x7f}, 512)},
		{name: "1024 zero bytes with error", data: make([]byte, 1024)},
		{name: "exactly 1025 bytes with error", data: bytes.Repeat([]byte{0x31}, 1025)},
		{name: "after prefix with final bytes and error", data: bytes.Repeat([]byte{0x42}, 1500)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded []byte
			var forwardedErr error
			f := &fakeRunner{Respond: func(_ string, stdin io.Reader, _, _ io.Writer) (int, error) {
				if stdin == nil {
					t.Fatal("TarIn passed nil stdin for a non-nil source")
				}
				forwarded, forwardedErr = io.ReadAll(stdin)
				return 0, nil // The runner ignores an stdin read failure.
			}}
			source := &tarInOneShotErrorReader{
				data:           append([]byte(nil), tc.data...),
				err:            errTarInTestSource,
				combineWithEOF: true,
			}
			err := New(f.Run, "t", sampleLimits()).TarIn(context.Background(), "/srv/tree", source)
			if err == nil {
				t.Fatal("TarIn error = nil, want tracked source read failure")
			}
			var classErr *transfercore.Error
			if !errors.As(err, &classErr) || classErr.Class != transfercore.ClassRemoteFailed {
				t.Fatalf("TarIn error = %T %v, want ClassRemoteFailed", err, err)
			}
			if strings.Contains(err.Error(), "secret-marker") {
				t.Fatalf("TarIn exposed source error text: %v", err)
			}
			if forwardedErr == nil {
				t.Fatal("stdin read error = nil, want one-shot source error")
			}
			if strings.Contains(forwardedErr.Error(), "secret-marker") {
				t.Fatalf("stdin read exposed source error text: %v", forwardedErr)
			}
			if !bytes.Equal(forwarded, tc.data) {
				t.Fatalf("forwarded %d bytes, want all %d source bytes", len(forwarded), len(tc.data))
			}
			var afterFailure [1]byte
			if n, readErr := source.Read(afterFailure[:]); n != 0 || !errors.Is(readErr, io.EOF) {
				t.Fatalf("source read after failure = (%d, %v), want (0, EOF)", n, readErr)
			}
			commands := f.Recorded()
			want := fmt.Sprintf(tree.TarInTemplate, core.ShellQuote("/srv/tree"))
			if len(commands) != 1 || commands[0] != want {
				t.Fatalf("commands = %#v, want original tar script %q", commands, want)
			}
		})
	}
}

func TestTarInCanonicalEmptyArchiveRequiresActualEOF(t *testing.T) {
	f := &fakeRunner{Respond: func(command string, stdin io.Reader, _, _ io.Writer) (int, error) {
		if stdin != nil {
			t.Errorf("canonical empty archive stdin = %T, want nil", stdin)
		}
		return 0, nil
	}}
	if err := New(f.Run, "t", sampleLimits()).TarIn(context.Background(), "/srv/tree", bytes.NewReader(make([]byte, 1024))); err != nil {
		t.Fatalf("TarIn canonical empty archive = %v, want nil", err)
	}
	commands := f.Recorded()
	want := fmt.Sprintf(tree.TarInEmptyTemplate, core.ShellQuote("/srv/tree"))
	if len(commands) != 1 || commands[0] != want {
		t.Fatalf("commands = %#v, want root-only script %q", commands, want)
	}
}

func TestTarInOrdinaryEOFStreamsKeepTarScriptAndBytes(t *testing.T) {
	for _, size := range []int{1023, 1025} {
		t.Run(fmt.Sprintf("%d zero bytes", size), func(t *testing.T) {
			payload := make([]byte, size)
			var forwarded []byte
			f := &fakeRunner{Respond: func(_ string, stdin io.Reader, _, _ io.Writer) (int, error) {
				if stdin == nil {
					t.Fatal("TarIn passed nil stdin for a non-nil source")
				}
				forwarded, _ = io.ReadAll(stdin)
				return 0, nil
			}}
			if err := New(f.Run, "t", sampleLimits()).TarIn(context.Background(), "/srv/tree", bytes.NewReader(payload)); err != nil {
				t.Fatalf("TarIn = %v, want nil", err)
			}
			if !bytes.Equal(forwarded, payload) {
				t.Fatalf("forwarded %d bytes, want %d", len(forwarded), size)
			}
			commands := f.Recorded()
			want := fmt.Sprintf(tree.TarInTemplate, core.ShellQuote("/srv/tree"))
			if len(commands) != 1 || commands[0] != want {
				t.Fatalf("commands = %#v, want original tar script %q", commands, want)
			}
		})
	}
}
