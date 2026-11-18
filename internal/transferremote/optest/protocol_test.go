package optest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	. "github.com/PHPCraftdream/ssjack/internal/transferremote"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

func TestExecuteCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// Success wins over late cancellation.
	f1 := &fakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, err := io.WriteString(stdout, "SSJACK-CAPS sha256sum t gnu names\n")
		return 0, err
	}}
	r1 := New(f1.Run, "t", sampleLimits())
	if err := r1.Probe(cancelled); err != nil {
		t.Fatalf("Probe with cancelled context and success = %v, want nil", err)
	}

	// A failed exit code under a cancelled context is ClassCancelled.
	f2 := &fakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 21, nil
	}}
	r2 := New(f2.Run, "t", sampleLimits())
	testWantErr(t, r2.Probe(cancelled), transfercore.ClassCancelled, core.MsgCancelled, -1)

	// A transport error under a cancelled context is ClassCancelled.
	f3 := &fakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		return 0, errors.New("connection lost")
	}}
	r3 := New(f3.Run, "t", sampleLimits())
	testWantErr(t, r3.Probe(cancelled), transfercore.ClassCancelled, core.MsgCancelled, -1)

	// A transport error on a live context is ClassRemoteFailed.
	r4 := New(f3.Run, "t", sampleLimits())
	testWantErr(t, r4.Probe(context.Background()), transfercore.ClassRemoteFailed, core.MsgTransport, -1)

	// A failed exit code on a live context keeps its class and exit code.
	r5 := New(f2.Run, "t", sampleLimits())
	testWantErr(t, r5.Probe(context.Background()), transfercore.ClassRefusedPath, core.MsgRefused, 21)
}

func TestStderrBounded(t *testing.T) {
	marker := bytes.Repeat([]byte("STDERR-MARKER"), 5325)[:64*1024]
	f := &fakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := stderr.Write(marker); err != nil {
			t.Errorf("writing stderr: %v", err)
		}
		return 24, nil
	}}
	r := New(f.Run, "t", sampleLimits())
	_, err := r.WriteFile(context.Background(), "/dest/f", strings.NewReader("x"), false)
	testWantErr(t, err, transfercore.ClassRemoteFailed, core.MsgRemoteFailed, 24)
	if strings.Contains(err.Error(), "STDERR-MARKER") {
		t.Errorf("error message leaked stderr content: %q", err.Error())
	}

	// An oversized stderr does not hide the exit code: 21 stays ClassRefusedPath.
	f2 := &fakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := stderr.Write(marker); err != nil {
			t.Errorf("writing stderr: %v", err)
		}
		return 21, nil
	}}
	r2 := New(f2.Run, "t", sampleLimits())
	_, err = r2.WriteFile(context.Background(), "/dest/f", strings.NewReader("x"), false)
	testWantErr(t, err, transfercore.ClassRefusedPath, core.MsgRefused, 21)

	// A bounded listing that overflows yields ClassLimit with exit code 0.
	f3 := &fakeRunner{Respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if _, err := stdout.Write(bytes.Repeat([]byte("z"), 9000)); err != nil {
			return 0, err
		}
		return 0, nil
	}}
	r3 := New(f3.Run, "t", sampleLimits())
	_, _, err = r3.StatFile(context.Background(), "/dest/f")
	testWantErr(t, err, transfercore.ClassLimit, core.MsgLimit, 0)
}

func TestReadyChecks(t *testing.T) {
	r := New(nil, "t", sampleLimits())
	testWantErr(t, r.Probe(context.Background()), transfercore.ClassInternal, core.MsgInternalRunner, -1)

	f := &fakeRunner{}
	r2 := New(f.Run, "t", transfercore.Limits{})
	testWantErr(t, r2.Probe(context.Background()), transfercore.ClassInternal, core.MsgInternalLimits, -1)
	if got := len(f.Recorded()); got != 0 {
		t.Errorf("%d commands run with unready remote, want 0", got)
	}
}
