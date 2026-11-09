package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestShellStdinEOFReachesServerAndPumpIsJoined(t *testing.T) {
	_, signer := testSigner(t)
	address, host, _ := shellServer(t, signer.PublicKey(), false)
	src := newInputSource()
	src.closeInput()
	in := src.newInput()
	resize := make(chan WindowSize, 1)
	resize <- WindowSize{Width: 100, Height: 30}
	close(resize)
	var stdout bytes.Buffer
	code, err := Shell(context.Background(), ShellOptions{Address: address, Config: shellClientConfig(signer, host),
		Term: "xterm", Size: WindowSize{80, 24}, Resize: resize, Stdin: in, Stdout: &stdout, Stderr: io.Discard})
	if err != nil || code != 7 || stdout.String() != "output:" || in.inflight.Load() != 0 {
		t.Fatalf("EOF: code=%d err=%v out=%q inflight=%d", code, err, stdout.String(), in.inflight.Load())
	}
}

func TestShellEarlyExitCancelsBlockedReadAndKeepsLaterInput(t *testing.T) {
	_, signer := testSigner(t)
	release := make(chan struct{})
	address, host, _ := miniServer(t, signer.PublicKey(), release)
	src := newInputSource()
	in1 := src.newInput()
	first := startShell(context.Background(), address, shellClientConfig(signer, host), in1)
	waitFor(t, "first Read", func() bool { return in1.reads.Load() > 0 })
	close(release)
	res := await(t, first)
	if res.code != 3 || res.err != nil || in1.cancels.Load() == 0 || in1.inflight.Load() != 0 {
		t.Fatalf("early exit: %+v cancels=%d inflight=%d", res, in1.cancels.Load(), in1.inflight.Load())
	}
	// A key typed between sessions must reach the next session, not the first.
	src.push("x")
	src.closeInput()
	address2, host2, received2 := miniServer(t, signer.PublicKey(), nil)
	res = await(t, startShell(context.Background(), address2, shellClientConfig(signer, host2), src.newInput()))
	if res.code != 0 || res.err != nil {
		t.Fatalf("second session: %+v", res)
	}
	select {
	case got := <-received2:
		if string(got) != "x" {
			t.Fatalf("second session received %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second server received nothing")
	}
}

type trackedReader struct {
	r        io.Reader
	inflight atomic.Int32
}

func (r *trackedReader) Read(p []byte) (int, error) {
	r.inflight.Add(1)
	defer r.inflight.Add(-1)
	return r.r.Read(p)
}

func TestShellReportsUncancelableInputWithoutHanging(t *testing.T) {
	previous := inputReleaseTimeout
	inputReleaseTimeout = 100 * time.Millisecond
	t.Cleanup(func() { inputReleaseTimeout = previous })
	_, signer := testSigner(t)
	release := make(chan struct{})
	close(release)
	address, host, _ := miniServer(t, signer.PublicKey(), release)
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	in := &trackedReader{r: pr}
	res := await(t, startShell(context.Background(), address, shellClientConfig(signer, host), in))
	if res.code != 3 || !errors.Is(res.err, ErrInputNotReleased) {
		t.Fatalf("uncancelable input: %+v", res)
	}
	pw.Close()
	waitFor(t, "pump Read to end", func() bool { return in.inflight.Load() == 0 })
}

func TestShellContextCancellationJoinsPump(t *testing.T) {
	_, signer := testSigner(t)
	address, host, events := shellServer(t, signer.PublicKey(), false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := newInputSource().newInput()
	finished := startShell(ctx, address, shellClientConfig(signer, host), in)
	timer := time.After(15 * time.Second)
	for started := false; !started; {
		select {
		case event := <-events:
			started = event.kind == "shell"
		case <-timer:
			t.Fatal("SSH shell did not start")
		}
	}
	waitFor(t, "first Read", func() bool { return in.reads.Load() > 0 })
	cancel()
	res := await(t, finished)
	if !errors.Is(res.err, context.Canceled) || errors.Is(res.err, ErrInputNotReleased) || in.inflight.Load() != 0 {
		t.Fatalf("cancellation: %+v inflight=%d", res, in.inflight.Load())
	}
}

func TestShellSetupFailuresNeverReadStdin(t *testing.T) {
	_, signer := testSigner(t)
	for _, name := range []string{"pty", "host", "ready"} {
		address, host, _ := shellServer(t, signer.PublicKey(), name == "pty")
		if name == "host" {
			_, wrong := testSigner(t)
			host = wrong.PublicKey()
		}
		opts := ShellOptions{Address: address, Config: shellClientConfig(signer, host), Term: "xterm",
			Size: WindowSize{80, 24}, Stdout: io.Discard, Stderr: io.Discard}
		if name == "ready" {
			opts.Ready = func() error { return errors.New("ready failed") }
		}
		in := newInputSource().newInput()
		opts.Stdin = in
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err := Shell(ctx, opts)
		cancel()
		if err == nil || in.reads.Load() != 0 || errors.Is(err, ErrInputNotReleased) {
			t.Fatalf("%s: err=%v reads=%d", name, err, in.reads.Load())
		}
	}
}

// A Cancel that never returns must not defeat the single release bound, even
// when the pump already joined (old code called Cancel synchronously and hung).
func TestShellBlockingCancelIsReportedNotReleased(t *testing.T) {
	for _, mode := range []string{"eof", "unblock"} {
		t.Run(mode, func(t *testing.T) {
			previous := inputReleaseTimeout
			inputReleaseTimeout = 100 * time.Millisecond
			t.Cleanup(func() { inputReleaseTimeout = previous })
			_, signer := testSigner(t)
			release := make(chan struct{})
			close(release)
			address, host, _ := miniServer(t, signer.PublicKey(), release)
			in := newStuckCancelInput(mode, 0)
			start := time.Now()
			res := await(t, startShell(context.Background(), address, shellClientConfig(signer, host), in))
			if elapsed := time.Since(start); res.code != 3 || !errors.Is(res.err, ErrInputNotReleased) || elapsed > 5*time.Second {
				t.Fatalf("blocking Cancel: %+v elapsed=%v", res, elapsed)
			}
			close(in.unblock)
			waitFor(t, "Cancel and Read to end", func() bool { return in.cancelOut.Load() == 1 && in.inflight.Load() == 0 })
		})
	}
}

func TestShellSlowCancelStillReportsRelease(t *testing.T) {
	previous := inputReleaseTimeout
	inputReleaseTimeout = time.Second
	t.Cleanup(func() { inputReleaseTimeout = previous })
	_, signer := testSigner(t)
	release := make(chan struct{})
	close(release)
	address, host, _ := miniServer(t, signer.PublicKey(), release)
	in := newStuckCancelInput("cancel", 20*time.Millisecond)
	res := await(t, startShell(context.Background(), address, shellClientConfig(signer, host), in))
	if res.code != 3 || res.err != nil || in.cancelOut.Load() != 1 || in.inflight.Load() != 0 {
		t.Fatalf("slow Cancel: %+v out=%d inflight=%d", res, in.cancelOut.Load(), in.inflight.Load())
	}
}
