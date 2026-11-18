package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

type shellEvent struct {
	kind          string
	width, height uint32
}

func shellServer(t *testing.T, allowed ssh.PublicKey, rejectPTY bool) (string, ssh.PublicKey, <-chan shellEvent) {
	t.Helper()
	_, host := testSigner(t)
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, errors.New("client key rejected")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	events := make(chan shellEvent, 8)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		closed := make(chan struct{})
		go func() { server.Wait(); close(closed) }()
		for next := range channels {
			if next.ChannelType() != "session" {
				next.Reject(ssh.UnknownChannelType, "")
				continue
			}
			channel, requests, err := next.Accept()
			if err != nil {
				return
			}
			resized := make(chan struct{})
			var once sync.Once
			for req := range requests {
				switch req.Type {
				case "pty-req":
					var pty struct {
						Term                         string
						Columns, Rows, Width, Height uint32
						Modes                        string
					}
					if err := ssh.Unmarshal(req.Payload, &pty); err != nil {
						req.Reply(false, nil)
						continue
					}
					events <- shellEvent{"pty", pty.Columns, pty.Rows}
					req.Reply(!rejectPTY, nil)
				case "shell":
					req.Reply(true, nil)
					events <- shellEvent{kind: "shell"}
					go func() {
						defer channel.Close()
						data, err := io.ReadAll(channel)
						if err != nil {
							return
						}
						select {
						case <-resized:
						case <-closed:
							return
						}
						channel.Write(append([]byte("output:"), data...))
						channel.Stderr().Write([]byte("stderr"))
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
					}()
				case "window-change":
					var size struct{ Columns, Rows, Width, Height uint32 }
					if ssh.Unmarshal(req.Payload, &size) == nil {
						events <- shellEvent{"resize", size.Columns, size.Rows}
						once.Do(func() { close(resized) })
					}
				default:
					req.Reply(false, nil)
				}
			}
			channel.Close()
		}
	}()
	return listener.Addr().String(), host.PublicKey(), events
}

func shellClientConfig(signer ssh.Signer, host ssh.PublicKey) *ssh.ClientConfig {
	return &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{sshauth.PublicKey(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), host.Marshal()) {
				return errors.New("wrong host key")
			}
			return nil
		}}
}

func TestInteractiveShellPTYResizeStreamsAndExit(t *testing.T) {
	_, signer := testSigner(t)
	address, host, events := shellServer(t, signer.PublicKey(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resize := make(chan WindowSize, 1)
	resize <- WindowSize{Width: 120, Height: 40}
	close(resize)
	var stdout, stderr bytes.Buffer
	ready := 0
	input := []byte("typed input|synthetic-known-literal|\x1b[?1049h\x1b[2J\x1b[Hnano\x1b[31m\x00\xff\x1b[0m\x1b[?1049l")
	code, err := Shell(ctx, ShellOptions{
		Address: address, Config: shellClientConfig(signer, host), Term: "xterm-256color",
		Size: WindowSize{Width: 80, Height: 24}, Resize: resize,
		Stdin: bytes.NewReader(input), Stdout: &stdout, Stderr: &stderr,
		Ready: func() error { ready++; return nil },
	})
	if err != nil || code != 7 || ready != 1 || !bytes.Equal(stdout.Bytes(), append([]byte("output:"), input...)) || stderr.String() != "stderr" {
		t.Fatalf("shell: code=%d err=%v ready=%d out=%q stderr=%q", code, err, ready, stdout.String(), stderr.String())
	}
	for _, want := range []shellEvent{{"pty", 80, 24}, {kind: "shell"}, {"resize", 120, 40}} {
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("event: got %+v, want %+v", got, want)
			}
		case <-ctx.Done():
			t.Fatal("missing SSH shell event")
		}
	}
}

func TestInteractiveShellCancellation(t *testing.T) {
	_, signer := testSigner(t)
	address, host, events := shellServer(t, signer.PublicKey(), false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	var mu sync.Mutex
	var transitions []string
	record := func(kind string) {
		mu.Lock()
		transitions = append(transitions, fmt.Sprintf("+%s %s", time.Since(start).Truncate(time.Millisecond), kind))
		mu.Unlock()
	}
	cancellation := "not yet issued"
	// Failure-only evidence: observed transitions, how cancellation was issued,
	// child process state (none: Shell is an in-process SSH client), and the
	// captured output tail.
	flakediag.OnFailure(t, func() string {
		mu.Lock()
		seen := append([]string(nil), transitions...)
		mu.Unlock()
		return flakediag.Join(
			fmt.Sprintf("cancellation: %s", cancellation),
			"child process: none (Shell runs an in-process SSH client, no os/exec)",
			"captured output: none (stdout/stderr use io.Discard)",
			fmt.Sprintf("transitions (%d):\n  %s", len(seen), strings.Join(seen, "\n  ")),
			fmt.Sprintf("goroutine dump:\n%s", flakediag.GoroutineDump(64*1024)),
		)
	})
	finished := make(chan error, 1)
	go func() {
		record("client goroutine started")
		_, err := Shell(ctx, ShellOptions{Address: address, Config: shellClientConfig(signer, host),
			Term: "xterm", Size: WindowSize{80, 24}, Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard})
		record("client returned")
		finished <- err
	}()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			record("server event " + event.kind)
			if event.kind == "shell" {
				cancellation = "ctx cancel (context.WithCancel) after server shell event"
				cancel()
				record("cancel issued")
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation: %v", err)
					}
				case <-timer.C:
					t.Fatal("SSH shell did not stop after cancellation")
				}
				return
			}
		case err := <-finished:
			t.Fatalf("shell stopped before cancellation: %v", err)
		case <-timer.C:
			t.Fatal("SSH shell did not start")
		}
	}
}

func TestInteractiveShellRejectsHostAndPTY(t *testing.T) {
	for _, rejectPTY := range []bool{false, true} {
		_, signer := testSigner(t)
		address, host, _ := shellServer(t, signer.PublicKey(), rejectPTY)
		if !rejectPTY {
			_, wrong := testSigner(t)
			host = wrong.PublicKey()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		ready := false
		_, err := Shell(ctx, ShellOptions{Address: address, Config: shellClientConfig(signer, host),
			Term: "xterm", Size: WindowSize{80, 24}, Ready: func() error { ready = true; return nil }})
		cancel()
		if err == nil || ready {
			t.Fatalf("invalid host or rejected PTY reached raw mode: err=%v ready=%v", err, ready)
		}
	}
}

func TestShellRejectsInvalidTerminalBeforeDial(t *testing.T) {
	for _, opts := range []ShellOptions{
		{},
		{Config: &ssh.ClientConfig{}, Term: "xterm", Size: WindowSize{80, 24}},
		{Config: &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}, Term: "xterm\n", Size: WindowSize{80, 24}},
	} {
		if _, err := Shell(context.Background(), opts); err == nil {
			t.Fatal("invalid shell options were accepted")
		}
	}
}

var errInputCanceled = errors.New("input canceled")

// inputSource models the terminal: bytes outlive any one reader.
type inputSource struct {
	mu   sync.Mutex
	cond *sync.Cond
	data []byte
	eof  bool
}

func newInputSource() *inputSource {
	s := &inputSource{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *inputSource) push(b string) {
	s.mu.Lock()
	s.data = append(s.data, b...)
	s.mu.Unlock()
	s.cond.Broadcast()
}

func (s *inputSource) closeInput() {
	s.mu.Lock()
	s.eof = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

// cancelableInput is one reader over a source; Cancel never consumes data.
type cancelableInput struct {
	src      *inputSource
	canceled bool
	reads    atomic.Int32
	inflight atomic.Int32
	cancels  atomic.Int32
}

func (s *inputSource) newInput() *cancelableInput { return &cancelableInput{src: s} }

func (c *cancelableInput) Read(p []byte) (int, error) {
	c.reads.Add(1)
	c.inflight.Add(1)
	defer c.inflight.Add(-1)
	c.src.mu.Lock()
	defer c.src.mu.Unlock()
	for {
		if c.canceled {
			return 0, errInputCanceled
		}
		if len(c.src.data) > 0 {
			n := copy(p, c.src.data)
			c.src.data = c.src.data[n:]
			return n, nil
		}
		if c.src.eof {
			return 0, io.EOF
		}
		c.src.cond.Wait()
	}
}

func (c *cancelableInput) Cancel() bool {
	c.src.mu.Lock()
	c.canceled = true
	c.src.mu.Unlock()
	c.src.cond.Broadcast()
	c.cancels.Add(1)
	return true
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	var attempts atomic.Int32
	// Failure-only evidence (what/timeout/elapsed/attempts/last state/goroutine
	// dump) is registered by flakediag when the deadline passes.
	done, _, _ := flakediag.WaitForDesc(t, what, 10*time.Second, func() (string, bool, error) {
		n := attempts.Add(1)
		ok := cond()
		return fmt.Sprintf("attempt %d: condition met=%v", n, ok), ok, nil
	})
	if !done {
		t.Fatalf("timed out waiting for %s", what)
	}
}

type shellResult struct {
	code int
	err  error
}

func startShell(ctx context.Context, address string, cfg *ssh.ClientConfig, in io.Reader) <-chan shellResult {
	out := make(chan shellResult, 1)
	go func() {
		code, err := Shell(ctx, ShellOptions{Address: address, Config: cfg, Term: "xterm",
			Size: WindowSize{80, 24}, Stdin: in, Stdout: io.Discard, Stderr: io.Discard})
		out <- shellResult{code, err}
	}()
	return out
}

func await(t *testing.T, ch <-chan shellResult) shellResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		flakediag.OnFailure(t, func() string {
			return fmt.Sprintf("await: waited 15s for Shell to return; goroutine dump:\n%s", flakediag.GoroutineDump(64*1024))
		})
		t.Fatal("Shell did not return")
		return shellResult{}
	}
}

// miniServer accepts one PTY shell. With release it exits (status 3) once
// release closes; without it, it exits (status 0) after stdin EOF and reports
// the bytes received.
func miniServer(t *testing.T, allowed ssh.PublicKey, release <-chan struct{}) (string, ssh.PublicKey, <-chan []byte) {
	t.Helper()
	_, host := testSigner(t)
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, errors.New("client key rejected")
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for next := range channels {
			if next.ChannelType() != "session" {
				next.Reject(ssh.UnknownChannelType, "")
				continue
			}
			channel, reqs, err := next.Accept()
			if err != nil {
				return
			}
			for req := range reqs {
				switch req.Type {
				case "pty-req":
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					go miniShell(ctx, channel, release, received)
				default:
					req.Reply(false, nil)
				}
			}
			channel.Close()
		}
	}()
	return listener.Addr().String(), host.PublicKey(), received
}

func miniShell(ctx context.Context, channel ssh.Channel, release <-chan struct{}, received chan<- []byte) {
	eof := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(channel); eof <- data }()
	var data []byte
	status := uint32(3)
	if release == nil {
		status = 0
		select {
		case data = <-eof:
		case <-ctx.Done():
			return
		}
	} else {
		select {
		case <-release:
		case <-ctx.Done():
			return
		}
	}
	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	channel.Close()
	if release == nil {
		received <- data
	}
}

// stuckCancelInput models an input whose Cancel can block. Read modes:
// "eof" returns at once, "unblock" waits for unblock, "cancel" waits for Cancel.
type stuckCancelInput struct {
	mode      string
	unblock   chan struct{}
	delay     time.Duration
	stop      chan struct{}
	once      sync.Once
	cancelIn  atomic.Int32
	cancelOut atomic.Int32
	inflight  atomic.Int32
}

func newStuckCancelInput(mode string, delay time.Duration) *stuckCancelInput {
	return &stuckCancelInput{mode: mode, delay: delay, unblock: make(chan struct{}), stop: make(chan struct{})}
}

func (s *stuckCancelInput) Read([]byte) (int, error) {
	s.inflight.Add(1)
	defer s.inflight.Add(-1)
	switch s.mode {
	case "unblock":
		<-s.unblock
	case "cancel":
		<-s.stop
		return 0, errInputCanceled
	}
	return 0, io.EOF
}

func (s *stuckCancelInput) Cancel() bool {
	s.cancelIn.Add(1)
	defer s.cancelOut.Add(1)
	time.Sleep(s.delay)
	if s.mode == "cancel" {
		s.once.Do(func() { close(s.stop) })
	} else {
		<-s.unblock
	}
	return true
}

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
