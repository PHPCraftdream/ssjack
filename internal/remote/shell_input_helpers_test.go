package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
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
