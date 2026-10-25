package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

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
	code, err := Shell(ctx, ShellOptions{
		Address: address, Config: shellClientConfig(signer, host), Term: "xterm-256color",
		Size: WindowSize{Width: 80, Height: 24}, Resize: resize,
		Stdin: bytes.NewBufferString("typed input"), Stdout: &stdout, Stderr: &stderr,
		Ready: func() error { ready++; return nil },
	})
	if err != nil || code != 7 || ready != 1 || stdout.String() != "output:typed input" || stderr.String() != "stderr" {
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
	finished := make(chan error, 1)
	go func() {
		_, err := Shell(ctx, ShellOptions{Address: address, Config: shellClientConfig(signer, host),
			Term: "xterm", Size: WindowSize{80, 24}, Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard})
		finished <- err
	}()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.kind == "shell" {
				cancel()
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
