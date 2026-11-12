package ownerrotationtest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The server models the fixed add-key SSH request in memory; it never starts a
// shell or touches operating-system key files.
type rotationSSHFixture struct {
	listener    net.Listener
	hostKey     ssh.PublicKey
	hostPrivate []byte
	initialKey  string
	wg          sync.WaitGroup
	holdStarted chan struct{}
	holdRelease chan struct{}
	holdOnce    sync.Once
	holdLost    atomic.Bool

	mu        sync.Mutex // guards everything below
	keys      map[string]ssh.PublicKey
	auths     []string
	conns     map[net.Conn]struct{}
	stopped   bool
	mutations int
	loseAck   bool
	rejectNew bool
	afterAdd  func() error
	barrier   *addBarrier
}

// addBarrier holds one Add after its remote effect and before its acknowledgement.
type addBarrier struct {
	ctx      context.Context
	entered  chan struct{}
	release  chan struct{}
	enterOne sync.Once
	freeOne  sync.Once
}

func startRotationSSHFixture(t *testing.T, old ssh.PublicKey) *rotationSSHFixture {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		clear(hostPrivate)
		t.Fatal(err)
	}
	f := &rotationSSHFixture{hostKey: host.PublicKey(), hostPrivate: hostPrivate, keys: map[string]ssh.PublicKey{string(old.Marshal()): old}, initialKey: string(old.Marshal()), conns: make(map[net.Conn]struct{}), holdStarted: make(chan struct{}, 4), holdRelease: make(chan struct{})}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.keys[string(key.Marshal())]; !ok || (f.rejectNew && string(key.Marshal()) != f.initialKey) {
			return nil, fmt.Errorf("synthetic key refused")
		}
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": ssh.FingerprintSHA256(key), "user": meta.User()}}, nil
	}}
	config.AddHostKey(host)
	if f.listener, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		clear(hostPrivate)
		t.Fatal(err)
	}
	f.wg.Add(1)
	go f.accept(config)
	t.Cleanup(f.close)
	return f
}

// configure changes fixture behavior under the same lock the server goroutines use.
func (f *rotationSSHFixture) configure(update func(*rotationSSHFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	update(f)
}

func (f *rotationSSHFixture) address() string { return f.listener.Addr().String() }
func (f *rotationSSHFixture) accept(config *ssh.ServerConfig) {
	defer f.wg.Done()
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.stopped {
			f.mu.Unlock()
			_ = conn.Close()
			return
		}
		f.conns[conn] = struct{}{}
		f.mu.Unlock()
		f.wg.Add(1)
		go f.serve(conn, config)
	}
}
func (f *rotationSSHFixture) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer f.wg.Done()
	defer func() { f.mu.Lock(); delete(f.conns, conn); f.mu.Unlock(); _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	connection, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer connection.Close()
	finished := make(chan struct{})
	go func() { _ = connection.Wait(); close(finished) }()
	f.mu.Lock()
	f.auths = append(f.auths, connection.Permissions.Extensions["fingerprint"])
	f.mu.Unlock()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, reqs, err := channel.Accept()
		if err != nil {
			continue
		}
		for request := range reqs {
			var command struct{ Command string }
			switch {
			case request.Type == "shell":
				reply(request, true)
				_, _ = io.WriteString(ch, "SYNTHETIC-ROTATION-HUMAN-READY\n")
				f.serveHuman(ch)
			case request.Type == "exec" && ssh.Unmarshal(request.Payload, &command) == nil:
				reply(request, true)
				f.serveCommand(conn, ch, command.Command, finished)
			case request.Type == "exec":
				reply(request, false)
			default:
				reply(request, request.Type == "pty-req")
				continue
			}
			break
		}
		_ = ch.Close()
	}
}

func reply(request *ssh.Request, ok bool) {
	if request.WantReply {
		_ = request.Reply(ok, nil)
	}
}

func exitStatus(ch ssh.Channel, status uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

func (f *rotationSSHFixture) serveHuman(ch ssh.Channel) {
	reader := bufio.NewReader(ch)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "exit" {
			exitStatus(ch, 0)
			return
		}
		_, _ = io.WriteString(ch, "HUMAN-ECHO:"+strings.TrimSpace(line)+"\n")
	}
}
func (f *rotationSSHFixture) serveCommand(conn net.Conn, ch ssh.Channel, command string, finished <-chan struct{}) {
	switch command {
	case rotationAuthorizedScript:
		payload, err := io.ReadAll(ch)
		if err == nil {
			err = f.install(payload)
		}
		clear(payload)
		status := uint32(0)
		if err != nil {
			status = 1
		}
		f.mu.Lock()
		after, barrier, lose := f.afterAdd, f.barrier, f.loseAck
		f.mu.Unlock()
		if after != nil && after() != nil {
			status = 1
		}
		if barrier != nil {
			barrier.enterOne.Do(func() { close(barrier.entered) })
			select {
			case <-barrier.release:
			case <-barrier.ctx.Done():
			case <-finished:
			}
		}
		if lose {
			_ = conn.Close()
			return
		}
		exitStatus(ch, status)
	case "ssjack-ci-owner-rotation-hold":
		f.serveHold(ch, finished)
	case "ssjack-ci-owner-rotation-release":
		f.release()
		_, _ = io.WriteString(ch, "SYNTHETIC-ROTATION-RELEASED\n")
		exitStatus(ch, 0)
	case "ssjack-ci-owner-rotation-once":
		_, _ = io.WriteString(ch, "SYNTHETIC-ROTATION-JOB-OK\n")
		exitStatus(ch, 0)
	default:
		exitStatus(ch, 127)
	}
}

// publicLine accepts only a canonical, option-free authorized_keys line.
func publicLine(line string) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(ssh.MarshalAuthorizedKey(key), []byte(line+"\n")) {
		return nil, fmt.Errorf("invalid public line")
	}
	return key, nil
}

func (f *rotationSSHFixture) install(payload []byte) error {
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) != 2 {
		return fmt.Errorf("expected old/new public lines")
	}
	old, oldErr := publicLine(lines[0])
	next, nextErr := publicLine(lines[1])
	if oldErr != nil || nextErr != nil || bytes.Equal(old.Marshal(), next.Marshal()) {
		return fmt.Errorf("invalid old or replacement public line")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[string(old.Marshal())]; !ok {
		return fmt.Errorf("old key is not authorized")
	}
	f.keys[string(next.Marshal())] = next
	f.mutations++
	return nil
}

// armAddBarrier makes the next Add wait after its effect, until released.
func (f *rotationSSHFixture) armAddBarrier(t *testing.T, ctx context.Context) *addBarrier {
	t.Helper()
	barrier := &addBarrier{ctx: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	f.configure(func(f *rotationSSHFixture) { f.barrier = barrier })
	t.Cleanup(barrier.free)
	return barrier
}

func (b *addBarrier) wait(ctx context.Context) error {
	select {
	case <-b.entered:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *addBarrier) free() { b.freeOne.Do(func() { close(b.release) }) }

func (f *rotationSSHFixture) release() {
	f.holdOnce.Do(func() { close(f.holdRelease) })
}
func (f *rotationSSHFixture) close() {
	_ = f.listener.Close()
	f.release()
	f.mu.Lock()
	f.stopped = true
	for conn := range f.conns {
		_ = conn.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
	clear(f.hostPrivate)
}
