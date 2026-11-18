// Package sshfixture provides the shared loopback SSH server used by the
// owner/connect test suites. It mirrors the previous package main fixture:
// nativeGuardSSHReply, syntheticLiveReply and syntheticSSHHold were copied
// verbatim; the originating root test files remove their originals once every
// suite owner has migrated.
package sshfixture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// ConnectPassword is the password credential the loopback server accepts
	// for the "second" account; suites assert on this exact value.
	ConnectPassword = "synthetic SSH account password"
	// Used only inside nativeGuardSSHReply below; not exported because
	// consumers do not compare these values through the fixture.
	nativeGuardCommand         = "ssjack-ci-known-literal-output"
	nativeGuardAddedCredential = "synthetic keeper MCP credential"
)

// SSHHold is a synthetic-live session held open until the suite releases it or
// the underlying SSH connection ends.
type SSHHold struct {
	identity       string
	connectionDone <-chan struct{}
}

func (hold SSHHold) Alive() bool {
	select {
	case <-hold.connectionDone:
		return false
	default:
		return true
	}
}

func (hold SSHHold) Identity() string { return hold.identity }

// LoopbackSSH is a synthetic SSH server on 127.0.0.1 inside the test process.
// It records only handshakes that completed authentication, so a client that
// rejects the host key never shows up in the records.
type LoopbackSSH struct {
	listener net.Listener
	config   *ssh.ServerConfig
	// HostKey is exposed because suites pin it as the client's known host key.
	HostKey     ssh.PublicKey
	marker      string
	wg          sync.WaitGroup
	mu          sync.Mutex
	conns       map[net.Conn]struct{}
	records     []string
	identities  []string
	exits       []uint32
	passwords   map[string]string
	holdStarted chan SSHHold
	holdRelease chan struct{}
	holdOnce    sync.Once
	accepted    int // raw TCP connections, counted before any SSH handshake
	stopped     bool
}

func StartLoopbackSSH(t *testing.T, allowed ssh.PublicKey, password, marker string) *LoopbackSSH {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	var server *LoopbackSSH
	accepted := func(method, identity string) (*ssh.Permissions, error) {
		return &ssh.Permissions{Extensions: map[string]string{"method": method, "identity": identity}}, nil
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, attempt []byte) (*ssh.Permissions, error) {
			if c.User() == "second" && server != nil {
				server.mu.Lock()
				identity := ""
				for candidate, label := range server.passwords {
					if subtle.ConstantTimeCompare(attempt, []byte(candidate)) == 1 {
						identity = label
					}
				}
				server.mu.Unlock()
				if identity != "" {
					return accepted("password", identity)
				}
			}
			return nil, errors.New("rejected")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return accepted("publickey", "key")
			}
			return nil, errors.New("rejected")
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server = &LoopbackSSH{
		listener: listener, config: config, HostKey: signer.PublicKey(), marker: marker,
		conns: make(map[net.Conn]struct{}), passwords: map[string]string{password: "default"},
		holdStarted: make(chan SSHHold, 8), holdRelease: make(chan struct{}),
	}
	server.wg.Add(1)
	go server.accept()
	t.Cleanup(server.Stop)
	return server
}

func (s *LoopbackSSH) Address() string { return s.listener.Addr().String() }

func (s *LoopbackSSH) SetPasswordLabel(password, label string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled {
		s.passwords[password] = label
	} else {
		delete(s.passwords, password)
	}
}

func (s *LoopbackSSH) HasIdentityLabel(want string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, identity := range s.identities {
		if identity == want {
			return true
		}
	}
	return false
}

func (s *LoopbackSSH) ReleaseSyntheticHolds() {
	s.holdOnce.Do(func() { close(s.holdRelease) })
}

func (s *LoopbackSSH) WaitSyntheticHold(ctx context.Context) (SSHHold, error) {
	select {
	case hold := <-s.holdStarted:
		return hold, nil
	case <-ctx.Done():
		return SSHHold{}, ctx.Err()
	}
}

func (s *LoopbackSSH) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepted++
		s.mu.Unlock()
		if !s.track(conn) {
			conn.Close()
			return
		}
		s.wg.Add(1)
		go s.serve(conn)
	}
}

func (s *LoopbackSSH) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *LoopbackSSH) Stop() {
	s.listener.Close()
	s.ReleaseSyntheticHolds()
	s.mu.Lock()
	s.stopped = true
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// AcceptedConnections returns how many TCP connections the listener accepted.
func (s *LoopbackSSH) AcceptedConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// Authentications returns "login|method" entries, sorted.
func (s *LoopbackSSH) Authentications() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := append([]string(nil), s.records...)
	sort.Strings(result)
	return result
}

func (s *LoopbackSSH) ExitStatuses() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.exits...)
}

func (s *LoopbackSSH) serve(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	// The deadline bounds only the handshake; sessions end by exit or stop().
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	connection, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	defer connection.Close()
	connectionDone := make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = connection.Wait()
		close(connectionDone)
	}()
	s.mu.Lock()
	s.identities = append(s.identities, connection.User()+"|"+connection.Permissions.Extensions["identity"])
	s.records = append(s.records, connection.User()+"|"+connection.Permissions.Extensions["method"])
	s.mu.Unlock()
	// Helper goroutines join s.wg: serve holds a count, so Add cannot race Wait,
	// and both end once the connection (closed by serve or stop) terminates.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ssh.DiscardRequests(requests)
	}()
	for channel := range channels {
		if channel.ChannelType() != "session" {
			channel.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		s.session(connection.User(), connection.Permissions.Extensions["identity"], channel, connectionDone)
	}
}

func (s *LoopbackSSH) session(login, identity string, opened ssh.NewChannel, connectionDone <-chan struct{}) {
	channel, requests, err := opened.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	shell, finished := make(chan struct{}), make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(finished)
		var once sync.Once
		for request := range requests {
			if request.Type == "exec" && (nativeGuardSSHReply(s, channel, request) || syntheticLiveReply(s, identity, channel, request, connectionDone)) {
				return
			}
			ok := request.Type == "pty-req" || request.Type == "shell"
			if request.Type == "shell" {
				once.Do(func() { close(shell) })
			}
			if request.WantReply {
				request.Reply(ok, nil)
			}
		}
	}()
	select {
	case <-shell:
	case <-finished:
		return
	}
	fmt.Fprintf(channel, "SYNTHETIC-SSH-READY user=%s marker=%s\r\n", login, s.marker)
	// A raw client terminal sends CR; accept CR or LF as the line end.
	reader := bufio.NewReader(channel)
	var line []byte
	for {
		next, err := reader.ReadByte()
		if err != nil {
			return
		}
		if next != '\r' && next != '\n' {
			if line = append(line, next); len(line) > 4096 {
				return
			}
			continue
		}
		text := string(line)
		line = line[:0]
		switch text {
		case "":
		case "exit":
			if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err == nil {
				s.mu.Lock()
				s.exits = append(s.exits, 0)
				s.mu.Unlock()
			}
			return
		default:
			fmt.Fprintf(channel, "ECHO:%s\r\n", text)
		}
	}
}

func nativeGuardSSHReply(server *LoopbackSSH, channel ssh.Channel, request *ssh.Request) bool {
	var command struct{ Command string }
	if server.marker != "owner-control" || ssh.Unmarshal(request.Payload, &command) != nil || (command.Command != nativeGuardCommand && command.Command != nativeGuardCommand+"-refresh") {
		return false
	}
	if request.WantReply {
		_ = request.Reply(true, nil)
	}
	output := []byte(ConnectPassword + "|")
	if command.Command == nativeGuardCommand+"-refresh" {
		output = append(output, []byte(nativeGuardAddedCredential+"|")...)
	}
	output = append(output, 255)
	for _, value := range output {
		if _, err := channel.Write([]byte{value}); err != nil {
			return true
		}
	}
	_, _ = channel.Stderr().Write(append([]byte(ConnectPassword+"|"), 254))
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{23}))
	_ = channel.Close()
	return true
}

func syntheticLiveReply(server *LoopbackSSH, identity string, channel ssh.Channel, request *ssh.Request, connectionDone <-chan struct{}) bool {
	var command struct{ Command string }
	if server.marker != "owner-control" || ssh.Unmarshal(request.Payload, &command) != nil ||
		(command.Command != "synthetic-live-hold" && command.Command != "synthetic-live-once") {
		return false
	}
	if request.WantReply {
		_ = request.Reply(true, nil)
	}
	if _, err := fmt.Fprintf(channel, "SYNTHETIC-LIVE:%s\n", identity); err != nil {
		return true
	}
	if command.Command == "synthetic-live-hold" {
		hold := SSHHold{identity: identity, connectionDone: connectionDone}
		select {
		case server.holdStarted <- hold:
		case <-connectionDone:
			return true
		}
		select {
		case <-server.holdRelease:
		case <-connectionDone:
			return true
		}
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	_ = channel.Close()
	return true
}
