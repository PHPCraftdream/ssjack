package main

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

// loopbackSSH is a synthetic SSH server on 127.0.0.1 inside the test process.
// It records only handshakes that completed authentication, so a client that
// rejects the host key never shows up in the records.
type loopbackSSH struct {
	listener    net.Listener
	config      *ssh.ServerConfig
	hostKey     ssh.PublicKey
	marker      string
	wg          sync.WaitGroup
	mu          sync.Mutex
	conns       map[net.Conn]struct{}
	records     []string
	identities  []string
	exits       []uint32
	passwords   map[string]string
	holdStarted chan syntheticSSHHold
	holdRelease chan struct{}
	holdOnce    sync.Once
	accepted    int // raw TCP connections, counted before any SSH handshake
	stopped     bool
}

func startLoopbackSSH(t *testing.T, allowed ssh.PublicKey, password, marker string) *loopbackSSH {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	var server *loopbackSSH
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
	server = &loopbackSSH{
		listener: listener, config: config, hostKey: signer.PublicKey(), marker: marker,
		conns: make(map[net.Conn]struct{}), passwords: map[string]string{password: "default"},
		holdStarted: make(chan syntheticSSHHold, 8), holdRelease: make(chan struct{}),
	}
	server.wg.Add(1)
	go server.accept()
	t.Cleanup(server.stop)
	return server
}

func (s *loopbackSSH) address() string { return s.listener.Addr().String() }

func (s *loopbackSSH) setPasswordLabel(password, label string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled {
		s.passwords[password] = label
	} else {
		delete(s.passwords, password)
	}
}

func (s *loopbackSSH) hasIdentityLabel(want string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, identity := range s.identities {
		if identity == want {
			return true
		}
	}
	return false
}
func (s *loopbackSSH) releaseSyntheticHolds() {
	s.holdOnce.Do(func() { close(s.holdRelease) })
}

func (s *loopbackSSH) waitSyntheticHold(ctx context.Context) (syntheticSSHHold, error) {
	select {
	case hold := <-s.holdStarted:
		return hold, nil
	case <-ctx.Done():
		return syntheticSSHHold{}, ctx.Err()
	}
}

func (s *loopbackSSH) accept() {
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

func (s *loopbackSSH) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *loopbackSSH) stop() {
	s.listener.Close()
	s.releaseSyntheticHolds()
	s.mu.Lock()
	s.stopped = true
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// acceptedConnections returns how many TCP connections the listener accepted.
func (s *loopbackSSH) acceptedConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// authentications returns "login|method" entries, sorted.
func (s *loopbackSSH) authentications() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := append([]string(nil), s.records...)
	sort.Strings(result)
	return result
}

func (s *loopbackSSH) exitStatuses() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.exits...)
}

func (s *loopbackSSH) serve(conn net.Conn) {
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

func (s *loopbackSSH) session(login, identity string, opened ssh.NewChannel, connectionDone <-chan struct{}) {
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
