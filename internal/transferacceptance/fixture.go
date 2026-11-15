//go:build linux

package transferacceptance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ExecServer is an in-process SSH server whose exec handler really runs the
// received command with sh -c inside a sandbox directory: stdin, stdout,
// stderr and the exit status pass through byte-exactly. Faults are injected
// by command substring: a hold gate delays a command before it runs, a kill
// injection closes the transport once bytes are in flight, and a corruption
// injection flips one bit of the stream in flight.
type ExecServer struct {
	listener net.Listener
	sandbox  string
	env      []string
	hostKey  ssh.PublicKey
	client   ssh.Signer
	wg       sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	stopped  bool
	holds    map[string]chan struct{}
	entered  []string
	seen     chan string
	kill     injection
	corrupt  injection
	password string
}

// injection describes one fault and the command substring that arms it.
type injection struct {
	armed  bool
	match  string
	amount int64
}

// StartExecServer starts the fixture on the loopback interface and stops it
// during test cleanup. env replaces the environment of every executed
// command; nil inherits the test process environment.
func StartExecServer(t *testing.T, sandbox string, env []string) *ExecServer {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(client.PublicKey().Marshal()) {
			return nil, errors.New("synthetic key refused")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &ExecServer{
		listener: listener, sandbox: sandbox, env: env,
		hostKey: host.PublicKey(), client: client,
		conns: make(map[net.Conn]struct{}),
		holds: make(map[string]chan struct{}),
		seen:  make(chan string, 64),
	}
	server.wg.Add(1)
	config.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		server.mu.Lock()
		want := server.password
		server.mu.Unlock()
		if want != "" && subtle.ConstantTimeCompare(password, []byte(want)) == 1 {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("synthetic password refused")
	}
	go server.accept(config)
	t.Cleanup(server.Stop)
	return server
}

// Address returns the host:port the fixture listens on.
func (s *ExecServer) Address() string { return s.listener.Addr().String() }

// HostKey returns the pinned host key of the fixture.
func (s *ExecServer) HostKey() ssh.PublicKey { return s.hostKey }

// ClientSigner returns the only accepted client identity.
func (s *ExecServer) ClientSigner() ssh.Signer { return s.client }

// ArmHold registers a gate: every exec whose command contains match waits
// until Release before the command runs.
func (s *ExecServer) ArmHold(match string) chan struct{} {
	gate := make(chan struct{})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holds[match] = gate
	return gate
}

// Release opens every registered hold gate.
func (s *ExecServer) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for match, gate := range s.holds {
		close(gate)
		delete(s.holds, match)
	}
}

// ArmKill makes every exec whose command contains match close the whole
// transport once amount bytes have crossed it in either direction.
func (s *ExecServer) ArmKill(match string, amount int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kill = injection{armed: true, match: match, amount: amount}
}

// ArmCorrupt flips one bit at offset amount of the stdin stream of every
// exec whose command contains match.
func (s *ExecServer) ArmCorrupt(match string, amount int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.corrupt = injection{armed: true, match: match, amount: amount}
}

// WaitEntered waits until an exec whose command contains match was accepted.
func (s *ExecServer) WaitEntered(t *testing.T, match string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		s.mu.Lock()
		found := false
		for _, command := range s.entered {
			if strings.Contains(command, match) {
				found = true
				break
			}
		}
		s.mu.Unlock()
		if found {
			return
		}
		select {
		case <-s.seen:
		case <-time.After(time.Until(deadline)):
			t.Fatalf("exec server never accepted a command containing %q", match)
		}
	}
}

func (s *ExecServer) note(command string) {
	s.mu.Lock()
	s.entered = append(s.entered, command)
	s.mu.Unlock()
	select {
	case s.seen <- command:
	default:
	}
}

// Stop releases every hold, closes the transports and joins the server.
func (s *ExecServer) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	_ = s.listener.Close()
	for conn := range s.conns {
		_ = conn.Close()
	}
	for _, gate := range s.holds {
		close(gate)
	}
	s.holds = make(map[string]chan struct{})
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *ExecServer) accept(config *ssh.ServerConfig) {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(conn, config)
	}
}

// SetPassword additionally accepts password authentication with this secret,
// for targets stored with a password in a vault.
func (s *ExecServer) SetPassword(password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password = password
}
