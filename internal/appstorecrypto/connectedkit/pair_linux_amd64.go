//go:build linux && amd64

package connectedkit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"golang.org/x/crypto/ssh"
)

type PairTarget struct {
	Path        string
	limit       int64
	listener    net.Listener
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]bool
	workers     sync.WaitGroup
	Accepted    atomic.Int32
	Writes      atomic.Int32
	Reads       atomic.Int32
}

func PairSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func NewPairTarget(t *testing.T, profile string) (*PairTarget, remote.StreamRunner, string) {
	return NewPairTargetWithLimit(t, profile, 1<<20)
}

func NewPairTargetWithLimit(t *testing.T, profile string, limit int64) (*PairTarget, remote.StreamRunner, string) {
	t.Helper()
	if limit < 1 || limit > 64<<20 {
		t.Fatal("invalid synthetic target limit")
	}
	clientKey, hostKey := PairSigner(t), PairSigner(t)
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() == "pair-consumer" && bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, os.ErrPermission
		},
	}
	config.AddHostKey(hostKey)
	target := StartPairTarget(t, limit, config)
	clientConfig := &ssh.ClientConfig{User: "pair-consumer", Auth: []ssh.AuthMethod{sshauth.PublicKey(clientKey)}, HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey())}
	runner, err := remote.NewCredentialStreamRunner(profile, target.listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	identity := sha256.Sum256(clientKey.PublicKey().Marshal())
	return target, runner, hex.EncodeToString(identity[:])
}

func StartPairTarget(t *testing.T, limit int64, config *ssh.ServerConfig) *PairTarget {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := &PairTarget{Path: filepath.Join(t.TempDir(), "consumer.txt"), limit: limit, listener: listener, connections: make(map[net.Conn]bool)}
	target.workers.Add(1)
	go func() {
		defer target.workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			target.mu.Lock()
			if target.closed {
				target.mu.Unlock()
				_ = connection.Close()
				return
			}
			target.Accepted.Add(1)
			target.connections[connection] = true
			target.workers.Add(1)
			target.mu.Unlock()
			go target.serve(connection, config)
		}
	}()
	t.Cleanup(func() {
		target.mu.Lock()
		target.closed = true
		for connection := range target.connections {
			_ = connection.Close()
		}
		target.mu.Unlock()
		_ = listener.Close()
		target.workers.Wait()
	})
	return target
}

func (target *PairTarget) serve(connection net.Conn, config *ssh.ServerConfig) {
	defer target.workers.Done()
	defer func() {
		_ = connection.Close()
		target.mu.Lock()
		delete(target.connections, connection)
		target.mu.Unlock()
	}()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	server, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		return
	}
	defer server.Close()
	_ = connection.SetDeadline(time.Time{})
	go ssh.DiscardRequests(requests)
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			_ = incoming.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		channel, commands, err := incoming.Accept()
		if err != nil {
			return
		}
		target.command(channel, commands)
	}
}

func (target *PairTarget) command(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for request := range requests {
		var input struct{ Command string }
		if request.Type != "exec" || ssh.Unmarshal(request.Payload, &input) != nil || (input.Command != "pair-write" && input.Command != "pair-read") {
			_ = request.Reply(false, nil)
			continue
		}
		_ = request.Reply(true, nil)
		code := uint32(0)
		if input.Command == "pair-write" {
			data, err := io.ReadAll(io.LimitReader(channel, target.limit+1))
			if err != nil || int64(len(data)) > target.limit {
				code = 1
			} else if os.WriteFile(target.Path, data, 0o600) != nil {
				code = 1
			} else {
				target.Writes.Add(1)
			}
			clear(data)
		} else {
			data, err := os.ReadFile(target.Path)
			if err != nil {
				code = 1
			} else {
				target.Reads.Add(1)
				if _, err = channel.Write(data); err != nil {
					code = 1
				}
			}
			clear(data)
		}
		_, _ = channel.Stderr().Write([]byte(PairLongSecret))
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
		return
	}
}

// Addr returns the listening address of the target.
func (target *PairTarget) Addr() string { return target.listener.Addr().String() }
