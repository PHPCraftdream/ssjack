package remote

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

func TestCheckRejectsNoneAuthEvenAfterPreviousKeySuccess(t *testing.T) {
	_, selected := testSigner(t)
	_, host := testSigner(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var allowNone atomic.Bool
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn, none bool) {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				serverConfig := &ssh.ServerConfig{NoClientAuth: none}
				if !none {
					serverConfig.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
						if !bytes.Equal(key.Marshal(), selected.PublicKey().Marshal()) {
							return nil, errors.New("wrong key")
						}
						return nil, nil
					}
				}
				serverConfig.AddHostKey(host)
				server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for next := range channels {
					channel, requests, err := next.Accept()
					if err != nil {
						return
					}
					go func() { ssh.DiscardRequests(requests); channel.Close() }()
				}
			}(conn, allowNone.Load())
		}
	}()
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{sshauth.PublicKey(selected)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
	address := listener.Addr().String()
	if err := Check(ctx, address, config); err != nil {
		t.Fatalf("selected key authentication failed: %v", err)
	}
	allowNone.Store(true)
	baseline, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(selected)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("fixture did not reproduce dependency none-auth acceptance: %v", err)
	}
	baselineSession, err := baseline.NewSession()
	if err != nil {
		baseline.Close()
		t.Fatalf("none-auth fixture refused session opening: %v", err)
	}
	baselineSession.Close()
	baseline.Close()
	if err := Check(ctx, address, config); err == nil || !strings.Contains(err.Error(), "selected private key") {
		t.Fatalf("none-auth was treated as proof of the selected key: %v", err)
	}
}
