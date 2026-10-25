package rotation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/remote"
	"storagehost/internal/vault"
)

func TestRotationOverPinnedSSHRetainsOldLogin(t *testing.T) {
	oldPrivate, oldPublic := rotationKey(t)
	newPrivate, newPublic := rotationKey(t)
	hostPrivate, _ := rotationKey(t)
	defer clear(oldPrivate)
	defer clear(newPrivate)
	defer clear(hostPrivate)
	host, err := ssh.ParsePrivateKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, _, _, _, err := ssh.ParseAuthorizedKey(oldPublic)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	allowed := map[string]bool{string(oldKey.Marshal()): true}
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		mu.Lock()
		defer mu.Unlock()
		if !allowed[string(key.Marshal())] {
			return nil, errors.New("not authorized")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
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
					for request := range requests {
						var command struct{ Value string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil || !strings.Contains(command.Value, "authorized_keys") {
							request.Reply(false, nil)
							continue
						}
						request.Reply(true, nil)
						data, err := io.ReadAll(channel)
						lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
						if err != nil || len(lines) != 2 || !bytes.Equal(lines[0], bytes.TrimSpace(oldPublic)) || !bytes.Equal(lines[1], bytes.TrimSpace(newPublic)) {
							channel.Close()
							return
						}
						key, _, _, _, err := ssh.ParseAuthorizedKey(lines[1])
						if err != nil {
							channel.Close()
							return
						}
						mu.Lock()
						allowed[string(key.Marshal())] = true
						mu.Unlock()
						channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						channel.Close()
						break
					}
					channel.Close()
				}
			}(conn)
		}
	}()
	original := vault.Target{Address: listener.Addr().String(), User: "test", PrivateKey: oldPrivate, HostKeys: []string{string(ssh.MarshalAuthorizedKey(host.PublicKey()))}}
	oldConfig, err := original.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	err = Apply(ctx, original, newPrivate, newPublic, Operations{
		Preserve: func(context.Context) error { return nil }, Confirm: func() error { return nil },
		Add: func(ctx context.Context, target vault.Target, public []byte) error {
			return remote.AddAuthorizedKey(ctx, target.Address, oldConfig, oldPublic, public)
		},
		Verify: func(ctx context.Context, target vault.Target) error {
			config, err := target.ClientConfig()
			if err != nil {
				return err
			}
			return remote.Check(ctx, target.Address, config)
		},
		Commit: func(context.Context, vault.Target) error { committed = true; return nil },
	})
	if err != nil || !committed {
		t.Fatalf("SSH rotation: committed=%t error=%v", committed, err)
	}
	if err := remote.Check(ctx, original.Address, oldConfig); err != nil {
		t.Fatalf("rotation removed the old login: %v", err)
	}
}
