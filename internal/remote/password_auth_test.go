package remote

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

func passwordEndpoint(t *testing.T, none bool) (string, ssh.Signer, *atomic.Int32) {
	t.Helper()
	_, host := testSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done := make(chan struct{})
	var attempts atomic.Int32
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		stop := context.AfterFunc(ctx, func() { connection.Close() })
		defer stop()
		serverConfig := &ssh.ServerConfig{NoClientAuth: none}
		if !none {
			serverConfig.PasswordCallback = func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				attempts.Add(1)
				if metadata.User() != "selected" || subtle.ConstantTimeCompare(password, []byte("synthetic-password")) != 1 {
					return nil, errors.New("synthetic credential mismatch")
				}
				return nil, nil
			}
		}
		serverConfig.AddHostKey(host)
		server, channels, _, err := ssh.NewServerConn(connection, serverConfig)
		if err != nil {
			return
		}
		defer server.Close()
		for next := range channels {
			if next.ChannelType() != "session" {
				next.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			channel, _, err := next.Accept()
			if err != nil {
				return
			}
			channel.Close()
		}
	}()
	return listener.Addr().String(), host, &attempts
}

func TestPasswordEvidenceIsFreshForEachConnection(t *testing.T) {
	first, firstHost, _ := passwordEndpoint(t, false)
	second, secondHost, attempts := passwordEndpoint(t, true)
	config := &ssh.ClientConfig{User: "selected", Auth: []ssh.AuthMethod{sshauth.Password([]byte("synthetic-password"))}, HostKeyCallback: ssh.FixedHostKey(firstHost.PublicKey())}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Check(ctx, first, config); err != nil {
		t.Fatal("selected password control did not authenticate")
	}
	config.HostKeyCallback = ssh.FixedHostKey(secondHost.PublicKey())
	if err := Check(ctx, second, config); err == nil || attempts.Load() != 0 {
		t.Fatal("previous password success authorized a later none-auth connection")
	}
}

func TestSelectedPasswordAuthentication(t *testing.T) {
	for _, mode := range []string{"correct", "wrong", "none", "untyped", "mixed", "wrong-host"} {
		t.Run(mode, func(t *testing.T) {
			address, host, attempts := passwordEndpoint(t, mode == "none")
			value := []byte("synthetic-password")
			if mode == "wrong" {
				value = []byte("wrong-password")
			}
			method := sshauth.Password(value)
			clear(value)
			config := &ssh.ClientConfig{User: "selected", Auth: []ssh.AuthMethod{method}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
			if mode == "untyped" {
				config.Auth = []ssh.AuthMethod{ssh.Password("synthetic-password")}
			}
			if mode == "mixed" {
				config.Auth = append(config.Auth, ssh.Password("fallback"))
			}
			if mode == "wrong-host" {
				_, other := testSigner(t)
				config.HostKeyCallback = ssh.FixedHostKey(other.PublicKey())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := Check(ctx, address, config)
			if mode == "correct" {
				if err != nil || attempts.Load() != 1 {
					t.Fatal("selected owned password did not authenticate")
				}
			} else if err == nil {
				t.Fatal("invalid authentication was accepted as the selected password")
			}
			if (mode == "none" || mode == "untyped" || mode == "mixed" || mode == "wrong-host") && attempts.Load() != 0 {
				t.Fatal("password was offered on a refused or unverified authentication path")
			}
		})
	}
}
