package remote

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"storagehost/internal/sshauth"
)

func TestCheckAuthenticatesWithoutRemoteRequests(t *testing.T) {
	_, clientKey := testSigner(t)
	_, host := testSigner(t)
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
			return nil, errors.New("wrong client key")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requestsSeen := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			requestsSeen <- -1
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			requestsSeen <- -1
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		count := 0
		for next := range channels {
			channel, requests, err := next.Accept()
			if err != nil {
				break
			}
			for request := range requests {
				count++
				request.Reply(false, nil)
			}
			channel.Close()
		}
		requestsSeen <- count
	}()
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{sshauth.PublicKey(clientKey)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
	if err := Check(ctx, listener.Addr().String(), config); err != nil {
		t.Fatal(err)
	}
	select {
	case count := <-requestsSeen:
		if count != 0 {
			t.Fatalf("check sent %d command/PTY/shell requests", count)
		}
	case <-ctx.Done():
		t.Fatal("check did not close its connection")
	}
}
