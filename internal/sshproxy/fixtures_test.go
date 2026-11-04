package sshproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func rawProxy(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var mu sync.Mutex
	var active net.Conn
	closed := false
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		active = conn
		mu.Unlock()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		handler(conn)
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		closed = true
		if active != nil {
			active.Close()
		}
		mu.Unlock()
		<-done
	})
	return listener.Addr().String()
}

func echoTarget(t *testing.T) string {
	return rawProxy(t, func(conn net.Conn) { io.Copy(conn, conn) })
}

func httpReply(t *testing.T, response string) string {
	return rawProxy(t, func(conn net.Conn) {
		if request, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			request.Body.Close()
			io.WriteString(conn, response)
		}
	})
}

func pipePair(t *testing.T, handler func(net.Conn)) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handler(server) }()
	t.Cleanup(func() { client.Close(); server.Close(); <-done })
	return client
}
