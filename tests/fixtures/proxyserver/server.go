// Package proxyserver supplies loopback-only synthetic proxies for CI.
package proxyserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type Options struct {
	Protocol, Target, Upstream, Username string
	Password                             []byte
}

type Server struct {
	options  Options
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	wg       sync.WaitGroup
	active   map[net.Conn]bool
	requests []string
	accepted int
	closed   bool
}

func Start(options Options) (*Server, error) {
	host, _, err := net.SplitHostPort(options.Upstream)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || options.Target == "" || (options.Protocol != "socks5" && options.Protocol != "http") {
		return nil, errors.New("synthetic proxy requires a loopback upstream")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	options.Password = append([]byte(nil), options.Password...)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{options: options, listener: listener, ctx: ctx, cancel: cancel, active: make(map[net.Conn]bool)}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

func (s *Server) Address() string { return s.listener.Addr().String() }

func (s *Server) Counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, len(s.requests)
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	s.listener.Close()
	for conn := range s.active {
		conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	clear(s.options.Password)
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.accepted++
		s.active[conn] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.active, conn)
		s.mu.Unlock()
	}()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	var target string
	var err error
	if s.options.Protocol == "socks5" {
		target, err = s.socks(conn)
	} else {
		target, err = s.http(conn)
	}
	if err != nil || target != s.options.Target {
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, target)
	s.mu.Unlock()
	dialer := net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.DialContext(s.ctx, "tcp", s.options.Upstream)
	if err != nil {
		return
	}
	defer upstream.Close()
	if s.options.Protocol == "socks5" {
		_, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	} else {
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	}
	if err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	cancelled := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { defer close(cancelled); upstream.Close() })
	defer func() {
		if !stop() {
			<-cancelled
		}
	}()
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(upstream, conn); upstream.Close() }()
	io.Copy(conn, upstream)
	conn.Close()
	<-done
}

func (s *Server) http(conn net.Conn) (string, error) {
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, 8192)))
	if err != nil || request.Method != http.MethodConnect || request.Host != request.RequestURI {
		return "", errors.New("synthetic CONNECT request rejected")
	}
	want := ""
	if s.options.Username != "" {
		value := append([]byte(s.options.Username+":"), s.options.Password...)
		want = "Basic " + base64.StdEncoding.EncodeToString(value)
		clear(value)
	}
	if request.Header.Get("Proxy-Authorization") != want {
		io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return "", errors.New("synthetic proxy authentication rejected")
	}
	return request.RequestURI, nil
}

func (s *Server) socks(conn net.Conn) (string, error) {
	var hello [3]byte
	method := byte(0)
	if s.options.Username != "" {
		method = 2
	}
	if _, err := io.ReadFull(conn, hello[:]); err != nil || hello != [3]byte{5, 1, method} {
		return "", errors.New("synthetic SOCKS greeting rejected")
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return "", err
	}
	if method == 2 {
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 1 || header[1] == 0 {
			return "", errors.New("synthetic SOCKS authentication framing rejected")
		}
		user := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, user); err != nil {
			return "", err
		}
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return "", err
		}
		password := make([]byte, int(size[0]))
		defer clear(password)
		if _, err := io.ReadFull(conn, password); err != nil {
			return "", err
		}
		if string(user) != s.options.Username || !bytes.Equal(password, s.options.Password) {
			conn.Write([]byte{1, 1})
			return "", errors.New("synthetic SOCKS authentication rejected")
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return "", err
		}
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != 1 || header[2] != 0 {
		return "", errors.New("synthetic SOCKS request rejected")
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil || size[0] == 0 {
			return "", errors.New("synthetic domain rejected")
		}
		length = int(size[0])
	default:
		return "", errors.New("synthetic address rejected")
	}
	data := make([]byte, length+2)
	if _, err := io.ReadFull(conn, data); err != nil {
		return "", err
	}
	host := string(data[:length])
	if header[3] != 3 {
		host = net.IP(data[:length]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(data[length:])))), nil
}
