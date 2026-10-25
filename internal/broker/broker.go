package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"storagehost/internal/wire"
)

type Handler func(context.Context, wire.Request) wire.Reply

type Server struct {
	listener  net.Listener
	pin       string
	session   string
	tokenHash [32]byte
	expires   time.Time
	handler   Handler
	ctx       context.Context
	cancel    context.CancelFunc

	mu       sync.Mutex
	consumed bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
	attached chan struct{}
	done     chan struct{}
}

func Listen(parent context.Context, session, token string, ttl time.Duration, handler Handler) (*Server, error) {
	if !validToken(session) || !validToken(token) || ttl <= 0 || handler == nil {
		return nil, errors.New("invalid session parameters")
	}
	config, pin, err := wire.ServerTLS()
	if err != nil {
		return nil, err
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{
		listener: listener, pin: pin, session: session,
		tokenHash: sha256.Sum256([]byte(token)),
		expires:   time.Now().Add(ttl), handler: handler, ctx: ctx, cancel: cancel,
		conns: make(map[net.Conn]struct{}), attached: make(chan struct{}), done: make(chan struct{}),
	}
	go s.accept()
	go func() {
		timer := time.NewTimer(ttl)
		defer timer.Stop()
		select {
		case <-s.attached:
			<-ctx.Done()
		case <-timer.C:
			s.mu.Lock()
			consumed := s.consumed
			s.mu.Unlock()
			if consumed {
				<-ctx.Done()
			}
		case <-ctx.Done():
		}
		s.shutdown()
	}()
	return s, nil
}

func (s *Server) Endpoint() string          { return s.listener.Addr().String() }
func (s *Server) Pin() string               { return s.pin }
func (s *Server) Done() <-chan struct{}     { return s.done }
func (s *Server) Attached() <-chan struct{} { return s.attached }

func (s *Server) shutdown() {
	s.once.Do(func() {
		s.cancel()
		s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			conn.Close()
		}
		s.mu.Unlock()
		close(s.done)
	})
}

func (s *Server) Close() {
	s.shutdown()
	s.wg.Wait()
}

func (s *Server) accept() {
	// Bound concurrent unauthenticated TLS handshakes.
	slots := make(chan struct{}, 4)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		if !loopbackPeer(conn.RemoteAddr()) {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.ctx.Err() != nil || s.consumed {
			s.mu.Unlock()
			conn.Close()
			<-slots
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-slots }()
			s.serve(conn)
		}()
	}
}

func (s *Server) claim(auth wire.Auth) bool {
	tokenHash := sha256.Sum256([]byte(auth.Token))
	tokenOK := subtle.ConstantTimeCompare(s.tokenHash[:], tokenHash[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || s.ctx.Err() != nil || !time.Now().Before(s.expires) || auth.Version != 2 || auth.Session != s.session || tokenOK != 1 {
		return false
	}
	s.consumed = true
	close(s.attached)
	return true
}

func (s *Server) serve(conn net.Conn) {
	claimed := false
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		if claimed {
			s.shutdown()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if s.expires.Before(deadline) {
		deadline = s.expires
	}
	conn.SetDeadline(deadline)
	var auth wire.Auth
	if wire.Read(conn, &auth) != nil {
		return
	}
	if !s.claim(auth) {
		wire.Write(conn, wire.Reply{Error: "access denied"})
		return
	}
	claimed = true
	// No new connections are needed after attachment.
	s.listener.Close()
	if wire.Write(conn, wire.Reply{OK: true}) != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	for {
		var request wire.Request
		if wire.Read(conn, &request) != nil {
			return
		}
		if wire.Write(conn, s.handler(s.ctx, request)) != nil {
			return
		}
	}
}

type Client struct {
	conn net.Conn
	mu   sync.Mutex
}

func Connect(ctx context.Context, endpoint, pin string, auth wire.Auth) (*Client, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	config, err := wire.ClientTLS(pin)
	if err != nil {
		return nil, err
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}
	conn, err := dialer.DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		return nil, errors.New("failed to establish a secure connection to the keeper")
	}
	if !loopbackPeer(conn.RemoteAddr()) {
		conn.Close()
		return nil, errors.New("keeper TCP peer is not loopback")
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var reply wire.Reply
	if err := wire.Write(conn, auth); err != nil {
		conn.Close()
		return nil, errors.New("failed to authenticate to the keeper")
	}
	if err := wire.Read(conn, &reply); err != nil || !reply.OK {
		conn.Close()
		return nil, errors.New("keeper rejected the connection")
	}
	conn.SetDeadline(time.Time{})
	return &Client{conn: conn}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Call(ctx context.Context, operation string, input, output any) error {
	data, err := wire.Encode(input)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.conn.Close() })
	defer stop()
	var reply wire.Reply
	if wire.Write(c.conn, wire.Request{Operation: operation, Data: data}) != nil || wire.Read(c.conn, &reply) != nil {
		c.conn.Close()
		return errors.New("keeper connection closed; start a new session")
	}
	c.conn.SetDeadline(time.Time{})
	if !reply.OK {
		return errors.New(reply.Error)
	}
	if output != nil {
		return wire.Decode(reply.Data, output)
	}
	return nil
}

func Result(value any, err error) wire.Reply {
	if err != nil {
		return wire.Reply{Error: err.Error()}
	}
	data, err := wire.Encode(value)
	if err != nil {
		return wire.Reply{Error: "failed to encode reply"}
	}
	return wire.Reply{OK: true, Data: data}
}
