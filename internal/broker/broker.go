package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type Handler func(context.Context, wire.Request) wire.Reply

// Trace receives fixed lifecycle event names and key/value pairs; it never
// receives request data, replies, tokens or error text.
type Trace func(event string, pairs ...string)

type Server struct {
	listener  net.Listener
	pin       string
	session   string
	tokenHash [32]byte
	expires   time.Time
	handler   Handler
	trace     Trace
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
	return ListenTraced(parent, session, token, ttl, handler, nil)
}

// ListenTraced is Listen with lifecycle events reported to trace.
func ListenTraced(parent context.Context, session, token string, ttl time.Duration, handler Handler, trace Trace) (*Server, error) {
	if trace == nil {
		trace = func(string, ...string) {}
	}
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
		expires:   time.Now().Add(ttl), handler: handler, trace: trace, ctx: ctx, cancel: cancel,
		conns: make(map[net.Conn]struct{}), attached: make(chan struct{}), done: make(chan struct{}),
	}
	trace("listen", "ttl_ms", strconv.FormatInt(ttl.Milliseconds(), 10))
	go s.accept()
	go func() {
		timer := time.NewTimer(ttl)
		defer timer.Stop()
		reason := "parent-cancelled"
		select {
		case <-s.attached:
			<-ctx.Done()
		case <-timer.C:
			s.mu.Lock()
			consumed := s.consumed
			s.mu.Unlock()
			if consumed {
				<-ctx.Done()
			} else {
				reason = "bootstrap-ttl-expired"
			}
		case <-ctx.Done():
		}
		s.shutdown(reason)
	}()
	return s, nil
}

func (s *Server) Endpoint() string          { return s.listener.Addr().String() }
func (s *Server) Pin() string               { return s.pin }
func (s *Server) Done() <-chan struct{}     { return s.done }
func (s *Server) Attached() <-chan struct{} { return s.attached }

// shutdown records only the first reason: later callers find it already done.
func (s *Server) shutdown(reason string) {
	s.once.Do(func() {
		s.trace("shutdown", "reason", reason)
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
	s.shutdown("closed")
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
			s.trace("accept-refused", "reason", "not-loopback")
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			s.trace("accept-refused", "reason", "handshake-slots-full")
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.ctx.Err() != nil || s.consumed {
			s.mu.Unlock()
			s.trace("accept-refused", "reason", "already-attached-or-stopped")
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

// claim returns "" on success, else the first failed condition for the log.
func (s *Server) claim(auth wire.Auth) string {
	tokenHash := sha256.Sum256([]byte(auth.Token))
	tokenOK := subtle.ConstantTimeCompare(s.tokenHash[:], tokenHash[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.consumed:
		return "token-already-used"
	case s.ctx.Err() != nil:
		return "stopped"
	case !time.Now().Before(s.expires):
		return "bootstrap-expired"
	case auth.Version != 2 || auth.Session != s.session || tokenOK != 1:
		return "credentials"
	}
	s.consumed = true
	close(s.attached)
	return ""
}

func (s *Server) serve(conn net.Conn) {
	claimed, started, requests, stage, cause := false, time.Now(), 0, "auth-read", "none"
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		s.trace("connection-end", "attached", strconv.FormatBool(claimed), "stage", stage, "cause", cause, "requests", strconv.Itoa(requests), "ms", lifelog.Millis(started))
		if claimed {
			s.shutdown("attached-connection-ended")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if s.expires.Before(deadline) {
		deadline = s.expires
	}
	conn.SetDeadline(deadline)
	var auth wire.Auth
	if err := wire.Read(conn, &auth); err != nil {
		cause = lifelog.Cause(err)
		return
	}
	if reason := s.claim(auth); reason != "" {
		stage, cause = "claim", reason
		wire.Write(conn, wire.Reply{Error: "access denied"})
		return
	}
	claimed = true
	s.trace("attached")
	// No new connections are needed after attachment.
	s.listener.Close()
	if err := wire.Write(conn, wire.Reply{OK: true}); err != nil {
		stage, cause = "attach-reply", lifelog.Cause(err)
		return
	}
	conn.SetDeadline(time.Time{})
	for {
		var request wire.Request
		if err := wire.Read(conn, &request); err != nil {
			stage, cause = "request-read", lifelog.Cause(err)
			return
		}
		began := time.Now()
		reply := s.handler(s.ctx, request)
		requests++
		s.trace("request", "op", request.Operation, "ok", strconv.FormatBool(reply.OK), "ms", lifelog.Millis(began))
		if err := wire.Write(conn, reply); err != nil {
			stage, cause = "reply-write", lifelog.Cause(err)
			return
		}
	}
}
