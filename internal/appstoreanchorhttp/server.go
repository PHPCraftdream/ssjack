package appstoreanchorhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Serve consumes one explicit listener; it never selects a bind address or opens credentials.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || server.state == nil || ctx == nil || listener == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := server.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return ErrBusy
	}
	s.started = true
	config := s.tlsConfig
	httpServer := &http.Server{Handler: http.HandlerFunc(s.serveHTTP), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0), TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler))}
	httpServer.SetKeepAlivesEnabled(false)
	s.http = httpServer
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = httpServer.Close() })
	limited := &limitedListener{Listener: listener, slots: make(chan struct{}, 32)}
	err := httpServer.Serve(tls.NewListener(limited, config))
	stop()
	closeErr := server.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return ErrUnavailable
	}
	return closeErr
}

// Close stops network admission and waits for real handlers; blocked filesystem IO has no hard bound.
func (server *Server) Close() error {
	if server == nil || server.state == nil {
		return nil
	}
	s := server.state
	s.mu.Lock()
	if s.closed {
		done := s.done
		s.mu.Unlock()
		<-done
		return nil
	}
	s.closed = true
	httpServer := s.http
	s.mu.Unlock()
	var err error
	if httpServer != nil {
		err = httpServer.Close()
	}
	s.handlers.Wait()
	s.mu.Lock()
	clear(s.signer)
	s.signer = nil
	s.tlsConfig = nil
	close(s.done)
	s.mu.Unlock()
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConnection{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			conn.Close()
		}
	}
}

type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
