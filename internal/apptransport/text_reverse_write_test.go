package apptransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type pipeResponseWriter struct {
	conn    net.Conn
	header  http.Header
	entered chan struct{}
	once    sync.Once
	err     error
	n       int
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(int) {}

func (w *pipeResponseWriter) SetWriteDeadline(deadline time.Time) error {
	return w.conn.SetWriteDeadline(deadline)
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	w.n, w.err = w.conn.Write(p)
	return w.n, w.err
}

func (w *pipeResponseWriter) FlushError() error { return nil }

func newPipeResponseWriter(conn net.Conn) *pipeResponseWriter {
	return &pipeResponseWriter{
		conn:    conn,
		header:  make(http.Header),
		entered: make(chan struct{}),
	}
}

func TestServeBoundedReverseResponseCanceledBlockedWrite(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	writer := newPipeResponseWriter(server)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	body := bytes.Repeat([]byte("x"), 64<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveBoundedReverseResponse(writer, request, handler)
	}()

	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("response write did not begin")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled response write did not finish")
	}
	var netErr net.Error
	if writer.err == nil || !errors.As(writer.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error = %v, want timeout net.Error", writer.err)
	}
	if writer.n != 0 {
		t.Fatalf("write count = %d, want 0", writer.n)
	}
}

func TestServeBoundedReverseResponseDeadlineBlockedWrite(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	writer := newPipeResponseWriter(server)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	body := bytes.Repeat([]byte("x"), 64<<10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveBoundedReverseResponse(writer, request, handler)
	}()

	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("response write did not begin")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadline-bound response write did not finish")
	}
	var netErr net.Error
	if writer.err == nil || !errors.As(writer.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error = %v, want timeout net.Error", writer.err)
	}
}

func TestServeBoundedReverseResponseCanceledBlockedFlush(t *testing.T) {
	server, peer := net.Pipe()
	writer := &flushPipeResponseWriter{pipeResponseWriter: newPipeResponseWriter(server)}
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 64<<10))
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveBoundedReverseResponse(writer, request, handler)
	}()
	defer func() {
		cancel()
		_ = server.Close()
		_ = peer.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("response server did not stop")
		}
	}()

	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("flush write did not begin")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled response flush did not finish")
	}
	var netErr net.Error
	if writer.err == nil || !errors.As(writer.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("flush error = %v, want timeout net.Error", writer.err)
	}
	if writer.n != 0 {
		t.Fatalf("flush write count = %d, want 0", writer.n)
	}
}

type flushPipeResponseWriter struct {
	*pipeResponseWriter
	buffer []byte
}

func (w *flushPipeResponseWriter) Write(p []byte) (int, error) {
	w.buffer = append(w.buffer, p...)
	return len(p), nil
}

func (w *flushPipeResponseWriter) FlushError() error {
	_, err := w.pipeResponseWriter.Write(w.buffer)
	return err
}

func TestServeBoundedReverseResponseHealthyPipeWrite(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	writer := newPipeResponseWriter(server)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	body := bytes.Repeat([]byte("healthy response"), (64<<10)/len("healthy response"))
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	type readResult struct {
		body []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		got := make([]byte, len(body))
		_, err := io.ReadFull(peer, got)
		readDone <- readResult{body: got, err: err}
	}()

	serveBoundedReverseResponse(writer, request, handler)
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("read response: %v", result.err)
		}
		if !bytes.Equal(result.body, body) {
			t.Fatal("received response differs from handler body")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not finish reading response")
	}
	if writer.err != nil || writer.n != len(body) {
		t.Fatalf("write = (%d, %v), want (%d, nil)", writer.n, writer.err, len(body))
	}
}
