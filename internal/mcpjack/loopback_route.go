package mcpjack

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maxLoopbackResponseHeaderBytes = 16 << 10

var errLoopbackRoute = errors.New("loopback_route_failed")
var errLoopbackInvalid = errors.New("loopback_route_invalid")
var errLoopbackUncertain = errors.New("loopback_route_uncertain")

// ContextDialFunc establishes a connection to the fixed target.
type ContextDialFunc func(context.Context, string, string) (net.Conn, error)

type loopbackRoute struct {
	target string
	dial   ContextDialFunc
}

// NewLoopbackRoute creates a non-retrying, non-reusing route to one literal loopback authority.
func NewLoopbackRoute(target string, dial ContextDialFunc) (http.RoundTripper, error) {
	host, port, err := net.SplitHostPort(target)
	ip := net.ParseIP(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || p < 1 || p > 65535 || dial == nil {
		return nil, errLoopbackInvalid
	}
	return &loopbackRoute{target: target, dial: dial}, nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

func validHostHeaders(header http.Header, target string) bool {
	for key, values := range header {
		if !strings.EqualFold(key, "Host") {
			continue
		}
		for _, value := range values {
			if value != target {
				return false
			}
		}
	}
	return true
}

func (r *loopbackRoute) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errLoopbackInvalid
	}
	if req.URL == nil || req.URL.Scheme != "http" || req.URL.Host != r.target || req.URL.Opaque != "" ||
		(req.Host != "" && req.Host != r.target) || !validHostHeaders(req.Header, r.target) {
		closeRequestBody(req)
		return nil, errLoopbackInvalid
	}
	conn, err := r.dial(req.Context(), "tcp", r.target)
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		closeRequestBody(req)
		return nil, errLoopbackRoute
	}
	stopClose := context.AfterFunc(req.Context(), func() { _ = conn.Close() })
	owned := false
	defer func() {
		if !owned {
			stopClose()
			_ = conn.Close()
		}
	}()
	copyReq := req.Clone(req.Context())
	copyURL := *req.URL
	copyURL.Host = r.target
	copyReq.URL = &copyURL
	copyReq.Host = r.target
	copyReq.Header = req.Header.Clone()
	for key := range copyReq.Header {
		if strings.EqualFold(key, "Host") {
			delete(copyReq.Header, key)
		}
	}
	// After the first write the server may have acted: every failure is uncertain.
	if err := copyReq.Write(conn); err != nil {
		return nil, errLoopbackUncertain
	}
	reader := &headerBoundReader{r: conn, left: maxLoopbackResponseHeaderBytes}
	resp, err := http.ReadResponse(bufio.NewReader(reader), copyReq)
	reader.left = -1
	if err != nil {
		return nil, errLoopbackUncertain
	}
	resp.Request = req
	resp.Body = &connectionBody{ReadCloser: resp.Body, conn: conn, stop: stopClose}
	owned = true
	return resp, nil
}

type headerBoundReader struct {
	r    io.Reader
	left int
}

func (r *headerBoundReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, errLoopbackRoute
	}
	if r.left > 0 && len(p) > r.left {
		p = p[:r.left]
	}
	n, err := r.r.Read(p)
	if r.left > 0 {
		r.left -= n
	}
	return n, err
}

type connectionBody struct {
	io.ReadCloser
	conn net.Conn
	stop func() bool
}

func (b *connectionBody) Close() error {
	b.stop()
	_ = b.conn.Close()
	e := b.ReadCloser.Close()
	if e != nil {
		return errLoopbackRoute
	}
	return nil
}
func (b *connectionBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.stop()
		_ = b.conn.Close()
	} else if err != nil {
		b.stop()
		_ = b.conn.Close()
		return n, errLoopbackRoute
	}
	return n, err
}
