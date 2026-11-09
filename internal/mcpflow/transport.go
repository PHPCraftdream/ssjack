// Package mcpflow bounds owned MCP HTTP exchange and shutdown, not authorization.
package mcpflow

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxRequest  = 64 << 10
	MaxResponse = 256 << 10
	MaxHeaders  = 16 << 10
	MaxActive   = 4
	MaxMessages = 4096
	MaxLease    = 10 * time.Minute
)

var ErrExchange = errors.New("remote MCP exchange unavailable; do not replay uncertain operations")

// errDefiniteResponse marks a transport error that already carries definite peer-response evidence: rejected headers, declared or actual size limits, or a non-2xx POST status. It never carries peer body text, header values, or IDs, and it never escapes as a public diagnostic.
var errDefiniteResponse = errors.New("definite peer response evidence")

// DefiniteResponse reports whether err carries definite peer-response evidence that must stay a fixed refusal even when shutdown overlaps.
func DefiniteResponse(err error) bool { return errors.Is(err, errDefiniteResponse) }

// definiteError carries the private definite-response marker while keeping the
// public fixed diagnostic text byte-identical to ErrExchange.
type definiteError struct{}

func (definiteError) Error() string   { return ErrExchange.Error() }
func (definiteError) Unwrap() []error { return []error{ErrExchange, errDefiniteResponse} }

func definiteRefusal() error { return definiteError{} }

type Transport struct {
	mu                                          sync.Mutex
	ctx                                         context.Context
	cancel                                      context.CancelFunc
	base                                        http.RoundTripper
	prepare                                     func(*http.Request) (*http.Request, error)
	clear                                       func()
	done                                        chan struct{}
	active, messages                            int
	get, deleted, closing, finalizing, ioFailed bool
}

// New borrows base, but owns cancellation and the bounded exchange lifetime.
// prepare/clear are trusted local callbacks; clear must not block or reenter.
func New(parent context.Context, base http.RoundTripper, prepare func(*http.Request) (*http.Request, error), clear func()) (*Transport, error) {
	if parent == nil || parent.Err() != nil || base == nil || prepare == nil || clear == nil {
		return nil, ErrExchange
	}
	ctx, cancel := context.WithTimeout(parent, MaxLease)
	return &Transport{ctx: ctx, cancel: cancel, base: base, prepare: prepare, clear: clear, done: make(chan struct{})}, nil
}

func (t *Transport) Available() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ctx != nil && !t.closing && t.ctx.Err() == nil
}

func headerBytes(header http.Header) bool {
	total := 0
	for name, values := range header {
		for _, value := range values {
			total += len(name) + len(value) + 4
			if total > MaxHeaders || strings.ContainsAny(value, "\x00\r\n") {
				return false
			}
		}
	}
	return true
}

func inputAllowed(request *http.Request) bool {
	if request == nil || request.URL == nil || request.Response != nil || request.ContentLength < 0 || request.ContentLength > MaxRequest || len(request.Trailer) != 0 || len(request.TransferEncoding) != 0 || !headerBytes(request.Header) {
		return false
	}
	if request.Method != http.MethodPost && request.Method != http.MethodGet && request.Method != http.MethodDelete {
		return false
	}
	seen := make(map[string]bool)
	for name, values := range request.Header {
		name = strings.ToLower(name)
		if seen[name] || len(values) != 1 {
			return false
		}
		seen[name] = true
		switch name {
		case "accept", "content-type", "mcp-protocol-version", "mcp-session-id":
		default:
			return false
		}
	}
	if request.Method == http.MethodPost {
		return request.ContentLength > 0 && request.Body != nil && request.Header.Get("Content-Type") == "application/json"
	}
	return request.ContentLength == 0 && request.Body == nil
}

func (t *Transport) enter(method string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ctx == nil || t.closing || t.ctx.Err() != nil || t.active == MaxActive || t.messages == MaxMessages || method == http.MethodGet && t.get || method == http.MethodDelete && t.deleted {
		return false
	}
	t.get = t.get || method == http.MethodGet
	t.deleted = t.deleted || method == http.MethodDelete
	t.active++
	t.messages++
	return true
}

func (t *Transport) leave(failed bool) {
	t.mu.Lock()
	t.active--
	t.ioFailed = t.ioFailed || failed
	t.mu.Unlock()
	t.finishClose()
}

func (t *Transport) finishClose() {
	t.mu.Lock()
	if !t.closing || t.active != 0 || t.finalizing {
		t.mu.Unlock()
		return
	}
	t.finalizing = true
	failed := t.ioFailed
	t.mu.Unlock()
	if !failed {
		t.clear()
	}
	close(t.done)
}

func (t *Transport) Close(ctx context.Context) error {
	if t == nil || ctx == nil || t.cancel == nil {
		return ErrExchange
	}
	t.mu.Lock()
	t.closing = true
	t.mu.Unlock()
	t.cancel()
	if idle, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		idle.CloseIdleConnections()
	}
	t.finishClose()
	select {
	case <-t.done:
		t.mu.Lock()
		failed := t.ioFailed
		t.mu.Unlock()
		if failed {
			return ErrExchange
		}
		return nil
	default:
	}
	select {
	case <-t.done:
		t.mu.Lock()
		failed := t.ioFailed
		t.mu.Unlock()
		if !failed {
			return nil
		}
	case <-ctx.Done():
	}
	return ErrExchange
}

func responseHeaders(header http.Header) (http.Header, bool) {
	if !headerBytes(header) {
		return nil, false
	}
	result := make(http.Header)
	seen := make(map[string]bool)
	for name, values := range header {
		lower := strings.ToLower(name)
		switch lower {
		case "content-type", "mcp-session-id", "mcp-protocol-version":
			if len(values) != 1 || seen[lower] {
				return nil, false
			}
			seen[lower] = true
			result.Set(name, values[0])
		}
	}
	return result, true
}

func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || !inputAllowed(request) || !t.enter(request.Method) {
		if request != nil && request.Body != nil {
			request.Body.Close()
		}
		return nil, ErrExchange
	}
	ctx, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	var once sync.Once
	finish := func(failed bool) { once.Do(func() { cancel(); stop(); t.leave(failed) }) }
	handed := false
	defer func() {
		if !handed {
			finish(false)
		}
	}()
	data, failed, err := readRequest(ctx, request)
	if err != nil {
		finish(failed)
		return nil, ErrExchange
	}
	body := &requestBody{data: data}
	defer body.Close()
	prepared, err := t.prepare(request.Clone(ctx))
	if err != nil || prepared == nil || prepared.Method != request.Method || !headerBytes(prepared.Header) || ctx.Err() != nil {
		return nil, ErrExchange
	}
	prepared = prepared.Clone(ctx)
	prepared.Body, prepared.GetBody, prepared.ContentLength = body, nil, int64(len(data))
	if request.Method != http.MethodPost {
		prepared.Body = nil
	}
	response, err := t.base.RoundTrip(prepared)
	body.Close()
	if err != nil || response == nil || response.Body == nil {
		cancel()
		if response != nil && response.Body != nil {
			finish(response.Body.Close() != nil)
		}
		return nil, ErrExchange
	}
	headers, valid := responseHeaders(response.Header)
	allowedEmpty := request.Method != http.MethodPost && (response.StatusCode == 404 || response.StatusCode == 405)
	definite := !valid || response.ContentLength > MaxResponse || response.StatusCode < 200 || response.StatusCode >= 300 && !allowedEmpty
	if definite || ctx.Err() != nil {
		cancel()
		finish(response.Body.Close() != nil)
		if definite {
			return nil, definiteRefusal() // refused evidence survives shutdown overlap, text unchanged
		}
		return nil, ErrExchange // cancellation carried no response evidence
	}
	response.Request, response.Trailer, response.Header = nil, nil, headers
	response.Status = strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode)
	if allowedEmpty || response.StatusCode == http.StatusNoContent || response.ContentLength == 0 {
		cancel()
		failed := response.Body.Close() != nil
		response.Body, response.ContentLength, response.TransferEncoding = http.NoBody, 0, nil
		finish(failed)
		if failed {
			return nil, ErrExchange
		}
	} else {
		bounded := &responseBody{source: response.Body, left: MaxResponse, cancel: cancel, finish: finish}
		response.Body = bounded
		context.AfterFunc(ctx, func() { bounded.Close() })
		handed = true
	}
	return response, nil
}

var _ http.RoundTripper = (*Transport)(nil)
