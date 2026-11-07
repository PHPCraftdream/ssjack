package mcpflow

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
)

func readRequest(ctx context.Context, request *http.Request) ([]byte, bool, error) {
	if request.Body == nil {
		return nil, false, nil
	}
	var once sync.Once
	failed := false
	closeSource := func() { once.Do(func() { failed = request.Body.Close() != nil }) }
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { closeSource(); close(joined) })
	data, err := io.ReadAll(io.LimitReader(request.Body, MaxRequest+1))
	closeSource()
	if !stop() {
		<-joined
	}
	if err != nil || failed || len(data) > MaxRequest || int64(len(data)) != request.ContentLength || ctx.Err() != nil {
		clear(data)
		return nil, failed, ErrExchange
	}
	return data, false, nil
}

type requestBody struct {
	mu     sync.Mutex
	data   []byte
	offset int
	closed bool
}

func (b *requestBody) Read(destination []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, ErrExchange
	}
	if len(destination) == 0 {
		return 0, nil
	}
	n := copy(destination, b.data[b.offset:])
	b.offset += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *requestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	clear(b.data)
	b.data = nil
	b.offset = 0
	return nil
}

type responseBody struct {
	source   io.ReadCloser
	left     int
	readMu   sync.Mutex
	closed   atomic.Bool
	once     sync.Once
	cancel   context.CancelFunc
	finish   func(bool)
	closeErr error
}

func (b *responseBody) Read(destination []byte) (int, error) {
	b.readMu.Lock()
	if b.closed.Load() {
		b.readMu.Unlock()
		return 0, ErrExchange
	}
	if len(destination) == 0 {
		b.readMu.Unlock()
		return 0, nil
	}
	n, err := b.source.Read(destination[:min(len(destination), b.left+1)])
	if n > b.left || b.closed.Load() {
		n, err = 0, ErrExchange
	} else {
		b.left -= n
		if err != nil && err != io.EOF {
			err = ErrExchange
		}
	}
	b.readMu.Unlock()
	if err != nil {
		if closeErr := b.Close(); closeErr != nil {
			return n, ErrExchange
		}
	}
	return n, err
}

func (b *responseBody) Close() error {
	b.once.Do(func() {
		b.closed.Store(true)
		b.cancel()
		failed := b.source.Close() != nil
		b.readMu.Lock()
		b.readMu.Unlock()
		if failed {
			b.closeErr = ErrExchange
		}
		b.finish(failed)
	})
	return b.closeErr
}
