package apptransport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

const reverseResponseWriteTimeout = 10 * time.Second

func beginReverseResponseWrite(ctx context.Context, w http.ResponseWriter) (func(bool), error) {
	controller := http.NewResponseController(w)
	deadline := time.Now().Add(reverseResponseWriteTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := controller.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = controller.SetWriteDeadline(time.Now())
		case <-stop:
		}
	}()
	return func(success bool) {
		close(stop)
		<-done
		if success && ctx.Err() == nil {
			_ = controller.SetWriteDeadline(time.Time{})
		} else {
			_ = controller.SetWriteDeadline(time.Now())
		}
	}, nil
}

// TextReverseResponseLimit bounds the complete encoded reverse-text response.
const TextReverseResponseLimit = (24 << 20) + (64 << 10)

const boundedReverseError = `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}`

type boundedReverseResponse struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func newBoundedReverseResponse() *boundedReverseResponse {
	return &boundedReverseResponse{header: make(http.Header)}
}

func (w *boundedReverseResponse) Header() http.Header { return w.header }

func (w *boundedReverseResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *boundedReverseResponse) Write(p []byte) (int, error) {
	if w.overflow {
		return 0, io.ErrShortWrite
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if len(p) > TextReverseResponseLimit-w.body.Len() {
		w.overflow = true
		return 0, io.ErrShortWrite
	}
	return w.body.Write(p)
}

// Flush is intentionally a no-op: reverse responses publish only after completion.
func (w *boundedReverseResponse) Flush() {}

func serveBoundedReverseResponse(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	buffered := newBoundedReverseResponse()
	handler.ServeHTTP(buffered, r)
	defer func() {
		clear(buffered.body.Bytes())
		buffered.body.Reset()
		clear(buffered.header)
	}()

	cleanup, err := beginReverseResponseWrite(r.Context(), w)
	if err != nil {
		return
	}
	published := false
	defer func() {
		cleanup(published)
	}()

	if r.Context().Err() != nil || buffered.overflow {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		written, writeErr := io.WriteString(w, boundedReverseError)
		if writeErr == nil && written == len(boundedReverseError) {
			published = http.NewResponseController(w).Flush() == nil
		}
		return
	}
	for key, values := range buffered.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	status := buffered.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	written, writeErr := w.Write(buffered.body.Bytes())
	if writeErr == nil && written == buffered.body.Len() {
		published = http.NewResponseController(w).Flush() == nil
	}
}

var _ http.ResponseWriter = (*boundedReverseResponse)(nil)
var _ interface{ Flush() } = (*boundedReverseResponse)(nil)
