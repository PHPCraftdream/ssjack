package apptransport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
}

func (deadlineRecorder) SetWriteDeadline(time.Time) error {
	return nil
}

func TestServeBoundedReverseResponseOverflowReplacesBody(t *testing.T) {
	largeSentinel := bytes.Repeat([]byte("large-sentinel"), TextReverseResponseLimit/len("large-sentinel")+1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "safe-prefix")
		_, _ = w.Write(largeSentinel)
	})
	recorder := httptest.NewRecorder()
	serveBoundedReverseResponse(deadlineRecorder{recorder}, httptest.NewRequest(http.MethodPost, "/", nil), handler)

	if recorder.Body.String() != boundedReverseError {
		t.Fatalf("body = %q, want fixed error", recorder.Body.String())
	}
	if recorder.Body.Len() > TextReverseResponseLimit {
		t.Fatalf("body length = %d, exceeds limit", recorder.Body.Len())
	}
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response status/content-type = %d/%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}

func TestServeBoundedReverseResponseExactLimitAndImplicitStatus(t *testing.T) {
	body := bytes.Repeat([]byte("x"), TextReverseResponseLimit)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	recorder := httptest.NewRecorder()
	serveBoundedReverseResponse(deadlineRecorder{recorder}, httptest.NewRequest(http.MethodPost, "/", nil), handler)

	if recorder.Code != http.StatusOK || recorder.Body.Len() != TextReverseResponseLimit || !bytes.Equal(recorder.Body.Bytes(), body) {
		t.Fatalf("response status/length/body mismatch: status=%d length=%d", recorder.Code, recorder.Body.Len())
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", recorder.Header().Get("Content-Type"))
	}
}

func TestServeBoundedReverseResponseLatchesOverflowWriteError(t *testing.T) {
	writer := newBoundedReverseResponse()
	if n, err := writer.Write(bytes.Repeat([]byte("x"), TextReverseResponseLimit+1)); n != 0 || err != io.ErrShortWrite {
		t.Fatalf("first overflow Write() = (%d, %v), want (0, %v)", n, err, io.ErrShortWrite)
	}
	if n, err := writer.Write([]byte("later")); n != 0 || err != io.ErrShortWrite {
		t.Fatalf("later Write() = (%d, %v), want (0, %v)", n, err, io.ErrShortWrite)
	}
}

func TestServeBoundedReverseResponseCanceledContextReplacesBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "safe-selected-text")
	})
	recorder := httptest.NewRecorder()
	serveBoundedReverseResponse(deadlineRecorder{recorder}, request, handler)

	if recorder.Body.String() != boundedReverseError || bytes.Contains(recorder.Body.Bytes(), []byte("safe-selected-text")) {
		t.Fatalf("canceled response body = %q, want fixed error", recorder.Body.String())
	}
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response status/content-type = %d/%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}
