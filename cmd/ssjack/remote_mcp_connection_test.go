package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// scriptedWriter owns entry witnesses, an in-write block, a held return gate,
// and the underlying close result; release is idempotent and single-owner.
type scriptedWriter struct {
	entries     chan struct{}
	block       chan struct{}
	returnGate  chan struct{}
	closeSignal chan struct{}

	blockOnce  sync.Once
	returnOnce sync.Once
	short      bool
	err        error
	closeErr   error

	writes     atomic.Int32
	closes     atomic.Int32
	active     atomic.Int32
	overlapped atomic.Bool
}

func (w *scriptedWriter) Write(p []byte) (int, error) {
	if w.active.Add(1) != 1 {
		w.overlapped.Store(true)
	}
	defer w.active.Add(-1)
	if w.entries != nil {
		w.entries <- struct{}{}
	}
	if w.block != nil {
		<-w.block
	}
	w.writes.Add(1)
	defer func() {
		if w.returnGate != nil {
			<-w.returnGate
		}
	}()
	if w.short {
		return len(p) - 1, nil
	}
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func (w *scriptedWriter) Close() error {
	first := w.closes.Add(1) == 1
	if first {
		if w.block != nil {
			w.blockOnce.Do(func() { close(w.block) })
		}
		if w.closeSignal != nil {
			close(w.closeSignal)
		}
	}
	return w.closeErr
}

// release unblocks the gates exactly once; repeats and post-Close calls are no-ops.
func (w *scriptedWriter) release() {
	if w.block != nil {
		w.blockOnce.Do(func() { close(w.block) })
	}
	if w.returnGate != nil {
		w.returnOnce.Do(func() { close(w.returnGate) })
	}
}

func TestMCPStdioConnectionRefusesShortAndFailedWrites(t *testing.T) {
	failure := errors.New("synthetic owned write failure")
	for _, tt := range []struct {
		name   string
		writer *scriptedWriter
		want   error
	}{
		{"short", &scriptedWriter{short: true}, io.ErrShortWrite},
		{"failed", &scriptedWriter{err: failure}, failure},
	} {
		connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), tt.writer)
		if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, tt.want) {
			t.Fatalf("%s owned write lost its exact fixed error: %v", tt.name, err)
		}
		if tt.writer.writes.Load() != 1 {
			t.Fatalf("%s underlying writer was not exercised exactly once", tt.name)
		}
	}
}

func TestMCPStdioConnectionRetainsGenuineCloseResult(t *testing.T) {
	closeRefusal := errors.New("synthetic owned close refusal")
	writer := &scriptedWriter{closeErr: closeRefusal}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); err != nil {
		t.Fatalf("successful owned write was rejected: %v", err)
	}
	if err := connection.Close(); !errors.Is(err, closeRefusal) {
		t.Fatalf("owned close lost its retained result: %v", err)
	}
	if err := connection.Close(); !errors.Is(err, closeRefusal) {
		t.Fatalf("repeated owned close did not retain its result: %v", err)
	}
	if writer.closes.Load() != 1 {
		t.Fatal("repeated close re-closed the owned writer")
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("write after close was not refused with the fixed error: %v", err)
	}
}

func TestMCPStdioConnectionSerializesContendedWrites(t *testing.T) {
	writer := &scriptedWriter{entries: make(chan struct{}, 4), block: make(chan struct{})}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	firstExited := make(chan struct{})
	secondExited := make(chan struct{})
	errs := make(chan error, 2)
	t.Cleanup(func() {
		writer.release()
		joinExited(t, firstExited, "first owned write worker did not exit")
		joinExited(t, secondExited, "second owned write worker did not exit")
	})
	// Pre-holding writeMu delays both launches behind the mutex but does not
	// prove either goroutine reached it before unlock; coverage is scheduler-dependent.
	connection.writeMu.Lock()
	go func() {
		defer close(firstExited)
		errs <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	go func() {
		defer close(secondExited)
		errs <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	connection.writeMu.Unlock()
	awaitSignal(t, writer.entries, "first owned write did not enter the underlying writer")
	select {
	case <-writer.entries:
		t.Fatal("second owned write entered the writer while the first held it")
	case <-time.After(50 * time.Millisecond):
	}
	if writer.overlapped.Load() {
		t.Fatal("concurrent owned writes overlapped inside the writer")
	}
	writer.release()
	if err := awaitSignal(t, errs, "first contended owned write did not return"); err != nil {
		t.Fatal(err)
	}
	if err := awaitSignal(t, errs, "second contended owned write did not return"); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, firstExited, "first owned write worker did not exit")
	awaitSignal(t, secondExited, "second owned write worker did not exit")
	if writer.overlapped.Load() {
		t.Fatal("contended owned writes overlapped before both completed")
	}
}

func TestMCPStdioConnectionCloseJoinsHeldWriteAndRetainsResult(t *testing.T) {
	closeRefusal := errors.New("synthetic owned close refusal")
	writer := &scriptedWriter{entries: make(chan struct{}, 8), block: make(chan struct{}), returnGate: make(chan struct{}), closeSignal: make(chan struct{}), closeErr: closeRefusal}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	const closers = 3
	writeExited := make(chan struct{})
	closeExited := make(chan struct{})
	closerExited := make(chan struct{}, closers-1)
	var closeLaunched atomic.Int32
	t.Cleanup(func() {
		writer.release()
		joinExited(t, writeExited, "held write worker did not exit")
		if n := int(closeLaunched.Load()); n > 0 {
			joinExited(t, closeExited, "first close worker did not exit")
			for i := 0; i < n-1; i++ {
				joinExited(t, closerExited, "concurrent close worker did not exit")
			}
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		defer close(writeExited)
		writeDone <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	awaitSignal(t, writer.entries, "owned write did not enter the blocked writer")
	closeDone := make(chan error, closers)
	closeLaunched.Add(1)
	go func() {
		defer close(closeExited)
		closeDone <- connection.Close()
	}()
	awaitSignal(t, writer.closeSignal, "owned close did not release the underlying writer")
	for i := 0; i < closers-1; i++ {
		closeLaunched.Add(1)
		go func() {
			defer func() { closerExited <- struct{}{} }()
			closeDone <- connection.Close()
		}()
	}
	select {
	case err := <-closeDone:
		t.Fatalf("a close returned before the held write returned: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	writer.release()
	for i := 0; i < closers; i++ {
		if err := awaitSignal(t, closeDone, "owned close did not join the held write"); !errors.Is(err, closeRefusal) {
			t.Fatalf("owned close lost its retained result: %v", err)
		}
	}
	if err := awaitSignal(t, writeDone, "held owned write did not return"); err != nil {
		t.Fatalf("admitted blocked write did not complete once released: %v", err)
	}
	if writer.closes.Load() != 1 {
		t.Fatal("owned writer was closed more than once")
	}
}

func TestMCPStdioConnectionRefusesTrackedResponseAfterClose(t *testing.T) {
	stream := []byte(`[{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]` + "\n")
	rawResponse := []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`)
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(stream)), &scriptedWriter{})
	if _, err := connection.Read(context.Background()); err != nil {
		t.Fatalf("legacy batch head did not decode: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("owned close failed: %v", err)
	}
	response, err := jsonrpc.DecodeMessage(rawResponse)
	if err != nil {
		t.Fatalf("synthetic tracked response did not decode: %v", err)
	}
	if err := connection.Write(context.Background(), response); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("tracked batch response after close was not refused with the fixed error: %v", err)
	}
	connection.batchMu.Lock()
	tracked := len(connection.batches)
	connection.batchMu.Unlock()
	if tracked != 1 {
		t.Fatalf("refused tracked response mutated batch state: %d entries", tracked)
	}
}

func TestMCPStdioConnectionRefusesAdmissionWhileShutdownHeld(t *testing.T) {
	writer := &scriptedWriter{entries: make(chan struct{}, 4), block: make(chan struct{}), returnGate: make(chan struct{}), closeSignal: make(chan struct{})}
	connection := newMCPStdioTransport(io.NopCloser(bytes.NewReader(nil)), writer)
	writeExited := make(chan struct{})
	closeExited := make(chan struct{})
	var closeLaunched atomic.Int32
	t.Cleanup(func() {
		writer.release()
		joinExited(t, writeExited, "held write worker did not exit")
		if closeLaunched.Load() == 1 {
			joinExited(t, closeExited, "close worker did not exit")
		}
	})
	writeDone := make(chan error, 1)
	go func() {
		defer close(writeExited)
		writeDone <- connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"})
	}()
	awaitSignal(t, writer.entries, "owned write did not enter the blocked writer")
	closeLaunched.Add(1)
	closeDone := make(chan error, 1)
	go func() {
		defer close(closeExited)
		closeDone <- connection.Close()
	}()
	awaitSignal(t, writer.closeSignal, "owned close did not release the underlying writer")
	select {
	case err := <-closeDone:
		t.Fatalf("shutdown returned while the admitted write was still held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := connection.Write(context.Background(), &jsonrpc.Request{Method: "ping"}); !errors.Is(err, errMCPStdioWriterClosed) {
		t.Fatalf("write admitted while shutdown was held lost the fixed refusal: %v", err)
	}
	writer.release()
	if err := awaitSignal(t, writeDone, "admitted held write did not return after release"); err != nil {
		t.Fatalf("admitted held write failed once released: %v", err)
	}
	if err := awaitSignal(t, closeDone, "owned close did not return"); err != nil {
		t.Fatalf("owned close failed: %v", err)
	}
	if writer.closes.Load() != 1 {
		t.Fatal("owned writer was closed more than once")
	}
}
