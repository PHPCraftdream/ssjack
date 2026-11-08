package main

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type fragmentedMCPInput struct {
	data []byte
	n    int
}

func (r *fragmentedMCPInput) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), min(r.n, len(r.data)))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}
func (*fragmentedMCPInput) Close() error { return nil }

func readBoundedMCP(t *testing.T, input io.ReadCloser) ([]byte, error) {
	t.Helper()
	return io.ReadAll(newBoundedMCPStdioReader(input))
}

func TestBoundedMCPStdioReaderPreservesFragmentsAndDoesNotFilter(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","id":"known-literal","method":"tools/call","params":{"name":"known-literal","arguments":{"token":"known-literal"}}}` + "\n")
	got, err := readBoundedMCP(t, &fragmentedMCPInput{data: append([]byte(nil), frame...), n: 3})
	if err != nil {
		t.Fatal("fragmented valid MCP frame was refused")
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("stdio reader changed the original JSON-RPC bytes: got %q", got)
	}
}

func TestMCPProtocolVersionsAndUnknownVersionAdmission(t *testing.T) {
	for _, version := range []string{mcpProtocol20241105, mcpProtocol20250326, mcpProtocol20250618} {
		frame := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `"}}` + "\n"
		if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: []byte(frame), n: len(frame)}); err != nil {
			t.Fatalf("supported initialization version %q refused", version)
		}
	}
	first := []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2099-01-01\"}}\n")
	input := &fragmentedMCPInput{data: append(append([]byte(nil), first...), []byte(`{"jsonrpc":"2.0","method":"ping"}`+"\n")...), n: len(first)}
	reader := newBoundedMCPStdioReader(input)
	buf := make([]byte, 1)
	if n, err := reader.Read(buf); n != 0 || err == nil {
		t.Fatal("unsupported initialize was not rejected before yielding frame bytes")
	}
	if len(input.data) == 0 || string(input.data[:1]) != "{" {
		t.Fatal("reader consumed bytes from the following frame before rejecting the version")
	}
}

func TestBoundedMCPStdioRejectsDuplicateAdmissionFieldsBeforeYield(t *testing.T) {
	for _, frame := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"unsupported","method":"ping"}` + "\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01","protocolVersion":"2025-06-18"}}` + "\n",
	} {
		input := &fragmentedMCPInput{data: []byte(frame), n: len(frame)}
		reader := newBoundedMCPStdioReader(input)
		buf := make([]byte, 1)
		if n, err := reader.Read(buf); n != 0 || err == nil {
			t.Fatalf("duplicate admission field was not rejected before yielding frame bytes: %q", frame)
		}
	}
}

func TestBoundedMCPStdioMessageByteLimitAtEOF(t *testing.T) {
	base := []byte(`{"method":"ping"}`)
	for _, size := range []int{maxMCPStdioMessage, maxMCPStdioMessage + 1} {
		frame := append(append([]byte(nil), base...), bytes.Repeat([]byte{' '}, size-len(base))...)
		_, err := readBoundedMCP(t, &fragmentedMCPInput{data: frame, n: 4093})
		if size == maxMCPStdioMessage && err != nil {
			t.Fatal("exactly bounded JSON frame was refused")
		}
		if size == maxMCPStdioMessage+1 && err == nil {
			t.Fatal("one-byte-oversized JSON frame was admitted")
		}
	}
}

func TestBoundedMCPStdioMessageCountAndMethods(t *testing.T) {
	frame := []byte(`{"method":"ping"}` + "\n")
	var stream []byte
	for range maxMCPStdioMessages + 1 {
		stream = append(stream, frame...)
	}
	if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: stream, n: 8191}); err == nil {
		t.Fatal("stream exceeding the bounded message count was admitted")
	}
	batch := `[` + strings.TrimSuffix(strings.Repeat(string(frame[:len(frame)-1])+",", maxMCPStdioMessages+1), ",") + `]` + "\n"
	if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: []byte(batch), n: 2047}); err == nil {
		t.Fatal("oversized JSON-RPC batch was admitted")
	}
	for _, method := range []string{"$/arbitrary", "resources/read", "prompts/list"} {
		unknown := []byte(`{"jsonrpc":"2.0","method":"` + method + `"}` + "\n")
		if _, err := readBoundedMCP(t, &fragmentedMCPInput{data: unknown, n: len(unknown)}); err == nil {
			t.Fatalf("unsupported upstream method %q was admitted", method)
		}
	}
}

type blockedMCPInput struct {
	reader      *io.PipeReader
	writer      *io.PipeWriter
	started     chan struct{}
	awakened    chan struct{}
	allowReturn chan struct{}
	readDone    chan struct{}
	closeOnce   sync.Once
}

func newBlockedMCPInput() *blockedMCPInput {
	reader, writer := io.Pipe()
	return &blockedMCPInput{reader: reader, writer: writer, started: make(chan struct{}), awakened: make(chan struct{}), allowReturn: make(chan struct{}), readDone: make(chan struct{})}
}
func (r *blockedMCPInput) Read(p []byte) (int, error) {
	close(r.started)
	n, err := r.reader.Read(p)
	<-r.allowReturn
	close(r.readDone)
	return n, err
}
func (r *blockedMCPInput) Close() error {
	var err error
	r.closeOnce.Do(func() {
		err = r.reader.Close()
		_ = r.writer.Close()
		close(r.awakened)
	})
	return err
}

func TestBoundedMCPStdioCloseUnblocksAndJoinsRead(t *testing.T) {
	source := newBlockedMCPInput()
	reader := newBoundedMCPStdioReader(source)
	readDone := make(chan struct{})
	closeDone := make(chan error, 1)
	closeFinished := make(chan struct{})
	var closeLaunch sync.Once
	launchClose := func() {
		closeLaunch.Do(func() {
			go func() {
				defer close(closeFinished)
				closeDone <- reader.Close()
			}()
		})
	}
	var releaseOnce sync.Once
	t.Cleanup(func() {
		select {
		case <-readDone:
		case <-time.After(2 * time.Second):
			t.Errorf("blocked reader read did not join after gate release")
		}
	})
	t.Cleanup(func() {
		select {
		case <-closeFinished:
		case <-time.After(2 * time.Second):
			t.Errorf("owned reader close work did not complete after gate release")
		}
	})
	t.Cleanup(launchClose)
	t.Cleanup(func() { releaseOnce.Do(func() { close(source.allowReturn) }) })
	go func() { _, _ = reader.Read(make([]byte, 1)); close(readDone) }()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("reader did not enter the blocked source")
	}
	launchClose()
	closeReturnedEarly := false
	var closeErr error
	select {
	case <-source.awakened:
	case <-time.After(time.Second):
		t.Fatal("Close did not close the owned input")
	}
	select {
	case err := <-closeDone:
		closeReturnedEarly = true
		closeErr = err
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(source.allowReturn) })
	select {
	case <-source.readDone:
	case <-time.After(time.Second):
		t.Fatal("source read barrier did not complete after release")
	}
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("blocked read did not finish after source close")
	}
	if !closeReturnedEarly {
		select {
		case err := <-closeDone:
			closeErr = err
		case <-time.After(time.Second):
			t.Fatal("reader Close did not join the read")
		}
	}
	if closeReturnedEarly {
		t.Fatal("reader Close returned before its blocked read barrier joined")
	}
	if closeErr != nil {
		t.Fatal("reader close failed")
	}
	if err := reader.Close(); err != nil {
		t.Fatal("repeated reader close returned an unexpected error")
	}
}
