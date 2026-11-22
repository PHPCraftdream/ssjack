package remotemcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PHPCraftdream/ssjack/internal/mcpjson"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"sync"
	"time"
)

const remoteMCPStdioWriteBudget = 15 * time.Second

// mcpStdioConnection adapts the bounded stdio reader and stdout writer to the
// pinned SDK Transport and Connection interfaces without weakening any bound.
// Every Write path is admitted against shutdown and joined by Close; the
// physical write runs in an abandonable worker so a writer whose Close does
// not release a blocked write cannot hold the logical call past the budget.
// Inbound legacy JSON-RPC batches are split for the SDK and their call
// responses are emitted as one JSON array.
type mcpStdioConnection struct {
	reader          *boundedMCPStdioReader
	writer          io.WriteCloser
	queue           []jsonrpc.Message
	protocolVersion string
	writeBudget     time.Duration

	writeToken chan struct{}
	failed     chan struct{}
	failedOnce sync.Once
	admitMu    sync.Mutex
	closing    bool
	failure    error
	writes     sync.WaitGroup

	batchMu sync.Mutex
	batches map[jsonrpc.ID]*mcpStdioBatch

	closeOnce       sync.Once
	closeErr        error
	writerCloseOnce sync.Once
	writerCloseErr  error
}

// mcpStdioWriteResult carries one abandoned-safe physical write outcome.
type mcpStdioWriteResult struct {
	n   int
	err error
}

// mcpStdioBatch tracks one inbound legacy batch so its call responses are
// emitted as a single array, mirroring the pinned SDK stdio framing.
type mcpStdioBatch struct {
	unresolved map[jsonrpc.ID]int
	responses  []*jsonrpc.Response
}

var (
	errMCPStdioBatchUnsupported = errors.New("JSON-RPC batching is not supported")
	errMCPStdioWriteTimeout     = errors.New("MCP stdio write timed out")
)

var _ mcp.Transport = (*mcpStdioConnection)(nil)

func newMCPStdioTransport(reader io.ReadCloser, writer io.WriteCloser) *mcpStdioConnection {
	connection := &mcpStdioConnection{
		reader:      newBoundedMCPStdioReader(reader),
		writer:      writer,
		writeBudget: remoteMCPStdioWriteBudget,
		writeToken:  make(chan struct{}, 1),
		failed:      make(chan struct{}),
	}
	connection.writeToken <- struct{}{}
	return connection
}

func (c *mcpStdioConnection) Connect(context.Context) (mcp.Connection, error) { return c, nil }

// Read yields only supported messages; a frame whose messages were all
// refused yields nothing, so the next frame is read.
func (c *mcpStdioConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	for len(c.queue) == 0 {
		frame := make([]byte, maxMCPStdioMessage+1)
		n, err := c.reader.Read(frame)
		if err != nil {
			if failure := c.writeFailure(); failure != nil {
				return nil, failure
			}
			return nil, err
		}
		messages, batch, err := decodeMCPFrame(frame[:n])
		if err != nil {
			return nil, err
		}
		if batch && (c.protocolVersion >= mcpProtocol20250618 || batchHasModernProtocolVersion(messages)) {
			return nil, fmt.Errorf("JSON-RPC batching is not supported in %s and later: %w", mcpProtocol20250618, errMCPStdioBatchUnsupported)
		}
		if batch {
			if err := c.trackBatch(messages); err != nil {
				return nil, err
			}
		}
		c.trackNegotiatedVersion(messages)
		if c.queue, err = c.refuseUnsupported(ctx, messages); err != nil {
			return nil, err
		}
	}
	next := c.queue[0]
	c.queue = c.queue[1:]
	return next, nil
}

// Write admits every path through admitWrite before touching any state: a
// Write is either fully registered with the shutdown join or refused after
// Close. A tracked incomplete batch response is buffered as admitted work; a
// completed batch is emitted as one array.
func (c *mcpStdioConnection) Write(ctx context.Context, message jsonrpc.Message) error {
	if err := c.admitWrite(); err != nil {
		return err
	}
	defer c.writes.Done()
	if resp, ok := message.(*jsonrpc.Response); ok {
		batch, complete := c.updateBatch(resp)
		if complete && len(batch) > 0 {
			return c.writeBatch(ctx, batch)
		}
		if complete {
			return nil
		}
	}
	data, err := jsonrpc.EncodeMessage(message)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return c.writeAll(ctx, data)
}

// Close flips the guarded closing flag before waiting, so a Write is either
// fully admitted before the join or refused after it. It closes the owned
// writer without taking the write slot, joins admitted logical writes, and
// closes the owned reader without joining a blocked physical read: a stalled
// peer cannot hold shutdown because abandoned physical operations are never
// joined. It is idempotent with the same owned result on every call.
func (c *mcpStdioConnection) Close() error {
	c.closeOnce.Do(func() {
		c.admitMu.Lock()
		c.closing = true
		c.admitMu.Unlock()
		writeErr := c.closeWriter()
		c.writes.Wait()
		readErr := c.reader.Close()
		c.closeErr = errors.Join(writeErr, readErr)
	})
	return c.closeErr
}

func (*mcpStdioConnection) SessionID() string { return "" }

// admitWrite registers one Write with the shutdown join under admitMu, so the
// registration cannot interleave with Close flipping the closing flag.
func (c *mcpStdioConnection) admitWrite() error {
	c.admitMu.Lock()
	defer c.admitMu.Unlock()
	if c.closing {
		if c.failure != nil {
			return c.failure
		}
		return errMCPStdioWriterClosed
	}
	c.writes.Add(1)
	return nil
}

func (c *mcpStdioConnection) writeFailure() error {
	c.admitMu.Lock()
	defer c.admitMu.Unlock()
	return c.failure
}

func (c *mcpStdioConnection) failWrites(err error) error {
	c.admitMu.Lock()
	c.closing = true
	if c.failure == nil {
		c.failure = err
	}
	failure := c.failure
	c.failedOnce.Do(func() { close(c.failed) })
	c.admitMu.Unlock()
	return failure
}

// writeRelease returns the write slot. Only the slot owner calls it; the
// timeout path abandons the slot with its worker instead.
func (c *mcpStdioConnection) writeRelease() {
	c.writeToken <- struct{}{}
}

func (c *mcpStdioConnection) closeWriter() error {
	c.writerCloseOnce.Do(func() { c.writerCloseErr = c.writer.Close() })
	return c.writerCloseErr
}

// interruptWrites latches the failure and closes only owned I/O; callers must
// not join admitted writes here because a writer failure may be self-owned.
func (c *mcpStdioConnection) interruptWrites(err error) error {
	failure := c.failWrites(err)
	c.closeWriter()
	_ = c.reader.Close()
	return failure
}

// writeAll starts the bound before taking the write slot; the physical write
// runs in an abandonable worker, so a writer whose Close does not release a
// blocked write cannot hold the logical call past the bound. On expiry the
// worker and the slot are abandoned: the slot is never returned and the
// latched failure refuses every later Write, so no frame can follow a
// timed-out one.
func (c *mcpStdioConnection) writeAll(ctx context.Context, data []byte) (result error) {
	writeCtx, cancel := context.WithTimeout(ctx, c.writeBudget)
	callbackDone := make(chan struct{})
	stopWatch := context.AfterFunc(writeCtx, func() {
		defer close(callbackDone)
		c.interruptWrites(errMCPStdioWriteTimeout)
	})
	defer func() {
		if !stopWatch() {
			<-callbackDone
		}
		cancel()
		if failure := c.writeFailure(); failure != nil {
			result = failure
		}
	}()
	if writeCtx.Err() != nil {
		return c.interruptWrites(errMCPStdioWriteTimeout)
	}
	select {
	case <-c.writeToken:
	case <-c.failed:
		return c.writeFailure()
	case <-writeCtx.Done():
		return c.interruptWrites(errMCPStdioWriteTimeout)
	}
	c.admitMu.Lock()
	closing, failure := c.closing, c.failure
	c.admitMu.Unlock()
	if failure != nil {
		c.writeRelease()
		return failure
	}
	if closing {
		c.writeRelease()
		return errMCPStdioWriterClosed
	}
	if writeCtx.Err() != nil {
		c.writeRelease()
		return c.interruptWrites(errMCPStdioWriteTimeout)
	}
	done := make(chan mcpStdioWriteResult, 1)
	go func() {
		n, err := c.writer.Write(data)
		done <- mcpStdioWriteResult{n: n, err: err}
	}()
	select {
	case res := <-done:
		if res.err == nil && res.n != len(data) {
			res.err = io.ErrShortWrite
		}
		if res.err != nil {
			// Stop queued writes before releasing the slot: a partial frame
			// cannot be followed by another frame on the same stream.
			c.interruptWrites(res.err)
			c.writeRelease()
			return res.err
		}
		c.writeRelease()
	case <-writeCtx.Done():
		return c.interruptWrites(errMCPStdioWriteTimeout)
	}
	return nil
}

func (c *mcpStdioConnection) writeBatch(ctx context.Context, batch []*jsonrpc.Response) error {
	encoded := make([]json.RawMessage, 0, len(batch))
	for _, response := range batch {
		raw, err := jsonrpc.EncodeMessage(response)
		if err != nil {
			return err
		}
		encoded = append(encoded, raw)
	}
	data, err := json.Marshal(encoded)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return c.writeAll(ctx, data)
}

// trackBatch records the call identifiers of one inbound legacy batch so their
// responses can be correlated into a single array reply.
func (c *mcpStdioConnection) trackBatch(messages []jsonrpc.Message) error {
	var respBatch *mcpStdioBatch
	for _, message := range messages {
		req, ok := message.(*jsonrpc.Request)
		if !ok || !req.ID.IsValid() {
			continue
		}
		if respBatch == nil {
			respBatch = &mcpStdioBatch{unresolved: make(map[jsonrpc.ID]int)}
		}
		if _, dup := respBatch.unresolved[req.ID]; dup {
			return errors.New("duplicate JSON-RPC batch request ID")
		}
		respBatch.unresolved[req.ID] = len(respBatch.responses)
		respBatch.responses = append(respBatch.responses, nil)
	}
	if respBatch == nil {
		return nil
	}
	c.batchMu.Lock()
	defer c.batchMu.Unlock()
	for id := range respBatch.unresolved {
		if _, dup := c.batches[id]; dup {
			return errors.New("batch contains a previously seen JSON-RPC batch request ID")
		}
	}
	for id := range respBatch.unresolved {
		if c.batches == nil {
			c.batches = make(map[jsonrpc.ID]*mcpStdioBatch)
		}
		c.batches[id] = respBatch
	}
	return nil
}

func (c *mcpStdioConnection) updateBatch(resp *jsonrpc.Response) ([]*jsonrpc.Response, bool) {
	c.batchMu.Lock()
	defer c.batchMu.Unlock()
	batch, tracked := c.batches[resp.ID]
	if !tracked {
		return nil, false
	}
	batch.responses[batch.unresolved[resp.ID]] = resp
	delete(batch.unresolved, resp.ID)
	delete(c.batches, resp.ID)
	if len(batch.unresolved) == 0 {
		return batch.responses, true
	}
	return nil, true
}

func batchHasModernProtocolVersion(messages []jsonrpc.Message) bool {
	for _, message := range messages {
		req, ok := message.(*jsonrpc.Request)
		if !ok {
			continue
		}

		if len(req.Params) == 0 {
			if req.Method == "initialize" && negotiatedMCPVersion("") >= mcpProtocol20250618 {
				return true
			}
			continue
		}

		var params map[string]json.RawMessage
		if err := json.Unmarshal(req.Params, &params); err != nil || params == nil {
			return true
		}

		malformed := false
		modern := false
		if rawVersion, present := params["protocolVersion"]; present {
			var version string
			if err := json.Unmarshal(rawVersion, &version); err != nil || version == "" {
				malformed = true
			} else if parsed, err := time.Parse("2006-01-02", version); err != nil || parsed.Format("2006-01-02") != version {
				malformed = true
			} else if req.Method == "initialize" && negotiatedMCPVersion(version) >= mcpProtocol20250618 {
				modern = true
			}
		} else if req.Method == "initialize" && negotiatedMCPVersion("") >= mcpProtocol20250618 {
			modern = true
		}

		if rawMeta, present := params["_meta"]; present {
			var meta map[string]json.RawMessage
			if err := json.Unmarshal(rawMeta, &meta); err != nil || meta == nil {
				malformed = true
			} else if rawVersion, present := meta["io.modelcontextprotocol/protocolVersion"]; present {
				var version string
				if err := json.Unmarshal(rawVersion, &version); err != nil || version == "" {
					malformed = true
				} else if parsed, err := time.Parse("2006-01-02", version); err != nil || parsed.Format("2006-01-02") != version {
					malformed = true
				} else if version >= mcpProtocol20250618 {
					modern = true
				}
			}
		}

		if malformed || modern {
			return true
		}
	}
	return false
}

// trackNegotiatedVersion derives the negotiated protocol version from the
// initialize request visible on this connection, mirroring the SDK server's
// own version update without any unexported SDK hook.
func (c *mcpStdioConnection) trackNegotiatedVersion(messages []jsonrpc.Message) {
	for _, message := range messages {
		req, ok := message.(*jsonrpc.Request)
		if !ok || req.Method != "initialize" {
			continue
		}
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(req.Params, &params) == nil {
			c.protocolVersion = negotiatedMCPVersion(params.ProtocolVersion)
		}
		return
	}
}

func negotiatedMCPVersion(version string) string {
	if !supportedMCPProtocol(version) || version >= mcpProtocol20260728 {
		return mcpProtocol20251125
	}
	return version
}

func decodeMCPFrame(frame []byte) ([]jsonrpc.Message, bool, error) {
	var rawMessages []json.RawMessage
	if err := json.Unmarshal(frame, &rawMessages); err == nil {
		if len(rawMessages) == 0 {
			return nil, true, errors.New("empty batch")
		}
		messages := make([]jsonrpc.Message, 0, len(rawMessages))
		for _, raw := range rawMessages {
			message, err := jsonrpc.DecodeMessage(raw)
			if err != nil {
				return nil, true, err
			}
			messages = append(messages, message)
		}
		return messages, true, nil
	}
	message, err := jsonrpc.DecodeMessage(frame)
	return []jsonrpc.Message{message}, false, err
}

const (
	maxMCPStdioMessage  = 256 << 10
	maxMCPStdioMessages = 4096
	mcpProtocol20241105 = "2024-11-05"
	mcpProtocol20250326 = "2025-03-26"
	mcpProtocol20250618 = "2025-06-18"
	mcpProtocol20251125 = "2025-11-25"
	mcpProtocol20260728 = "2026-07-28"
)

var (
	errMCPStdioReaderClosed      = errors.New("MCP stdio reader is closed")
	errMCPStdioConcurrentRead    = errors.New("concurrent MCP stdio read refused")
	errMCPStdioMessageLimit      = errors.New("MCP stdio message exceeds limit")
	errMCPStdioMessageCountLimit = errors.New("MCP stdio message limit exceeded")
	errMCPStdioInvalidMessage    = errors.New("invalid MCP stdio message")
	errMCPStdioUnsupportedMethod = errors.New("unsupported MCP method")
	errMCPStdioWriterClosed      = errors.New("MCP stdio writer is closed")
)

type boundedMCPStdioReader struct {
	reader    *bufio.Reader
	source    io.ReadCloser
	pending   []byte
	frame     []byte
	messages  int
	eof       bool
	mu        sync.Mutex
	closing   bool
	active    bool
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// mcpStdioReadResult carries one abandoned-safe physical read outcome.
type mcpStdioReadResult struct {
	n   int
	err error
}

func newBoundedMCPStdioReader(reader io.ReadCloser) *boundedMCPStdioReader {
	return &boundedMCPStdioReader{
		reader: bufio.NewReaderSize(reader, 4096),
		source: reader,
		closed: make(chan struct{}),
	}
}

// Read frames one message through the bounded reader. The blocking source
// read runs in an abandonable worker: a source whose Close does not release
// a blocked read cannot hold the logical call after Close, which latches the
// closed state and abandons the worker (its goroutine may live until process
// exit) instead of joining it.
func (r *boundedMCPStdioReader) Read(target []byte) (int, error) {
	r.mu.Lock()
	if r.closing {
		r.mu.Unlock()
		return 0, errMCPStdioReaderClosed
	}
	if len(target) == 0 {
		r.mu.Unlock()
		return 0, nil
	}
	if r.active {
		r.mu.Unlock()
		return 0, errMCPStdioConcurrentRead
	}
	r.active = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active = false
		r.mu.Unlock()
	}()

	done := make(chan mcpStdioReadResult, 1)
	go r.readFrame(target, done)
	select {
	case res := <-done:
		return res.n, res.err
	case <-r.closed:
		return 0, errMCPStdioReaderClosed
	}
}

// readFrame is the former Read body up to and including the framing loop. It
// sends exactly one result; the buffered channel keeps an abandoned worker
// from blocking on its send. Once abandoned it is the only goroutine touching
// the framing state, and Close refuses every later logical read.
func (r *boundedMCPStdioReader) readFrame(target []byte, done chan<- mcpStdioReadResult) {
	if len(r.pending) != 0 {
		n, _ := r.copyPending(target)
		done <- mcpStdioReadResult{n: n}
		return
	}
	if r.eof {
		done <- mcpStdioReadResult{err: io.EOF}
		return
	}
	for {
		chunk, err := r.reader.ReadSlice('\n')
		complete := len(chunk) != 0 && chunk[len(chunk)-1] == '\n'
		payload := chunk
		if complete {
			payload = chunk[:len(chunk)-1]
		}
		if len(r.frame)+len(payload) > maxMCPStdioMessage {
			done <- mcpStdioReadResult{err: errMCPStdioMessageLimit}
			return
		}
		r.frame = append(r.frame, payload...)
		if complete {
			r.frame = append(r.frame, '\n')
			if err := r.admitFrame(); err != nil {
				done <- mcpStdioReadResult{err: err}
				return
			}
			n, _ := r.copyPending(target)
			done <- mcpStdioReadResult{n: n}
			return
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			r.eof = true
			if len(r.frame) == 0 {
				done <- mcpStdioReadResult{err: io.EOF}
				return
			}
			if err := r.admitFrame(); err != nil {
				done <- mcpStdioReadResult{err: err}
				return
			}
			n, _ := r.copyPending(target)
			done <- mcpStdioReadResult{n: n}
			return
		}
		if err != nil {
			done <- mcpStdioReadResult{err: err}
			return
		}
	}
}

func (r *boundedMCPStdioReader) copyPending(target []byte) (int, error) {
	n := copy(target, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *boundedMCPStdioReader) admitFrame() error {
	var messages []json.RawMessage
	if json.Unmarshal(r.frame, &messages) == nil {
		if len(messages) == 0 || len(messages) > maxMCPStdioMessages-r.messages {
			return errMCPStdioMessageCountLimit
		}
		for _, message := range messages {
			if err := validateMCPStdioMessage(message); err != nil {
				return err
			}
		}
		r.messages += len(messages)
	} else {
		if r.messages >= maxMCPStdioMessages {
			return errMCPStdioMessageCountLimit
		}
		if err := validateMCPStdioMessage(r.frame); err != nil {
			return err
		}
		r.messages++
	}
	r.pending = r.frame
	r.frame = nil
	return nil
}

func validateMCPStdioMessage(frame []byte) error {
	decoded, err := mcpjson.Decode(frame, maxMCPStdioMessage, 32, 8192)
	if err != nil {
		return errMCPStdioInvalidMessage
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return errMCPStdioInvalidMessage
	}
	if version, present := object["jsonrpc"]; present && version != "2.0" {
		return errMCPStdioInvalidMessage
	}
	if method, present := object["method"]; present {
		if _, ok := method.(string); !ok {
			return errMCPStdioInvalidMessage
		}
	}
	// The method surface is enforced by the connection, which can answer a
	// refused call instead of ending the session; an unknown initialize
	// version is negotiated down by the SDK.
	return nil
}

// supportedMCPMethod is the whole surface the bridge admits to the SDK.
func supportedMCPMethod(method string) bool {
	switch method {
	case "initialize", "notifications/initialized", "notifications/cancelled", "tools/list", "tools/call", "ping", "server/discover", "subscriptions/listen", "tasks/get", "tasks/update", "tasks/cancel":
		return true
	}
	return false
}

// taskMethod reports whether method belongs to the tasks extension, which
// only revision 2026-07-28 and later serve.
func taskMethod(method string) bool {
	switch method {
	case "tasks/get", "tasks/update", "tasks/cancel":
		return true
	}
	return false
}

// supportedMCPProtocol lists protocol versions accepted by the stdio transport.
func supportedMCPProtocol(version string) bool {
	switch version {
	case mcpProtocol20260728, mcpProtocol20251125, mcpProtocol20250618, mcpProtocol20250326, mcpProtocol20241105:
		return true
	}
	return false
}

func supportedMCPProtocols() []string {
	return []string{mcpProtocol20260728, mcpProtocol20251125, mcpProtocol20250618, mcpProtocol20250326, mcpProtocol20241105}
}

func (*mcpStdioConnection) SupportsProtocolVersion(version string) bool {
	return supportedMCPProtocol(version)
}

// Close latches the closed state, releases the owned source if it can, and
// returns without joining an in-flight read: the read is abandoned and its
// worker may live until process exit. The retained source close result is
// returned on every call.
func (r *boundedMCPStdioReader) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		close(r.closed)
		r.mu.Unlock()
		r.closeErr = r.source.Close()
	})
	return r.closeErr
}
