package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpStdioConnection adapts the bounded stdio reader and stdout writer to the
// pinned SDK Transport and Connection interfaces without weakening any bound.
// Every Write path is admitted against shutdown and joined by Close; inbound
// legacy JSON-RPC batches are split for the SDK and their call responses are
// emitted as one JSON array.
type mcpStdioConnection struct {
	reader          *boundedMCPStdioReader
	writer          io.WriteCloser
	queue           []jsonrpc.Message
	protocolVersion string

	writeMu sync.Mutex
	admitMu sync.Mutex
	closing bool
	writes  sync.WaitGroup

	batchMu sync.Mutex
	batches map[jsonrpc.ID]*mcpStdioBatch

	closeOnce sync.Once
	closeErr  error
}

// mcpStdioBatch tracks one inbound legacy batch so its call responses are
// emitted as a single array, mirroring the pinned SDK stdio framing.
type mcpStdioBatch struct {
	unresolved map[jsonrpc.ID]int
	responses  []*jsonrpc.Response
}

var _ mcp.Transport = (*mcpStdioConnection)(nil)

func newMCPStdioTransport(reader io.ReadCloser, writer io.WriteCloser) *mcpStdioConnection {
	return &mcpStdioConnection{reader: newBoundedMCPStdioReader(reader), writer: writer}
}

func (c *mcpStdioConnection) Connect(context.Context) (mcp.Connection, error) { return c, nil }

func (c *mcpStdioConnection) Read(context.Context) (jsonrpc.Message, error) {
	if len(c.queue) > 0 {
		next := c.queue[0]
		c.queue = c.queue[1:]
		return next, nil
	}
	frame := make([]byte, maxMCPStdioMessage+1)
	n, err := c.reader.Read(frame)
	if err != nil {
		return nil, err
	}
	messages, batch, err := decodeMCPFrame(frame[:n])
	if err != nil {
		return nil, err
	}
	if batch && c.protocolVersion >= mcpProtocol20250618 {
		return nil, fmt.Errorf("JSON-RPC batching is not supported in %s and later", mcpProtocol20250618)
	}
	if batch {
		if err := c.trackBatch(messages); err != nil {
			return nil, err
		}
	}
	c.trackNegotiatedVersion(messages)
	c.queue = messages[1:]
	return messages[0], nil
}

// Write admits every path through admitWrite before touching any state: a
// Write is either fully registered with the shutdown join or refused after
// Close. A tracked incomplete batch response is buffered as admitted work; a
// completed batch is emitted as one array.
func (c *mcpStdioConnection) Write(_ context.Context, message jsonrpc.Message) error {
	if !c.admitWrite() {
		return errMCPStdioWriterClosed
	}
	defer c.writes.Done()
	if resp, ok := message.(*jsonrpc.Response); ok {
		batch, complete := c.updateBatch(resp)
		if complete && len(batch) > 0 {
			return c.writeBatch(batch)
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
	return c.writeAll(data)
}

// Close flips the guarded closing flag before waiting, so a Write is either
// fully admitted before the join or refused after it. It closes the owned
// writer without taking writeMu, joins admitted writes and the owned blocking
// read, and is idempotent with the same owned result on every call.
func (c *mcpStdioConnection) Close() error {
	c.closeOnce.Do(func() {
		c.admitMu.Lock()
		c.closing = true
		c.admitMu.Unlock()
		writeErr := c.writer.Close()
		c.writes.Wait()
		readErr := c.reader.Close()
		c.closeErr = errors.Join(writeErr, readErr)
	})
	return c.closeErr
}

func (*mcpStdioConnection) SessionID() string { return "" }

// admitWrite registers one Write with the shutdown join under admitMu, so the
// registration cannot interleave with Close flipping the closing flag.
func (c *mcpStdioConnection) admitWrite() bool {
	c.admitMu.Lock()
	defer c.admitMu.Unlock()
	if c.closing {
		return false
	}
	c.writes.Add(1)
	return true
}

// writeAll serializes the underlying write under writeMu, which Close never
// takes; admission and join accounting happened in Write.
func (c *mcpStdioConnection) writeAll(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.writer.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (c *mcpStdioConnection) writeBatch(batch []*jsonrpc.Response) error {
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
	return c.writeAll(data)
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
	if !supportedMCPProtocol(version) {
		return mcpProtocol20250618
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
