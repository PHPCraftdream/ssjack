package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/mcpjson"
)

const (
	maxMCPStdioMessage  = 256 << 10
	maxMCPStdioMessages = 4096
	mcpProtocol20241105 = "2024-11-05"
	mcpProtocol20250326 = "2025-03-26"
	mcpProtocol20250618 = "2025-06-18"
)

var (
	errMCPStdioReaderClosed       = errors.New("MCP stdio reader is closed")
	errMCPStdioConcurrentRead     = errors.New("concurrent MCP stdio read refused")
	errMCPStdioMessageLimit       = errors.New("MCP stdio message exceeds limit")
	errMCPStdioMessageCountLimit  = errors.New("MCP stdio message limit exceeded")
	errMCPStdioInvalidMessage     = errors.New("invalid MCP stdio message")
	errMCPStdioUnsupportedVersion = errors.New("unsupported MCP protocol version")
	errMCPStdioUnsupportedMethod  = errors.New("unsupported MCP method")
	errMCPStdioWriterClosed       = errors.New("MCP stdio writer is closed")
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
	readDone  chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newBoundedMCPStdioReader(reader io.ReadCloser) *boundedMCPStdioReader {
	return &boundedMCPStdioReader{
		reader:   bufio.NewReaderSize(reader, 4096),
		source:   reader,
		readDone: make(chan struct{}),
	}
}

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
		if r.closing {
			close(r.readDone)
		}
		r.mu.Unlock()
	}()

	if len(r.pending) != 0 {
		return r.copyPending(target)
	}
	if r.eof {
		return 0, io.EOF
	}
	for {
		chunk, err := r.reader.ReadSlice('\n')
		complete := len(chunk) != 0 && chunk[len(chunk)-1] == '\n'
		payload := chunk
		if complete {
			payload = chunk[:len(chunk)-1]
		}
		if len(r.frame)+len(payload) > maxMCPStdioMessage {
			return 0, errMCPStdioMessageLimit
		}
		r.frame = append(r.frame, payload...)
		if complete {
			r.frame = append(r.frame, '\n')
			if err := r.admitFrame(); err != nil {
				return 0, err
			}
			return r.copyPending(target)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			r.eof = true
			if len(r.frame) == 0 {
				return 0, io.EOF
			}
			if err := r.admitFrame(); err != nil {
				return 0, err
			}
			return r.copyPending(target)
		}
		if err != nil {
			return 0, err
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
	var message struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(frame, &message) != nil {
		return errMCPStdioInvalidMessage
	}
	switch message.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(message.Params, &params) != nil || !supportedMCPProtocol(params.ProtocolVersion) {
			return errMCPStdioUnsupportedVersion
		}
	case "notifications/initialized", "notifications/cancelled", "tools/list", "tools/call", "ping":
	default:
		return errMCPStdioUnsupportedMethod
	}
	return nil
}

func supportedMCPProtocol(version string) bool {
	return version == mcpProtocol20241105 || version == mcpProtocol20250326 || version == mcpProtocol20250618
}

func (r *boundedMCPStdioReader) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		waitForRead := r.active
		r.mu.Unlock()

		r.closeErr = r.source.Close()
		if waitForRead {
			<-r.readDone
		}
	})
	return r.closeErr
}
