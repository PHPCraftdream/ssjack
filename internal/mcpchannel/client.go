package mcpchannel

import (
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

var ErrClient = errors.New("remote MCP channel request failed")

type Client struct {
	mu     sync.Mutex
	client *broker.Client
	active chan struct{}
}

// Connect validates all descriptor fields and expiry before making a network call.
func Connect(ctx context.Context, descriptor Descriptor) (*Client, error) {
	if ctx == nil || ctx.Err() != nil || !descriptor.valid(time.Now()) {
		return nil, ErrClient
	}
	client, err := broker.ConnectBootstrap(ctx, bootstrap(descriptor))
	if err != nil {
		return nil, ErrClient
	}
	return &Client{client: client, active: make(chan struct{}, 1)}, nil
}

func (c *Client) Describe(ctx context.Context) ([]byte, error) {
	return c.request(ctx, "describe", struct{}{})
}

func (c *Client) Call(ctx context.Context, tool string, input []byte) ([]byte, error) {
	if _, err := MarshalCall(tool, input); err != nil {
		return nil, ErrClient
	}
	return c.request(ctx, "call", callEnvelope{Tool: tool, Input: string(input)})
}

func (c *Client) request(ctx context.Context, operation string, input any) ([]byte, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || operation != "describe" && operation != "call" {
		return nil, ErrClient
	}
	select {
	case c.active <- struct{}{}:
		defer func() { <-c.active }()
	default:
		return nil, ErrClient
	}
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		return nil, ErrClient
	}
	if operation == "call" {
		envelope, ok := input.(callEnvelope)
		if !ok || envelope.Tool == "" || len(envelope.Tool) > MaxToolBytes || len(envelope.Input) == 0 || len(envelope.Input) > MaxClientInputBytes || !utf8.ValidString(envelope.Input) || !strictJSON(envelope.Input) {
			return nil, ErrClient
		}
	}
	data, err := wire.Encode(input)
	if err != nil || len(data) > MaxRequestBytes {
		return nil, ErrClient
	}
	frame, err := wire.Encode(wire.Request{Operation: operation, Data: data})
	if err != nil || len(frame) > wire.MaxFrame {
		return nil, ErrClient
	}
	callCtx, cancel := context.WithTimeout(ctx, OperationBudget)
	defer cancel()
	result, err := client.CallRaw(callCtx, operation, input)
	limit := MaxResultBytes
	if operation == "describe" {
		limit = MaxInventoryBytes
	}
	if err != nil || len(result) > limit || !strictJSON(result) {
		return nil, ErrClient
	}
	return []byte(result), nil
}

// Close drops this one-use connection. No reconnect or retry is performed.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	client := c.client
	c.client = nil
	c.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}
