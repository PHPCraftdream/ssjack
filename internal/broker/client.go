package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// Connection failures keep their fixed text; the identities tell the stage.
var (
	ErrDial     = errors.New("failed to establish a secure connection to the keeper")
	ErrAuth     = errors.New("failed to authenticate to the keeper")
	ErrRejected = errors.New("keeper rejected the connection")
)

type Client struct {
	conn  net.Conn
	mu    sync.Mutex
	trace Trace
}

// SetTrace must be called before the client is shared.
func (c *Client) SetTrace(trace Trace) { c.trace = trace }

// exchange reports which half of a failed call broke, never its content.
func (c *Client) exchange(operation, data string, reply *wire.Reply) bool {
	stage, err := "write", wire.Write(c.conn, wire.Request{Operation: operation, Data: data})
	if err == nil {
		stage, err = "read", wire.Read(c.conn, reply)
	}
	if err != nil && c.trace != nil {
		c.trace("call-failed", "op", operation, "stage", stage, "cause", lifelog.Cause(err))
	}
	return err == nil
}

func Connect(ctx context.Context, endpoint, pin string, auth wire.Auth) (*Client, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	config, err := wire.ClientTLS(pin)
	if err != nil {
		return nil, err
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}
	conn, err := dialer.DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		return nil, ErrDial
	}
	if !loopbackPeer(conn.RemoteAddr()) {
		conn.Close()
		return nil, errors.New("keeper TCP peer is not loopback")
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var reply wire.Reply
	if err := wire.Write(conn, auth); err != nil {
		conn.Close()
		return nil, ErrAuth
	}
	if err := wire.Read(conn, &reply); err != nil || !reply.OK {
		conn.Close()
		return nil, ErrRejected
	}
	conn.SetDeadline(time.Time{})
	return &Client{conn: conn}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) CallRaw(ctx context.Context, operation string, input any) (string, error) {
	data, err := wire.Encode(input)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.conn.Close() })
	defer stop()
	var reply wire.Reply
	if !c.exchange(operation, data, &reply) {
		c.conn.Close()
		return "", errors.New("keeper connection closed; start a new session")
	}
	c.conn.SetDeadline(time.Time{})
	if !reply.OK {
		return "", errors.New(reply.Error)
	}
	return reply.Data, nil
}

func (c *Client) Call(ctx context.Context, operation string, input, output any) error {
	data, err := wire.Encode(input)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.conn.Close() })
	defer stop()
	var reply wire.Reply
	if !c.exchange(operation, data, &reply) {
		c.conn.Close()
		return errors.New("keeper connection closed; start a new session")
	}
	c.conn.SetDeadline(time.Time{})
	if !reply.OK {
		return errors.New(reply.Error)
	}
	if output != nil {
		return wire.Decode(reply.Data, output)
	}
	return nil
}

func Result(value any, err error) wire.Reply {
	if err != nil {
		return wire.Reply{Error: err.Error()}
	}
	data, err := wire.Encode(value)
	if err != nil {
		return wire.Reply{Error: "failed to encode reply"}
	}
	return wire.Reply{OK: true, Data: data}
}
