package broker

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// Connection failures keep their fixed text; the identities tell the stage.
var (
	ErrDial     = errors.New("failed to establish a secure connection to the keeper")
	ErrAuth     = errors.New("failed to authenticate to the keeper")
	ErrRejected = errors.New("keeper rejected the connection")

	// ErrSessionClosed reports a keeper connection that is no longer usable:
	// an exchange failed or the keeper closed it.
	ErrSessionClosed = errors.New("keeper connection closed; start a new session")
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
		return "", ErrSessionClosed
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
		return ErrSessionClosed
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

// waitCallBudget is the IPC deadline of a waiting call: the longest wait the
// keeper accepts plus a margin for the reply, so a full wait never trips it.
const waitCallBudget = jobwait.MaxSeconds*time.Second + 10*time.Second

// CallWait is Call for an operation that may block in the keeper for up to
// jobwait.MaxSeconds (wait_seconds). It differs from Call in two ways. Its
// deadline is waitCallBudget, not 30 s, and the request context is not
// applied to the connection. When ctx ends first the call returns ctx.Err()
// at once but the session stays open: the reply still owed by the keeper is
// read and dropped in the background while the client stays busy, so the next
// call waits for it (at most the remaining wait) instead of a closed session.
func (c *Client) CallWait(ctx context.Context, operation string, input, output any) error {
	data, err := wire.Encode(input)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.conn.SetDeadline(time.Now().Add(waitCallBudget))
	var reply wire.Reply
	exchanged := make(chan bool, 1)
	go func() { exchanged <- c.exchange(operation, data, &reply) }()
	select {
	case ok := <-exchanged:
		defer c.mu.Unlock()
		if !ok {
			c.conn.Close()
			return ErrSessionClosed
		}
		c.conn.SetDeadline(time.Time{})
		if !reply.OK {
			return errors.New(reply.Error)
		}
		if output != nil {
			return wire.Decode(reply.Data, output)
		}
		return nil
	case <-ctx.Done():
		go func() {
			defer c.mu.Unlock()
			if <-exchanged {
				c.conn.SetDeadline(time.Time{})
				return
			}
			c.conn.Close()
		}()
		return ctx.Err()
	}
}

// acquire waits for the connection lock bounded by ctx, so a caller with a
// short deadline neither queues unbounded behind a long keeper call nor
// disturbs the current holder. When ctx ends first, a waiter goroutine hands
// the lock back, keeping the mutex state exact.
func (c *Client) acquire(ctx context.Context) error {
	locked := make(chan struct{})
	go func() {
		c.mu.Lock()
		close(locked)
	}()
	select {
	case <-locked:
		return nil
	case <-ctx.Done():
		go func() {
			<-locked
			c.mu.Unlock()
		}()
		return ctx.Err()
	}
}

// CallDetached is Call for best-effort pre-acceptance requests: ctx only
// bounds waiting for the connection and gates issuing, and a context
// deadline or cancellation never closes the shared connection the ordinary
// dispatch uses. Once issued, the exchange runs under the normal IPC
// deadline; a real transport failure still closes the connection, as in
// Call, because it is then unusable for everyone.
func (c *Client) CallDetached(ctx context.Context, operation string, input, output any) error {
	data, err := wire.Encode(input)
	if err != nil {
		return err
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	var reply wire.Reply
	if !c.exchange(operation, data, &reply) {
		c.conn.Close()
		return ErrSessionClosed
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

const (
	EnvToken    = "SSJACK_ENV_TOKEN"
	EnvSession  = "SSJACK_SESSION"
	EnvEndpoint = "SSJACK_ENDPOINT"
	EnvPin      = "SSJACK_CERTIFICATE_SHA256"
	// EnvFile is scrubbed for compatibility, never read or written.
	EnvFile = "SSJACK_BOOTSTRAP_FILE"
)

// Bootstrap exists only in memory and the launched harness environment.
type Bootstrap struct {
	Session  string
	Endpoint string
	Pin      string
	Token    string
}

func validToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	clear(decoded)
	return err == nil
}

func ConnectBootstrap(ctx context.Context, bootstrap Bootstrap) (*Client, error) {
	if !validToken(bootstrap.Session) || !validToken(bootstrap.Token) {
		return nil, errors.New("invalid memory-only bootstrap parameters")
	}
	return Connect(ctx, bootstrap.Endpoint, bootstrap.Pin, wire.Auth{
		Version: 2, Session: bootstrap.Session, Token: bootstrap.Token,
	})
}
