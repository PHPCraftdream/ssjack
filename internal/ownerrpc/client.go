package ownerrpc

import (
	"context"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
)

type clientPeer interface {
	AcceptHello([]byte) ([]byte, error)
	AcceptReady([]byte) error
	Command(ownerpacket.Command) ([]byte, error)
	OpenReply([]byte) (ownerpacket.Reply, error)
	Deadline() time.Time
	Close()
}

// Client owns its connection and packet peer, not the borrowed unlock context.
// Close joins any active exchange before releasing the peer's key capability.
type Client struct {
	gate       chan struct{}
	connection ownerlocal.Connection
	peer       clientPeer
	closed     bool
	closeOnce  sync.Once
}

// Attach consumes both arguments, including on authentication failure.
func Attach(ctx context.Context, connection ownerlocal.Connection, peer *ownerpacket.Client) (*Client, error) {
	if connection == nil || peer == nil {
		if connection != nil {
			connection.Close()
		}
		if peer != nil {
			peer.Close()
		}
		return nil, ownerpacket.ErrProtocol
	}
	client := newClient(connection, peer)
	if err := client.authenticate(ctx); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func newClient(connection ownerlocal.Connection, peer clientPeer) *Client {
	return &Client{gate: make(chan struct{}, 1), connection: connection, peer: peer}
}

func exchangeContext(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ownerpacket.ErrProtocol
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, nil, ownerpacket.ErrProtocol
	}
	limit := time.Now().Add(time.Minute)
	if !deadline.IsZero() && deadline.Before(limit) {
		limit = deadline
	}
	bounded, cancel := context.WithDeadline(ctx, limit)
	if bounded.Err() != nil {
		cancel()
		return nil, nil, ownerpacket.ErrExpired
	}
	return bounded, cancel, nil
}

func (c *Client) authenticate(ctx context.Context) error {
	bounded, cancel, err := exchangeContext(ctx, time.Now().Add(10*time.Second))
	if err != nil {
		return err
	}
	defer cancel()
	hello, err := ownerpacket.ReadFrame(bounded, c.connection)
	if err != nil {
		return err
	}
	defer clear(hello)
	authentication, err := c.peer.AcceptHello(hello)
	if err != nil {
		return err
	}
	defer clear(authentication)
	if err := ownerpacket.WriteFrame(bounded, c.connection, authentication); err != nil {
		return err
	}
	ready, err := ownerpacket.ReadFrame(bounded, c.connection)
	if err != nil {
		return err
	}
	defer clear(ready)
	return c.peer.AcceptReady(ready)
}

// Call never retries. After dispatch, any missing authenticated reply is uncertain.
func (c *Client) Call(ctx context.Context, command ownerpacket.Command) (ownerpacket.Reply, error) {
	wait, stop, err := exchangeContext(ctx, time.Time{})
	if err != nil {
		return ownerpacket.Reply{}, err
	}
	defer stop()
	select {
	case c.gate <- struct{}{}:
	case <-wait.Done():
		return ownerpacket.Reply{}, wait.Err()
	}
	defer func() { <-c.gate }()
	if c.closed {
		return ownerpacket.Reply{}, ownerpacket.ErrAuthentication
	}
	bounded, cancel, err := exchangeContext(wait, c.peer.Deadline())
	if err != nil {
		return ownerpacket.Reply{}, err
	}
	defer cancel()
	encoded, err := c.peer.Command(command)
	if err != nil {
		return ownerpacket.Reply{}, err
	}
	defer clear(encoded)
	if err := ownerpacket.WriteFrame(bounded, c.connection, encoded); err != nil {
		c.fail()
		return ownerpacket.Reply{}, ownerpacket.ErrUncertain
	}
	encodedReply, err := ownerpacket.ReadFrame(bounded, c.connection)
	if err != nil {
		c.fail()
		return ownerpacket.Reply{}, ownerpacket.ErrUncertain
	}
	defer clear(encodedReply)
	reply, err := c.peer.OpenReply(encodedReply)
	if err != nil {
		c.fail()
		return ownerpacket.Reply{}, ownerpacket.ErrUncertain
	}
	return reply, nil
}

func (c *Client) closeConnection() {
	c.closeOnce.Do(func() { c.connection.Close() })
}

func (c *Client) fail() {
	c.closed = true
	c.closeConnection()
	c.peer.Close()
}

func (c *Client) Close() {
	// Closing native I/O first wakes the active exchange.
	c.closeConnection()
	c.gate <- struct{}{}
	defer func() { <-c.gate }()
	if !c.closed {
		c.closed = true
		c.peer.Close()
	}
}
