package ownerpacket

import (
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

// Client borrows a fresh owner-unlocked context. The caller closes that context.
type Client struct {
	mu      sync.Mutex
	peer    peer
	hello   bool
	waiting uint64
}

func NewClient(key *keyfile.Unlocked, binding [32]byte) (*Client, error) {
	if key == nil || binding == ([32]byte{}) {
		return nil, ErrAuthentication
	}
	return &Client{peer: peer{key: key, binding: binding, sequence: 1, now: time.Now}}, nil
}
func (c *Client) Close()              { c.mu.Lock(); defer c.mu.Unlock(); c.peer.closed, c.peer.key = true, nil }
func (c *Client) Deadline() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.peer.expires }

// AcceptHello proves the server owns the same context before any value is sent.
func (c *Client) AcceptHello(encoded []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer.closed || c.hello {
		return nil, c.peer.fail()
	}
	packet, err := open(c.peer.key, encoded)
	defer packet.clear()
	now := c.peer.now()
	expires := time.Unix(packet.Expires, 0)
	if err != nil || packet.Kind != "hello" || packet.Direction != "server" || packet.Binding != c.peer.binding || packet.Client != ([32]byte{}) || packet.Sequence != 0 || packet.Digest == ([32]byte{}) || packet.Command != nil || packet.Reply != nil || !now.Before(expires) || expires.After(now.Add(Lease)) {
		return nil, c.peer.fail()
	}
	client, err := nonce()
	if err != nil {
		return nil, c.peer.fail()
	}
	c.peer.session, c.peer.client, c.peer.digest = packet.Session, client, packet.Digest
	c.peer.expires = now.Add(expires.Sub(now))
	authentication, err := seal(c.peer.key, c.peer.packet("auth", "client", 0))
	if err != nil {
		c.peer.closed = true
		return nil, err
	}
	c.hello = true
	return authentication, nil
}

func (c *Client) AcceptReady(encoded []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hello || c.peer.ready || c.peer.live() != nil {
		return c.peer.fail()
	}
	packet, err := open(c.peer.key, encoded)
	defer packet.clear()
	if err != nil || !c.peer.matches(packet, "ready", "server", 0) || packet.Command != nil || packet.Reply != nil {
		return c.peer.fail()
	}
	c.peer.ready = true
	return nil
}

func (c *Client) Command(command Command) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.peer.ready || c.waiting != 0 || c.peer.live() != nil || c.peer.sequence > MaxMessages {
		return nil, c.peer.fail()
	}
	if !command.valid() {
		return nil, ErrProtocol
	}
	packet := c.peer.packet("command", "client", c.peer.sequence)
	packet.Command = &command
	encoded, err := seal(c.peer.key, packet)
	if err != nil {
		c.peer.closed = true
		return nil, err
	}
	c.waiting = c.peer.sequence
	c.peer.sequence++
	return encoded, nil
}

func (c *Client) OpenReply(encoded []byte) (Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.peer.ready || c.waiting == 0 || c.peer.live() != nil {
		return Reply{}, c.peer.fail()
	}
	packet, err := open(c.peer.key, encoded)
	defer packet.clear()
	if err != nil || !c.peer.matches(packet, "reply", "server", c.waiting) || packet.Command != nil || packet.Reply == nil || !packet.Reply.valid() {
		return Reply{}, c.peer.fail()
	}
	c.waiting = 0
	return *packet.Reply, nil
}
