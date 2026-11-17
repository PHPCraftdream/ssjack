package faultproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// chunkSize is the read buffer of one forwarding direction.
const chunkSize = 32 * 1024

// past is a deadline that has already expired; setting it wakes blocked
// reads and writes.
var past = time.Unix(1, 0)

// limit is one DropAfterBytes fault of one connection. reserved counts bytes
// granted to a write that may still be in flight, written those that were
// really forwarded; the drop fires on written, so every granted byte is
// delivered and the cut is exact.
type limit struct {
	dir      Direction
	n        int64
	reserved int64
	written  int64
}

type rateSpec struct{ rate, burst int64 }

// Conn is one accepted client connection and its fault plan.
type Conn struct {
	p      *Proxy
	index  int
	client net.Conn
	ctx    context.Context
	cancel context.CancelFunc

	// Set by configure before run starts; read-only afterwards.
	limits  []*limit
	rates   [2]*rateSpec
	buckets [2]*bucket
	timers  []Timer

	halted chan struct{} // closed when forwarding stops for any Reason
	done   chan struct{} // closed when both sockets are released

	mu       sync.Mutex
	upstream net.Conn
	stopped  bool
	reason   Reason
	c2s, s2c int64
	closed   bool
}

// ConnStats is a snapshot of one connection.
type ConnStats struct {
	Index int
	// ClientToServer and ServerToClient are the bytes forwarded.
	ClientToServer, ServerToClient int64
	// Reason says why forwarding stopped; ReasonNone while it runs or when it
	// ended on its own.
	Reason Reason
	// Halted: forwarding stopped because of Reason.
	Halted bool
	// Closed: both sockets are released.
	Closed bool
}

func newConn(p *Proxy, index int, client net.Conn) *Conn {
	ctx, cancel := context.WithCancel(p.ctx)
	return &Conn{
		p: p, index: index, client: client, ctx: ctx, cancel: cancel,
		halted: make(chan struct{}), done: make(chan struct{}),
	}
}

// Index returns the 1-based accept order of the connection.
func (c *Conn) Index() int { return c.index }

// Halted is closed when forwarding stopped because a fault fired, the
// connection errored or the proxy closed. It stays open when the connection
// ends on its own.
func (c *Conn) Halted() <-chan struct{} { return c.halted }

// Done is closed when the connection is fully released: forwarding stopped,
// peers had the chance to read every forwarded byte, both sockets closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Wait blocks until Done and returns the final stats.
func (c *Conn) Wait(ctx context.Context) (ConnStats, error) {
	select {
	case <-c.done:
		return c.Stats(), nil
	case <-ctx.Done():
		return c.Stats(), ctx.Err()
	}
}

// Stats returns a snapshot.
func (c *Conn) Stats() ConnStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ConnStats{
		Index: c.index, ClientToServer: c.c2s, ServerToClient: c.s2c,
		Reason: c.reason, Halted: c.stopped, Closed: c.closed,
	}
}

// Drop cuts the connection now. Forwarded bytes are not lost; unforwarded
// bytes are discarded.
func (c *Conn) Drop() { c.halt(ReasonManual) }

// configure resolves the rules matching this connection into its plan. It
// runs under the proxy lock before the connection is published.
func (c *Conn) configure(rules []Rule) {
	for _, rule := range rules {
		if rule.Conns != nil && !rule.Conns(c.index) {
			continue
		}
		for _, fault := range rule.Faults {
			switch fault.kind {
			case kindDropBytes:
				c.limits = append(c.limits, &limit{dir: fault.dir, n: fault.n})
			case kindDropAfter:
				c.timers = append(c.timers, c.p.clock.AfterFunc(fault.d, func() { c.halt(ReasonDuration) }))
			case kindThrottle:
				for _, dir := range []Direction{ClientToServer, ServerToClient} {
					if fault.dir&dir != 0 {
						c.rates[dirIndex(dir)] = &rateSpec{rate: fault.n, burst: fault.burst}
					}
				}
			}
		}
	}
	now := c.p.clock.Now()
	for i, spec := range c.rates {
		if spec != nil {
			c.buckets[i] = newBucket(spec.rate, spec.burst, now)
		}
	}
	for _, l := range c.limits {
		if l.n == 0 {
			c.halt(ReasonBytes)
			break
		}
	}
}

// refuse resets the connection without dialing the upstream.
func (c *Conn) refuse() {
	c.mu.Lock()
	c.stopped, c.reason, c.closed = true, ReasonRefused, true
	c.mu.Unlock()
	close(c.halted)
	c.cancel()
	if tcp, ok := c.client.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = c.client.Close()
	close(c.done)
}

// halt stops forwarding. Only the first call counts; it wakes every blocked
// read, write, dial and throttle wait.
func (c *Conn) halt(reason Reason) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped, c.reason = true, reason
	upstream := c.upstream
	c.mu.Unlock()
	close(c.halted)
	c.cancel()
	_ = c.client.SetDeadline(past)
	if upstream != nil {
		_ = upstream.SetDeadline(past)
	}
}

// shutdown ends the connection for Proxy.Close: no lingering.
func (c *Conn) shutdown() {
	c.halt(ReasonShutdown)
	c.mu.Lock()
	upstream := c.upstream
	c.mu.Unlock()
	_ = c.client.Close()
	if upstream != nil {
		_ = upstream.Close()
	}
}

func (c *Conn) isHalted() bool {
	select {
	case <-c.halted:
		return true
	default:
		return false
	}
}

// run owns the connection from dial to release.
func (c *Conn) run() {
	defer c.p.wg.Done()
	if !c.isHalted() {
		c.forwardAll()
	}
	c.teardown()
	for _, timer := range c.timers {
		timer.Stop()
	}
	c.cancel()
	close(c.done)
}

// forwardAll dials the upstream and pumps both directions until they end.
func (c *Conn) forwardAll() {
	var dialer net.Dialer
	upstream, err := dialer.DialContext(c.ctx, "tcp", c.p.upstream)
	if err != nil {
		c.halt(ReasonError)
		return
	}
	c.mu.Lock()
	c.upstream = upstream
	stopped := c.stopped
	c.mu.Unlock()
	if stopped {
		// halt ran before the upstream was recorded and could not wake it.
		_ = upstream.SetDeadline(past)
		return
	}
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		c.pump(ClientToServer, c.client, upstream, c.buckets[0])
	}()
	go func() {
		defer pumps.Done()
		c.pump(ServerToClient, upstream, c.client, c.buckets[1])
	}()
	pumps.Wait()
}

// teardown releases the sockets. After a halt the proxy first half-closes
// both peers (FIN, queued data is delivered first) and discards what they
// still send until they close or the linger expires: closing a socket that
// has unread data would send a reset, which can destroy bytes the peer has
// not read yet and would make the exact cut observable only on some systems.
func (c *Conn) teardown() {
	c.mu.Lock()
	upstream, stopped := c.upstream, c.stopped
	c.mu.Unlock()
	if stopped && c.p.linger > 0 && !c.p.isClosed() {
		var drains sync.WaitGroup
		for _, peer := range []net.Conn{c.client, upstream} {
			if peer == nil {
				continue
			}
			drains.Add(1)
			go func() {
				defer drains.Done()
				_ = peer.SetDeadline(time.Now().Add(c.p.linger))
				closeWrite(peer)
				_, _ = io.Copy(io.Discard, peer)
			}()
		}
		drains.Wait()
	}
	_ = c.client.Close()
	if upstream != nil {
		_ = upstream.Close()
	}
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

func closeWrite(conn net.Conn) {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}

// pump copies src to dst until EOF, an error or a halt. A clean EOF is passed
// on as a half-close so request/response protocols finish normally.
func (c *Conn) pump(dir Direction, src, dst net.Conn, tokens *bucket) {
	buf := make([]byte, chunkSize)
	for {
		n, err := src.Read(buf)
		if n > 0 && !c.forward(dir, dst, buf[:n], tokens) {
			return
		}
		if err != nil {
			if c.isHalted() {
				return
			}
			if errors.Is(err, io.EOF) {
				closeWrite(dst)
				return
			}
			c.halt(ReasonError)
			return
		}
	}
}

// forward writes data to dst under the byte limits and the throttle. It
// returns false when forwarding must stop.
func (c *Conn) forward(dir Direction, dst net.Conn, data []byte, tokens *bucket) bool {
	for len(data) > 0 {
		want := int64(len(data))
		if tokens != nil && want > tokens.burst {
			want = tokens.burst
		}
		grant := c.reserve(dir, want)
		if grant == 0 {
			// At a byte limit: the write that completes it fires the halt.
			<-c.halted
			return false
		}
		if tokens != nil && !c.take(tokens, grant) {
			return false
		}
		n, err := dst.Write(data[:grant])
		c.account(dir, n)
		if err != nil {
			c.halt(ReasonError)
			return false
		}
		data = data[n:]
	}
	return true
}

// reserve grants up to want bytes without exceeding any byte limit that
// covers dir.
func (c *Conn) reserve(dir Direction, want int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	grant := want
	for _, l := range c.limits {
		if l.dir&dir != 0 && l.n-l.reserved < grant {
			grant = l.n - l.reserved
		}
	}
	if grant <= 0 {
		return 0
	}
	for _, l := range c.limits {
		if l.dir&dir != 0 {
			l.reserved += grant
		}
	}
	return grant
}

// account records n forwarded bytes and fires the byte drop when a limit is
// exactly reached.
func (c *Conn) account(dir Direction, n int) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	if dir == ClientToServer {
		c.c2s += int64(n)
	} else {
		c.s2c += int64(n)
	}
	reached := false
	for _, l := range c.limits {
		if l.dir&dir != 0 {
			l.written += int64(n)
			if l.written >= l.n {
				reached = true
			}
		}
	}
	c.mu.Unlock()
	if reached {
		c.halt(ReasonBytes)
	}
}

// take spends n tokens, waiting on the proxy clock until they exist. It
// returns false when the connection halted first.
func (c *Conn) take(tokens *bucket, n int64) bool {
	for {
		wait := tokens.try(c.p.clock.Now(), n)
		if wait == 0 {
			return true
		}
		fired := make(chan struct{})
		timer := c.p.clock.AfterFunc(wait, func() { close(fired) })
		select {
		case <-fired:
		case <-c.halted:
			timer.Stop()
			return false
		}
		if c.isHalted() {
			return false
		}
	}
}
