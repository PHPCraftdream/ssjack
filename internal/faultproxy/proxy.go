package faultproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// defaultLinger bounds how long a cut connection waits for its peers to
// close after the proxy half-closed them (see Conn.teardown).
const defaultLinger = 2 * time.Second

// ErrClosed is returned by waits on a proxy that was closed.
var ErrClosed = errors.New("faultproxy: proxy closed")

type options struct {
	clock  Clock
	linger time.Duration
}

// Option configures New.
type Option func(*options)

// WithClock sets the time source of duration drops and throttling. The
// default is RealClock.
func WithClock(clock Clock) Option { return func(o *options) { o.clock = clock } }

// WithLinger sets how long a cut connection waits, in real time, for its
// peers to close after the proxy sent them FIN, before the sockets are closed
// anyway. The wait lets the peers read every forwarded byte and avoids the
// TCP reset a close with unread data would send. Zero closes at once. The
// default is two seconds; peers that close on EOF finish in microseconds.
func WithLinger(d time.Duration) Option { return func(o *options) { o.linger = d } }

// Proxy is a fault-injecting TCP proxy to one upstream address. All methods
// are safe for concurrent use.
type Proxy struct {
	upstream string
	clock    Clock
	linger   time.Duration
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	mu      sync.Mutex
	rules   []Rule
	refuse  int
	conns   []*Conn
	changed chan struct{}
	closed  bool
}

// New starts a proxy listening on a free loopback port that forwards every
// accepted connection to upstream (host:port). Close it when done.
func New(upstream string, opts ...Option) (*Proxy, error) {
	if upstream == "" {
		return nil, errors.New("faultproxy: empty upstream address")
	}
	cfg := options{clock: RealClock{}, linger: defaultLinger}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.clock == nil {
		cfg.clock = RealClock{}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		upstream: upstream, clock: cfg.clock, linger: cfg.linger,
		listener: listener, ctx: ctx, cancel: cancel,
		changed: make(chan struct{}),
	}
	p.wg.Add(1)
	go p.acceptLoop()
	return p, nil
}

// Addr returns the host:port clients dial instead of the upstream address.
func (p *Proxy) Addr() string { return p.listener.Addr().String() }

// SetRules replaces the fault rules. They apply to connections accepted after
// the call; connections already open keep the faults they were accepted with.
// Calling it with no rules removes all faults. An invalid fault is reported
// and leaves the previous rules in place.
func (p *Proxy) SetRules(rules ...Rule) error {
	copied := make([]Rule, len(rules))
	for i, rule := range rules {
		for _, fault := range rule.Faults {
			if err := fault.validate(); err != nil {
				return err
			}
		}
		copied[i] = Rule{Conns: rule.Conns, Faults: append([]Fault(nil), rule.Faults...)}
	}
	p.mu.Lock()
	p.rules = copied
	p.mu.Unlock()
	return nil
}

// RefuseNext makes the next n accepted connections fail at once: the proxy
// accepts the TCP connection, then resets it without dialing the upstream.
// The client sees a reset or EOF on its first read or write rather than a
// refused dial. Refused connections take connection indexes like any other.
// Calling it again replaces the remaining count.
func (p *Proxy) RefuseNext(n int) {
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	p.refuse = n
	p.mu.Unlock()
}

// Stats is a snapshot of the proxy counters.
type Stats struct {
	// Accepted is the number of connections accepted so far.
	Accepted int
	// Dropped counts connections cut by an injected fault (bytes, duration,
	// manual). Refused connections are counted separately.
	Dropped int
	Refused int
	// Stalled counts connections a stall engaged on, whatever ended them
	// afterwards.
	Stalled int
	// Closed counts connections fully released.
	Closed int
	// ClientToServer and ServerToClient sum the forwarded bytes.
	ClientToServer, ServerToClient int64
	// Conns holds one entry per accepted connection, in index order.
	Conns []ConnStats
}

// Stats returns a snapshot of the counters.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	conns := append([]*Conn(nil), p.conns...)
	p.mu.Unlock()
	stats := Stats{Accepted: len(conns), Conns: make([]ConnStats, 0, len(conns))}
	for _, c := range conns {
		cs := c.Stats()
		stats.Conns = append(stats.Conns, cs)
		switch {
		case cs.Reason == ReasonRefused:
			stats.Refused++
		case cs.Reason.isFault():
			stats.Dropped++
		}
		if cs.Stalled {
			stats.Stalled++
		}
		if cs.Closed {
			stats.Closed++
		}
		stats.ClientToServer += cs.ClientToServer
		stats.ServerToClient += cs.ServerToClient
	}
	return stats
}

// WaitConn blocks until the connection with the given 1-based index was
// accepted and returns it. Its fault plan, including any duration timer, is
// already in place when WaitConn returns.
func (p *Proxy) WaitConn(ctx context.Context, index int) (*Conn, error) {
	if index < 1 {
		return nil, errors.New("faultproxy: connection index starts at 1")
	}
	for {
		p.mu.Lock()
		if index <= len(p.conns) {
			c := p.conns[index-1]
			p.mu.Unlock()
			return c, nil
		}
		closed, changed := p.closed, p.changed
		p.mu.Unlock()
		if closed {
			return nil, ErrClosed
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close stops accepting, cuts every connection without lingering and waits
// until every goroutine the proxy started has returned. It is idempotent.
func (p *Proxy) Close() error {
	p.mu.Lock()
	var conns []*Conn
	if !p.closed {
		p.closed = true
		p.cancel()
		_ = p.listener.Close()
		conns = append(conns, p.conns...)
		close(p.changed)
		p.changed = make(chan struct{})
	}
	p.mu.Unlock()
	for _, c := range conns {
		c.shutdown()
	}
	p.wg.Wait()
	return nil
}

func (p *Proxy) isClosed() bool { return p.ctx.Err() != nil }

func (p *Proxy) acceptLoop() {
	defer p.wg.Done()
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.admit(client)
	}
}

// admit numbers the connection, resolves its fault plan and publishes it. The
// plan (timers included) exists before WaitConn can return the connection.
func (p *Proxy) admit(client net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = client.Close()
		return
	}
	c := newConn(p, len(p.conns)+1, client)
	p.conns = append(p.conns, c)
	if p.refuse > 0 {
		p.refuse--
		c.refuse()
	} else {
		c.configure(p.rules)
		p.wg.Add(1)
		go c.run()
	}
	close(p.changed)
	p.changed = make(chan struct{})
}
