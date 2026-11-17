package faultproxy

import (
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// testBudget bounds every wait in these tests. It is a hang detector, never
// an expected delay.
const testBudget = 30 * time.Second

// upstreamRecord is what one upstream connection received.
type upstreamRecord struct {
	data  []byte
	ended chan struct{}
}

// upstreamServer is a plain TCP server standing in for sshd: it records the
// bytes every connection sends, optionally greets and echoes, and closes its
// side when it reads EOF.
type upstreamServer struct {
	listener net.Listener
	echo     bool
	greeting []byte
	wg       sync.WaitGroup

	mu      sync.Mutex
	records []*upstreamRecord
	conns   map[net.Conn]struct{}
	changed chan struct{}
	closed  bool
}

type upstreamOptions struct {
	echo     bool
	greeting []byte
}

func newUpstream(t *testing.T, opts upstreamOptions) *upstreamServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &upstreamServer{
		listener: listener, echo: opts.echo, greeting: opts.greeting,
		conns: make(map[net.Conn]struct{}), changed: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(s.close)
	return s
}

func (s *upstreamServer) addr() string { return s.listener.Addr().String() }

func (s *upstreamServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		record := &upstreamRecord{ended: make(chan struct{})}
		s.records = append(s.records, record)
		s.conns[conn] = struct{}{}
		s.broadcastLocked()
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(conn, record)
	}
}

func (s *upstreamServer) broadcastLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *upstreamServer) handle(conn net.Conn, record *upstreamRecord) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()
	if len(s.greeting) > 0 {
		_, _ = conn.Write(s.greeting)
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			record.data = append(record.data, buf[:n]...)
			s.broadcastLocked()
			s.mu.Unlock()
			if s.echo {
				_, _ = conn.Write(buf[:n])
			}
		}
		if err != nil {
			break
		}
	}
	close(record.ended)
}

func (s *upstreamServer) close() {
	s.mu.Lock()
	s.closed = true
	_ = s.listener.Close()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// accepted returns the number of upstream connections so far.
func (s *upstreamServer) accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// waitReceived blocks until upstream connection index (1-based) has received
// at least n bytes, and returns everything it has received so far.
func (s *upstreamServer) waitReceived(t *testing.T, index, n int) []byte {
	t.Helper()
	deadline := time.After(testBudget)
	for {
		s.mu.Lock()
		var got []byte
		found := index <= len(s.records)
		if found {
			got = append([]byte(nil), s.records[index-1].data...)
		}
		changed := s.changed
		s.mu.Unlock()
		if found && len(got) >= n {
			return got
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("upstream connection %d never received %d bytes (has %d)", index, n, len(got))
		}
	}
}

// waitEnded blocks until upstream connection index saw EOF or an error, and
// returns every byte it received.
func (s *upstreamServer) waitEnded(t *testing.T, index int) []byte {
	t.Helper()
	deadline := time.After(testBudget)
	for {
		s.mu.Lock()
		var record *upstreamRecord
		if index <= len(s.records) {
			record = s.records[index-1]
		}
		changed := s.changed
		s.mu.Unlock()
		if record != nil {
			select {
			case <-record.ended:
			case <-deadline:
				t.Fatalf("upstream connection %d never ended", index)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			return append([]byte(nil), record.data...)
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("upstream connection %d was never accepted", index)
		}
	}
}

// startProxy starts a proxy and, after it is closed at cleanup, requires that
// none of its goroutines is left.
func startProxy(t *testing.T, upstream string, opts ...Option) *Proxy {
	t.Helper()
	t.Cleanup(func() { requireNoProxyGoroutines(t) })
	return Start(t, upstream, opts...)
}

// requireNoProxyGoroutines fails when a goroutine still runs proxy code. The
// proxy joins its goroutines in Close, but a goroutine is only visible as
// gone a moment after it signals the join, so this polls up to a bound.
func requireNoProxyGoroutines(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(testBudget)
	for {
		dump := goroutineDump()
		if !strings.Contains(dump, "faultproxy.(*Conn).") && !strings.Contains(dump, "faultproxy.(*Proxy).") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy goroutines leaked:\n%s", dump)
		}
		time.Sleep(time.Millisecond)
	}
}

func goroutineDump() string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// dial connects to addr and closes the connection at cleanup.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, testBudget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readAll reads until EOF. A reset or timeout fails the test: the proxy cuts
// connections with a clean FIN.
func readAll(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(testBudget))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read until EOF: %v", err)
	}
	return data
}

// readFull reads exactly n bytes.
func readFull(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(testBudget))
	data := make([]byte, n)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return data
}

// writeAsync writes data in the background so a test never deadlocks on full
// socket buffers; the returned func waits for the write and returns its error.
func writeAsync(conn net.Conn, data []byte) func() error {
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(data)
		done <- err
	}()
	return func() error { return <-done }
}

// pattern returns n deterministic, non-repeating-looking bytes.
func pattern(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}
