package faultproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testBudget)
	t.Cleanup(cancel)
	return ctx
}

func TestForwardsBothDirectionsAndCounts(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p := startProxy(t, up.addr())
	client := dial(t, p.Addr())
	payload := pattern(200 * 1024)
	wait := writeAsync(client, payload)
	if got := readFull(t, client, len(payload)); !bytes.Equal(got, payload) {
		t.Fatal("echoed bytes differ from the payload")
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	stats := p.Await(t, 1)
	if stats.Reason != ReasonNone || stats.Halted || !stats.Closed {
		t.Fatalf("clean connection stats = %+v", stats)
	}
	if stats.ClientToServer != int64(len(payload)) || stats.ServerToClient != int64(len(payload)) {
		t.Fatalf("byte counters = %+v, want %d each way", stats, len(payload))
	}
	total := p.Stats()
	if total.Accepted != 1 || total.Dropped != 0 || total.Refused != 0 || total.Closed != 1 {
		t.Fatalf("proxy stats = %+v", total)
	}
}

func TestDropAfterBytesClientToServerIsExact(t *testing.T) {
	// 32768 is the read chunk size and 70000 spans several chunks, so the
	// cut is exact regardless of how the stream is read.
	for _, limit := range []int64{1, 10, 32768, 70000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			up := newUpstream(t, upstreamOptions{})
			p := startProxy(t, up.addr())
			p.MustSetRules(t, Rule{Faults: []Fault{DropAfterBytes(ClientToServer, limit)}})
			client := dial(t, p.Addr())
			payload := pattern(100 * 1024)
			wait := writeAsync(client, payload)
			if got := readAll(t, client); len(got) != 0 {
				t.Fatalf("client received %d bytes from a silent upstream", len(got))
			}
			_ = client.Close()
			_ = wait() // the proxy discards the unforwarded rest; the outcome is irrelevant
			stats := p.Await(t, 1)
			if stats.Reason != ReasonBytes || !stats.Halted || stats.ClientToServer != limit || stats.ServerToClient != 0 {
				t.Fatalf("stats = %+v, want a byte drop at exactly %d", stats, limit)
			}
			if got := up.waitEnded(t, 1); !bytes.Equal(got, payload[:limit]) {
				t.Fatalf("upstream received %d bytes, want exactly the first %d", len(got), limit)
			}
			if total := p.Stats(); total.Dropped != 1 || total.Refused != 0 {
				t.Fatalf("proxy stats = %+v", total)
			}
		})
	}
}

func TestDropAfterBytesServerToClientIsExact(t *testing.T) {
	for _, limit := range []int64{1, 10, 32768, 70000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			greeting := pattern(100 * 1024)
			up := newUpstream(t, upstreamOptions{greeting: greeting})
			p := startProxy(t, up.addr())
			p.MustSetRules(t, Rule{Faults: []Fault{DropAfterBytes(ServerToClient, limit)}})
			client := dial(t, p.Addr())
			got := readAll(t, client)
			_ = client.Close()
			if !bytes.Equal(got, greeting[:limit]) {
				t.Fatalf("client received %d bytes, want exactly the first %d", len(got), limit)
			}
			stats := p.Await(t, 1)
			if stats.Reason != ReasonBytes || stats.ServerToClient != limit || stats.ClientToServer != 0 {
				t.Fatalf("stats = %+v, want a byte drop at exactly %d", stats, limit)
			}
			up.waitEnded(t, 1)
		})
	}
}

func TestDropAfterBytesBothDirectionsCountsTheSum(t *testing.T) {
	const limit = 20
	up := newUpstream(t, upstreamOptions{echo: true, greeting: pattern(8)})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Faults: []Fault{DropAfterBytes(Both, limit)}})
	client := dial(t, p.Addr())
	wait := writeAsync(client, pattern(100))
	received := readAll(t, client)
	_ = client.Close()
	_ = wait()
	stats := p.Await(t, 1)
	if stats.Reason != ReasonBytes || stats.ClientToServer+stats.ServerToClient != limit {
		t.Fatalf("stats = %+v, want %d bytes in total", stats, limit)
	}
	// Every byte the proxy counted as forwarded reached its destination.
	if int64(len(received)) != stats.ServerToClient {
		t.Fatalf("client received %d bytes, proxy counted %d", len(received), stats.ServerToClient)
	}
	if got := up.waitEnded(t, 1); int64(len(got)) != stats.ClientToServer {
		t.Fatalf("upstream received %d bytes, proxy counted %d", len(got), stats.ClientToServer)
	}
}

func TestDropAfterZeroBytesCutsBeforeDialing(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Faults: []Fault{DropAfterBytes(Both, 0)}})
	client := dial(t, p.Addr())
	if got := readAll(t, client); len(got) != 0 {
		t.Fatalf("client received %d bytes", len(got))
	}
	_ = client.Close()
	stats := p.Await(t, 1)
	if stats.Reason != ReasonBytes || stats.ClientToServer != 0 || stats.ServerToClient != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if up.accepted() != 0 {
		t.Fatal("a connection cut at zero bytes still reached the upstream")
	}
}

func TestRulesTargetConnectionIndexes(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Conns: Conns(1, 3), Faults: []Fault{DropAfterBytes(ClientToServer, 5)}})
	message := pattern(20)
	for index := 1; index <= 4; index++ {
		client := dial(t, p.Addr())
		if _, err := client.Write(message); err != nil {
			t.Fatal(err)
		}
		if index == 1 || index == 3 {
			readAll(t, client) // cut after 5 bytes; how much of the echo made it back is not asserted
			_ = client.Close()
			stats := p.Await(t, index)
			if stats.Reason != ReasonBytes || stats.ClientToServer != 5 {
				t.Fatalf("connection %d stats = %+v, want a drop at 5 bytes", index, stats)
			}
			if got := up.waitEnded(t, index); !bytes.Equal(got, message[:5]) {
				t.Fatalf("upstream connection %d received %d bytes, want 5", index, len(got))
			}
			continue
		}
		if got := readFull(t, client, len(message)); !bytes.Equal(got, message) {
			t.Fatalf("connection %d echo differs", index)
		}
		_ = client.Close()
		stats := p.Await(t, index)
		if stats.Reason != ReasonNone || stats.ClientToServer != 20 || stats.ServerToClient != 20 {
			t.Fatalf("connection %d stats = %+v, want an untouched pass-through", index, stats)
		}
	}
	if total := p.Stats(); total.Accepted != 4 || total.Dropped != 2 || total.Closed != 4 {
		t.Fatalf("proxy stats = %+v", total)
	}
	// FromConn selects the given index and everything after it.
	if !FromConn(3)(3) || !FromConn(3)(9) || FromConn(3)(2) || !AllConns()(1) {
		t.Fatal("selector semantics are wrong")
	}
}

func TestRefuseNextConnections(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p := startProxy(t, up.addr())
	p.RefuseNext(2)
	for index := 1; index <= 2; index++ {
		// Depending on the OS the reset is seen by the dial itself (macOS
		// loopback) or by the first read; either way the client gets an error.
		if client, err := net.DialTimeout("tcp", p.Addr(), testBudget); err == nil {
			_ = client.SetReadDeadline(time.Now().Add(testBudget))
			n, readErr := client.Read(make([]byte, 1))
			_ = client.Close()
			if readErr == nil {
				t.Fatalf("refused connection %d delivered %d bytes", index, n)
			}
		}
		stats := p.Await(t, index)
		if stats.Reason != ReasonRefused || !stats.Halted || !stats.Closed {
			t.Fatalf("connection %d stats = %+v", index, stats)
		}
	}
	client := dial(t, p.Addr())
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, client, 5); string(got) != "hello" {
		t.Fatalf("third connection echoed %q", got)
	}
	_ = client.Close()
	if stats := p.Await(t, 3); stats.Reason != ReasonNone {
		t.Fatalf("third connection stats = %+v", stats)
	}
	if total := p.Stats(); total.Accepted != 3 || total.Refused != 2 || total.Dropped != 0 {
		t.Fatalf("proxy stats = %+v", total)
	}
	if up.accepted() != 1 {
		t.Fatalf("upstream saw %d connections, want 1", up.accepted())
	}
}

func TestRulesSwitchAtRuntimeForNewConnectionsOnly(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p := startProxy(t, up.addr())
	ctx := testContext(t)
	first := dial(t, p.Addr())
	if _, err := p.WaitConn(ctx, 1); err != nil {
		t.Fatal(err)
	}
	p.MustSetRules(t, Rule{Faults: []Fault{DropAfterBytes(ClientToServer, 5)}})
	// Connection 1 was accepted before the rule existed and keeps running.
	if _, err := first.Write(pattern(100)); err != nil {
		t.Fatal(err)
	}
	readFull(t, first, 100)
	second := dial(t, p.Addr())
	if _, err := second.Write(pattern(100)); err != nil {
		t.Fatal(err)
	}
	readAll(t, second)
	_ = second.Close()
	if stats := p.Await(t, 2); stats.Reason != ReasonBytes || stats.ClientToServer != 5 {
		t.Fatalf("connection 2 stats = %+v", stats)
	}
	p.MustSetRules(t)
	third := dial(t, p.Addr())
	if _, err := third.Write(pattern(100)); err != nil {
		t.Fatal(err)
	}
	readFull(t, third, 100)
	_ = first.Close()
	_ = third.Close()
	for _, index := range []int{1, 3} {
		if stats := p.Await(t, index); stats.Reason != ReasonNone || stats.ClientToServer != 100 {
			t.Fatalf("connection %d stats = %+v", index, stats)
		}
	}
}

func TestManualDropCutsALiveConnection(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p := startProxy(t, up.addr())
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(testContext(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, client, 5); string(got) != "alive" {
		t.Fatalf("echo = %q", got)
	}
	conn.Drop()
	select {
	case <-conn.Halted():
	default:
		t.Fatal("Drop returned before the connection halted")
	}
	readAll(t, client)
	_ = client.Close()
	stats := p.Await(t, 1)
	if stats.Reason != ReasonManual || stats.ClientToServer != 5 || stats.ServerToClient != 5 {
		t.Fatalf("stats = %+v", stats)
	}
	if total := p.Stats(); total.Dropped != 1 {
		t.Fatalf("proxy stats = %+v", total)
	}
}

func TestDropAfterDurationWithManualClock(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	clock := NewManualClock(time.Time{})
	p := startProxy(t, up.addr(), WithClock(clock))
	p.MustSetRules(t, Rule{Faults: []Fault{DropAfter(5 * time.Second)}})
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(testContext(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	// The timer is registered before WaitConn returns.
	if clock.Pending() != 1 {
		t.Fatalf("pending timers = %d, want the one drop timer", clock.Pending())
	}
	clock.Advance(5*time.Second - time.Nanosecond)
	select {
	case <-conn.Halted():
		t.Fatal("connection was cut before its duration elapsed")
	default:
	}
	if _, err := client.Write([]byte("early")); err != nil {
		t.Fatal(err)
	}
	if got := readFull(t, client, 5); string(got) != "early" {
		t.Fatalf("echo = %q", got)
	}
	clock.Advance(time.Nanosecond)
	select {
	case <-conn.Halted():
	default:
		t.Fatal("connection was not cut when its duration elapsed")
	}
	readAll(t, client)
	_ = client.Close()
	stats := p.Await(t, 1)
	if stats.Reason != ReasonDuration || stats.ClientToServer != 5 || stats.ServerToClient != 5 {
		t.Fatalf("stats = %+v", stats)
	}
	if clock.Pending() != 0 {
		t.Fatalf("pending timers = %d after the drop", clock.Pending())
	}
}

func TestDropAfterDurationWithRealClock(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Faults: []Fault{DropAfter(100 * time.Millisecond)}})
	start := time.Now()
	client := dial(t, p.Addr())
	readAll(t, client) // returns when the proxy cuts the connection
	elapsed := time.Since(start)
	_ = client.Close()
	// Approximate mode: only the lower bound is a guarantee.
	if elapsed < 90*time.Millisecond {
		t.Fatalf("connection was cut after %s, before its 100ms duration", elapsed)
	}
	if stats := p.Await(t, 1); stats.Reason != ReasonDuration {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestThrottleWithManualClock(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	clock := NewManualClock(time.Time{})
	p := startProxy(t, up.addr(), WithClock(clock))
	p.MustSetRules(t, Rule{Faults: []Fault{ThrottleBurst(ClientToServer, 10, 10)}})
	ctx := testContext(t)
	client := dial(t, p.Addr())
	chunk := pattern(10)
	// The bucket starts full: the first 10 bytes pass at once.
	if _, err := client.Write(chunk); err != nil {
		t.Fatal(err)
	}
	up.waitReceived(t, 1, 10)
	for step := 2; step <= 4; step++ {
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		// The proxy has the next 10 bytes and waits one second for tokens.
		if err := clock.WaitPending(ctx, 1); err != nil {
			t.Fatal(err)
		}
		if got := up.waitReceived(t, 1, 0); len(got) != 10*(step-1) {
			t.Fatalf("step %d: upstream has %d bytes before the clock moved, want %d", step, len(got), 10*(step-1))
		}
		clock.Advance(time.Second)
		up.waitReceived(t, 1, 10*step)
	}
	// Half a second does not release the next 10 bytes, a full one does.
	if _, err := client.Write(chunk); err != nil {
		t.Fatal(err)
	}
	if err := clock.WaitPending(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(500 * time.Millisecond)
	if got := up.waitReceived(t, 1, 0); len(got) != 40 {
		t.Fatalf("upstream has %d bytes after half the refill time, want 40", len(got))
	}
	clock.Advance(500 * time.Millisecond)
	if got := up.waitReceived(t, 1, 50); !bytes.Equal(got, bytes.Repeat(chunk, 5)) {
		t.Fatal("throttled bytes were reordered or altered")
	}
}

func TestThrottleWithRealClockBoundsElapsedTimeFromBelow(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	// 11000 bytes at 50000 B/s with a 1000-byte burst need at least
	// (11000-1000)/50000 = 200ms.
	p.MustSetRules(t, Rule{Faults: []Fault{ThrottleBurst(ClientToServer, 50000, 1000)}})
	payload := pattern(11000)
	start := time.Now()
	client := dial(t, p.Addr())
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := up.waitReceived(t, 1, len(payload)); !bytes.Equal(got, payload) {
		t.Fatal("throttled bytes were altered")
	}
	// Approximate mode: the proxy can be slower than the rate, never faster.
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond {
		t.Fatalf("11000 bytes passed in %s, faster than the throttle allows", elapsed)
	}
}

func TestThrottleAppliesPerDirection(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	clock := NewManualClock(time.Time{})
	p := startProxy(t, up.addr(), WithClock(clock))
	// Only the return path is slow: uploads are not delayed at all.
	p.MustSetRules(t, Rule{Faults: []Fault{ThrottleBurst(ServerToClient, 10, 10)}})
	ctx := testContext(t)
	client := dial(t, p.Addr())
	if _, err := client.Write(pattern(30)); err != nil {
		t.Fatal(err)
	}
	up.waitReceived(t, 1, 30)
	readFull(t, client, 10)
	if err := clock.WaitPending(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	readFull(t, client, 10)
	if err := clock.WaitPending(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	readFull(t, client, 10)
}

func TestThrottleComposesWithByteDrop(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	clock := NewManualClock(time.Time{})
	p := startProxy(t, up.addr(), WithClock(clock))
	p.MustSetRules(t, Rule{Faults: []Fault{
		ThrottleBurst(ClientToServer, 10, 10),
		DropAfterBytes(ClientToServer, 25),
	}})
	ctx := testContext(t)
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := pattern(30)
	if _, err := client.Write(payload[:10]); err != nil {
		t.Fatal(err)
	}
	up.waitReceived(t, 1, 10)
	for step := 1; step <= 2; step++ {
		if _, err := client.Write(payload[10*step : 10*step+10]); err != nil {
			t.Fatal(err)
		}
		if err := clock.WaitPending(ctx, 1); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)
		if step == 1 {
			up.waitReceived(t, 1, 20)
		}
	}
	// The third write is trimmed to the 5 bytes left before the limit.
	select {
	case <-conn.Halted():
	case <-ctx.Done():
		t.Fatal("connection never reached its byte limit")
	}
	readAll(t, client)
	_ = client.Close()
	stats := p.Await(t, 1)
	if stats.Reason != ReasonBytes || stats.ClientToServer != 25 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := up.waitEnded(t, 1); !bytes.Equal(got, payload[:25]) {
		t.Fatalf("upstream received %d bytes, want exactly the first 25", len(got))
	}
}

func TestInvalidFaultsAreRejected(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	invalid := []Fault{
		{},
		DropAfterBytes(0, 10),
		DropAfterBytes(Direction(8), 10),
		DropAfterBytes(Both, -1),
		DropAfter(-time.Second),
		Throttle(Both, 0),
		Throttle(0, 100),
		ThrottleBurst(Both, 100, 0),
		ThrottleBurst(Both, maxBurst+1, 10),
	}
	for i, fault := range invalid {
		if err := p.SetRules(Rule{Faults: []Fault{fault}}); err == nil {
			t.Fatalf("invalid fault #%d was accepted", i)
		}
	}
	if err := p.SetRules(Rule{Faults: []Fault{DropAfterBytes(Both, 0), Throttle(Both, 1)}}); err != nil {
		t.Fatalf("valid faults were rejected: %v", err)
	}
}

func TestUpstreamDialFailureEndsTheConnection(t *testing.T) {
	// A closed listener gives an address nothing listens on.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := listener.Addr().String()
	_ = listener.Close()
	p := startProxy(t, dead)
	client := dial(t, p.Addr())
	readAll(t, client)
	_ = client.Close()
	if stats := p.Await(t, 1); stats.Reason != ReasonError || !stats.Closed {
		t.Fatalf("stats = %+v", stats)
	}
	if total := p.Stats(); total.Dropped != 0 {
		t.Fatalf("a dial error is not an injected drop: %+v", total)
	}
}

func TestCloseJoinsGoroutinesAndCutsLiveConnections(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p, err := New(up.addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { requireNoProxyGoroutines(t) })
	t.Cleanup(func() { _ = p.Close() })
	var clients []net.Conn
	for index := 1; index <= 3; index++ {
		client := dial(t, p.Addr())
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		readFull(t, client, 1)
		clients = append(clients, client)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for index, client := range clients {
		_ = client.SetReadDeadline(time.Now().Add(testBudget))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatalf("client %d still reads data after Close", index+1)
		}
	}
	for index := 1; index <= 3; index++ {
		if stats := p.Await(t, index); stats.Reason != ReasonShutdown || !stats.Closed {
			t.Fatalf("connection %d stats = %+v", index, stats)
		}
	}
	if _, err := p.WaitConn(testContext(t), 4); !errors.Is(err, ErrClosed) {
		t.Fatalf("WaitConn after Close = %v, want ErrClosed", err)
	}
	if conn, err := net.DialTimeout("tcp", p.Addr(), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("the listener still accepts after Close")
	}
}

func TestWaitConnHonoursItsContext(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.WaitConn(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitConn with a cancelled context = %v", err)
	}
	if _, err := p.WaitConn(testContext(t), 0); err == nil {
		t.Fatal("index 0 was accepted")
	}
}
