package faultproxy

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// waitStalled blocks until the connection's stall engaged. The budget is a hang
// detector, never an expected delay.
func waitStalled(t *testing.T, conn *Conn) {
	t.Helper()
	select {
	case <-conn.Stalled():
	case <-time.After(testBudget):
		t.Fatal("the connection never stalled")
	}
}

func requireNotHalted(t *testing.T, conn *Conn) {
	t.Helper()
	select {
	case <-conn.Halted():
		t.Fatal("a stalled connection was cut; it must stay open")
	default:
	}
}

func TestStallAfterBytesClientToServerIsExactAndKeepsTheSocketOpen(t *testing.T) {
	// 32768 is the read chunk size and 70000 spans several chunks, so the
	// freeze is exact regardless of how the stream is read.
	for _, limit := range []int64{1, 10, 32768, 70000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			up := newUpstream(t, upstreamOptions{})
			p := startProxy(t, up.addr())
			p.MustSetRules(t, Rule{Faults: []Fault{StallAfterBytes(ClientToServer, limit)}})
			client := dial(t, p.Addr())
			conn, err := p.WaitConn(testContext(t), 1)
			if err != nil {
				t.Fatal(err)
			}
			payload := pattern(100 * 1024)
			wait := writeAsync(client, payload)
			waitStalled(t, conn)
			// The proxy keeps reading and discarding, so the client's write
			// completes: nothing is refused, reset or closed.
			if err := wait(); err != nil {
				t.Fatalf("client write on a stalled connection: %v", err)
			}
			requireNotHalted(t, conn)
			if total := p.Stats(); total.Stalled != 1 || total.Dropped != 0 || total.Closed != 0 {
				t.Fatalf("proxy stats while stalled = %+v", total)
			}
			// A peer that closes its own end still winds the connection down,
			// and everything after the stall point was discarded, not forwarded.
			_ = client.Close()
			stats := p.Await(t, 1)
			if !stats.Stalled || stats.Reason != ReasonNone || stats.ClientToServer != limit || stats.ServerToClient != 0 {
				t.Fatalf("stats = %+v, want a stall at exactly %d bytes", stats, limit)
			}
			if got := up.waitEnded(t, 1); !bytes.Equal(got, payload[:limit]) {
				t.Fatalf("upstream received %d bytes, want exactly the first %d", len(got), limit)
			}
			if total := p.Stats(); total.Stalled != 1 || total.Dropped != 0 {
				t.Fatalf("proxy stats = %+v", total)
			}
		})
	}
}

func TestStallAfterBytesServerToClientIsExact(t *testing.T) {
	for _, limit := range []int64{1, 10, 32768, 70000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			greeting := pattern(100 * 1024)
			up := newUpstream(t, upstreamOptions{greeting: greeting})
			p := startProxy(t, up.addr())
			p.MustSetRules(t, Rule{Faults: []Fault{StallAfterBytes(ServerToClient, limit)}})
			client := dial(t, p.Addr())
			conn, err := p.WaitConn(testContext(t), 1)
			if err != nil {
				t.Fatal(err)
			}
			waitStalled(t, conn)
			requireNotHalted(t, conn)
			// Ending the frozen connection by hand shows what crossed: every
			// forwarded byte and not one more.
			conn.Drop()
			got := readAll(t, client)
			_ = client.Close()
			if !bytes.Equal(got, greeting[:limit]) {
				t.Fatalf("client received %d bytes, want exactly the first %d", len(got), limit)
			}
			stats := p.Await(t, 1)
			if !stats.Stalled || stats.Reason != ReasonManual || stats.ServerToClient != limit || stats.ClientToServer != 0 {
				t.Fatalf("stats = %+v, want a stall at exactly %d bytes", stats, limit)
			}
		})
	}
}

func TestStallAfterBytesBothDirectionsCountsTheSumAndFreezesBoth(t *testing.T) {
	const limit = 20
	up := newUpstream(t, upstreamOptions{echo: true, greeting: pattern(8)})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Faults: []Fault{StallAfterBytes(Both, limit)}})
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(testContext(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	wait := writeAsync(client, pattern(100))
	waitStalled(t, conn)
	requireNotHalted(t, conn)
	conn.Drop()
	received := readAll(t, client)
	_ = client.Close()
	_ = wait()
	stats := p.Await(t, 1)
	if !stats.Stalled || stats.Reason != ReasonManual || stats.ClientToServer+stats.ServerToClient != limit {
		t.Fatalf("stats = %+v, want %d bytes in total", stats, limit)
	}
	if int64(len(received)) != stats.ServerToClient {
		t.Fatalf("client received %d bytes, proxy counted %d", len(received), stats.ServerToClient)
	}
	if got := up.waitEnded(t, 1); int64(len(got)) != stats.ClientToServer {
		t.Fatalf("upstream received %d bytes, proxy counted %d", len(got), stats.ClientToServer)
	}
}

func TestStallAfterZeroBytesFreezesRightAfterAccept(t *testing.T) {
	up := newUpstream(t, upstreamOptions{greeting: pattern(16)})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Faults: []Fault{StallAfterBytes(Both, 0)}})
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(testContext(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	// The stall is part of the plan that exists when WaitConn returns.
	select {
	case <-conn.Stalled():
	default:
		t.Fatal("a zero-byte stall was not engaged at accept")
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	up.waitReceived(t, 1, 0) // the upstream was dialed: the frozen link is a live one
	conn.Drop()
	if got := readAll(t, client); len(got) != 0 {
		t.Fatalf("client received %d bytes through a frozen connection", len(got))
	}
	_ = client.Close()
	stats := p.Await(t, 1)
	if !stats.Stalled || stats.ClientToServer != 0 || stats.ServerToClient != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := up.waitEnded(t, 1); len(got) != 0 {
		t.Fatalf("upstream received %d bytes through a frozen connection", len(got))
	}
}

func TestStallAfterDurationWithManualClock(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	clock := NewManualClock(time.Time{})
	p := startProxy(t, up.addr(), WithClock(clock))
	p.MustSetRules(t, Rule{Faults: []Fault{StallAfter(5 * time.Second)}})
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(testContext(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if clock.Pending() != 1 {
		t.Fatalf("pending timers = %d, want the one stall timer", clock.Pending())
	}
	clock.Advance(5*time.Second - time.Nanosecond)
	select {
	case <-conn.Stalled():
		t.Fatal("the connection stalled before its duration elapsed")
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
	case <-conn.Stalled():
	default:
		t.Fatal("the connection did not stall when its duration elapsed")
	}
	requireNotHalted(t, conn)
	if _, err := client.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	conn.Drop()
	if got := readAll(t, client); len(got) != 0 {
		t.Fatalf("a frozen connection echoed %q", got)
	}
	_ = client.Close()
	stats := p.Await(t, 1)
	if !stats.Stalled || stats.Reason != ReasonManual || stats.ClientToServer != 5 || stats.ServerToClient != 5 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := up.waitEnded(t, 1); string(got) != "early" {
		t.Fatalf("upstream received %q, want only the bytes before the stall", got)
	}
	if clock.Pending() != 0 {
		t.Fatalf("pending timers = %d after the stall", clock.Pending())
	}
}

func TestStalledConnectionEndsWhenTheProxyCloses(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Faults: []Fault{StallAfterBytes(ClientToServer, 4)}})
	client := dial(t, p.Addr())
	conn, err := p.WaitConn(testContext(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(pattern(64)); err != nil {
		t.Fatal(err)
	}
	waitStalled(t, conn)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	stats := p.Await(t, 1)
	if !stats.Stalled || stats.Reason != ReasonShutdown || !stats.Closed || stats.ClientToServer != 4 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestStallOnlyAffectsTheSelectedConnections(t *testing.T) {
	up := newUpstream(t, upstreamOptions{echo: true})
	p := startProxy(t, up.addr())
	p.MustSetRules(t, Rule{Conns: Conns(2), Faults: []Fault{StallAfterBytes(ClientToServer, 0)}})
	for index := 1; index <= 3; index++ {
		client := dial(t, p.Addr())
		conn, err := p.WaitConn(testContext(t), index)
		if err != nil {
			t.Fatal(err)
		}
		if index == 2 {
			waitStalled(t, conn)
			conn.Drop()
			readAll(t, client)
			_ = client.Close()
			if stats := p.Await(t, index); !stats.Stalled {
				t.Fatalf("connection 2 stats = %+v", stats)
			}
			continue
		}
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if got := readFull(t, client, 4); string(got) != "ping" {
			t.Fatalf("connection %d echo = %q", index, got)
		}
		_ = client.Close()
		if stats := p.Await(t, index); stats.Stalled || stats.Reason != ReasonNone {
			t.Fatalf("connection %d stats = %+v, want an untouched pass-through", index, stats)
		}
	}
	if total := p.Stats(); total.Accepted != 3 || total.Stalled != 1 {
		t.Fatalf("proxy stats = %+v", total)
	}
}

func TestInvalidStallFaultsAreRejected(t *testing.T) {
	up := newUpstream(t, upstreamOptions{})
	p := startProxy(t, up.addr())
	for i, fault := range []Fault{
		StallAfterBytes(0, 10),
		StallAfterBytes(Direction(8), 10),
		StallAfterBytes(Both, -1),
		StallAfter(-time.Second),
	} {
		if err := p.SetRules(Rule{Faults: []Fault{fault}}); err == nil {
			t.Fatalf("invalid stall fault #%d was accepted", i)
		}
	}
	if err := p.SetRules(Rule{Faults: []Fault{StallAfterBytes(Both, 0), StallAfter(0)}}); err != nil {
		t.Fatalf("valid stall faults were rejected: %v", err)
	}
}
