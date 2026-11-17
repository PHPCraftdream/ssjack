// Package faultproxy is a test-only TCP proxy that sits between a client and
// a server (for ssjack: the engine's SSH client and a test sshd) and injects
// connection faults on purpose: it cuts a connection after an exact number of
// forwarded bytes, after a duration, throttles it to a byte rate, or refuses
// connections outright, or freezes it silently after an exact number of bytes
// or a duration (StallAfterBytes, StallAfter): the socket stays open and
// nothing moves, the failure mode that only an inactivity timer can detect.
//
// Faults are described by Rule values (a connection selector plus Fault
// values) and are resolved once when a connection is accepted. SetRules
// changes the rules for connections accepted afterwards; connections already
// open keep the plan they were accepted with, except that Conn.Drop cuts one
// by hand. Connections are numbered from 1 in accept order, so a test can
// target "the 1st and 3rd connection only" with Conns(1, 3).
//
// Determinism. Byte-count drops are exact: the sum of the bytes forwarded in
// the selected directions never exceeds N and is exactly N when the drop
// fires, whatever the read sizes. Duration and throttle behaviour measure
// time through a Clock; with the default real clock they are approximate
// (timer and scheduler latency), so assert only lower bounds on elapsed time.
// With ManualClock they are exact and need no sleeping: the test advances
// time itself and waits for the proxy with WaitPending.
//
// Observability needs no sleeping either: Proxy.WaitConn waits until the k-th
// connection exists, Conn.Halted closes when a fault fired, Conn.Stalled closes
// when a stall engaged and Conn.Done closes when the connection is fully
// released. Proxy.Close joins every goroutine the proxy started.
//
// A cut is clean: the proxy half-closes both peers after the last forwarded
// byte, so the peers read every byte that was counted as forwarded and then
// see EOF; it never relies on a reset (see WithLinger).
//
// Usage in a test:
//
//	proxy := faultproxy.Start(t, server.Address())      // closed at cleanup
//	runner, _ := remote.NewCredentialStreamRunner(name, proxy.Addr(), config)
//	proxy.MustSetRules(t, faultproxy.Rule{
//		Conns:  faultproxy.Conns(1, 3), // nil: every connection
//		Faults: []faultproxy.Fault{faultproxy.DropAfterBytes(faultproxy.ClientToServer, 64<<10)},
//	})
//	// ... run the transfer ...
//	stats := proxy.Await(t, 1) // waits for connection #1 to close, no sleeping
//
// With a ManualClock (WithClock) a duration or throttle test advances time
// itself: WaitConn(k) guarantees the drop timer exists, ManualClock.WaitPending
// guarantees a throttled pump waits for tokens, then ManualClock.Advance.
package faultproxy

import (
	"errors"
	"fmt"
	"time"
)

// Direction selects the bytes a fault applies to. The values combine with |.
type Direction uint8

const (
	// ClientToServer is traffic read from the dialing client and written to
	// the upstream server (for the engine: the upload stream).
	ClientToServer Direction = 1 << iota
	// ServerToClient is traffic read from the upstream server and written to
	// the client (for the engine: the download stream).
	ServerToClient
	// Both selects both directions.
	Both = ClientToServer | ServerToClient
)

func (d Direction) valid() bool { return d != 0 && d&^Both == 0 }

// dirIndex returns 0 for ClientToServer and 1 for ServerToClient.
func dirIndex(d Direction) int {
	if d == ClientToServer {
		return 0
	}
	return 1
}

type faultKind uint8

const (
	kindDropBytes faultKind = iota + 1
	kindDropAfter
	kindThrottle
	kindStallBytes
	kindStallAfter
)

// Fault is one fault behaviour. Build it with DropAfterBytes, DropAfter,
// Throttle or ThrottleBurst. Faults of one Rule and of several matching
// Rules all apply to a connection: several byte limits each cut the
// connection when reached, several durations cut at the earliest, and of
// several throttles for one direction the last wins.
type Fault struct {
	kind  faultKind
	dir   Direction
	n     int64
	burst int64
	d     time.Duration
}

// DropAfterBytes cuts the connection once n bytes were forwarded in total in
// the directions selected by dir. n == 0 cuts it right after accept, before
// anything is dialed or forwarded. With Both the split between the two
// directions depends on scheduling but their sum is exactly n.
func DropAfterBytes(dir Direction, n int64) Fault {
	return Fault{kind: kindDropBytes, dir: dir, n: n}
}

// DropAfter cuts the connection d after it was accepted, measured by the
// proxy's Clock.
func DropAfter(d time.Duration) Fault {
	return Fault{kind: kindDropAfter, d: d}
}

// StallAfterBytes freezes the connection once n bytes were forwarded in total
// in the directions selected by dir: exactly n bytes cross, then nothing more
// is forwarded in either direction, and the connection stays open. Bytes the
// peers send afterwards are read and discarded (never forwarded, never
// answered), so neither side sees a reset or an EOF from the proxy: a silent
// break, as when a middlebox loses the path but keeps the socket state. When a
// peer closes its own end the close is passed on as usual, so a client that
// gives up (its stall watchdog fired) lets the upstream wind down. n == 0
// freezes the connection right after accept. Conn.Drop, a DropAfter fault and
// Proxy.Close still end a frozen connection.
func StallAfterBytes(dir Direction, n int64) Fault {
	return Fault{kind: kindStallBytes, dir: dir, n: n}
}

// StallAfter freezes the connection d after it was accepted, measured by the
// proxy's Clock, with the semantics of StallAfterBytes.
func StallAfter(d time.Duration) Fault {
	return Fault{kind: kindStallAfter, d: d}
}

// Throttle limits each selected direction of the connection to bytesPerSecond
// with a token bucket whose capacity is one second of traffic.
func Throttle(dir Direction, bytesPerSecond int64) Fault {
	return ThrottleBurst(dir, bytesPerSecond, bytesPerSecond)
}

// ThrottleBurst is Throttle with an explicit bucket capacity in bytes: that
// many bytes may pass at once after an idle period. The bucket starts full.
func ThrottleBurst(dir Direction, bytesPerSecond, burst int64) Fault {
	return Fault{kind: kindThrottle, dir: dir, n: bytesPerSecond, burst: burst}
}

// maxBurst keeps the bucket arithmetic inside int64.
const maxBurst = int64(1) << 32

func (f Fault) validate() error {
	switch f.kind {
	case kindDropBytes, kindStallBytes:
		if !f.dir.valid() {
			return errors.New("faultproxy: invalid direction")
		}
		if f.n < 0 {
			return fmt.Errorf("faultproxy: negative byte limit %d", f.n)
		}
	case kindDropAfter, kindStallAfter:
		if f.d < 0 {
			return fmt.Errorf("faultproxy: negative duration %s", f.d)
		}
	case kindThrottle:
		if !f.dir.valid() {
			return errors.New("faultproxy: invalid direction")
		}
		if f.n <= 0 || f.n > maxBurst {
			return fmt.Errorf("faultproxy: throttle rate %d out of range", f.n)
		}
		if f.burst <= 0 || f.burst > maxBurst {
			return fmt.Errorf("faultproxy: throttle burst %d out of range", f.burst)
		}
	default:
		return errors.New("faultproxy: zero Fault")
	}
	return nil
}

// Selector reports whether a rule applies to the connection with the given
// 1-based index.
type Selector func(index int) bool

// AllConns selects every connection.
func AllConns() Selector { return func(int) bool { return true } }

// Conns selects exactly the listed connection indexes.
func Conns(indexes ...int) Selector {
	set := make(map[int]struct{}, len(indexes))
	for _, index := range indexes {
		set[index] = struct{}{}
	}
	return func(index int) bool {
		_, ok := set[index]
		return ok
	}
}

// FromConn selects the connection with index first and every later one.
func FromConn(first int) Selector { return func(index int) bool { return index >= first } }

// Rule applies Faults to the connections its Conns selector matches. A nil
// selector matches every connection.
type Rule struct {
	Conns  Selector
	Faults []Fault
}

// Reason says why forwarding on a connection stopped.
type Reason string

const (
	// ReasonNone: the connection ended on its own or is still running.
	ReasonNone Reason = ""
	// ReasonBytes: a DropAfterBytes limit was reached.
	ReasonBytes Reason = "bytes"
	// ReasonDuration: a DropAfter timer fired.
	ReasonDuration Reason = "duration"
	// ReasonManual: Conn.Drop was called.
	ReasonManual Reason = "manual"
	// ReasonRefused: the connection was refused by RefuseNext.
	ReasonRefused Reason = "refused"
	// ReasonError: a socket or upstream dial error ended the connection.
	ReasonError Reason = "error"
	// ReasonShutdown: Proxy.Close ended the connection.
	ReasonShutdown Reason = "shutdown"
)

// isFault reports whether the reason is an injected drop.
func (r Reason) isFault() bool {
	return r == ReasonBytes || r == ReasonDuration || r == ReasonManual
}
