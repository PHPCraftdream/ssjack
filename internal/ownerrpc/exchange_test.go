package ownerrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
)

// Protocol probes test I/O state only; production entry points require real peers.
type clientProbe struct {
	commands, replies, closes int
	badReply                  bool
	errorCode                 string
}

func (p *clientProbe) AcceptHello([]byte) ([]byte, error) { return []byte("auth"), nil }
func (p *clientProbe) AcceptReady([]byte) error           { return nil }
func (p *clientProbe) Deadline() time.Time                { return time.Now().Add(time.Minute) }
func (p *clientProbe) Close()                             { p.closes++ }
func (p *clientProbe) Command(ownerpacket.Command) ([]byte, error) {
	p.commands++
	return []byte("command"), nil
}
func (p *clientProbe) OpenReply([]byte) (ownerpacket.Reply, error) {
	p.replies++
	if p.badReply {
		return ownerpacket.Reply{}, ownerpacket.ErrAuthentication
	}
	return ownerpacket.Reply{ErrorCode: p.errorCode, Status: ownerpacket.Status{Revision: 9}}, nil
}

type exchangeConnection struct {
	input          io.Reader
	writes, closes int
	failWrite      int
}

func (c *exchangeConnection) Read(_ context.Context, data []byte) (int, error) {
	return c.input.Read(data)
}
func (c *exchangeConnection) Write(_ context.Context, data []byte) (int, error) {
	c.writes++
	if c.failWrite == c.writes {
		return 0, io.ErrClosedPipe
	}
	return len(data), nil
}
func (c *exchangeConnection) Close() error { c.closes++; return nil }

func frames(parts ...string) *bytes.Reader {
	var b bytes.Buffer
	for _, part := range parts {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(part)))
		b.Write(header[:])
		b.WriteString(part)
	}
	return bytes.NewReader(b.Bytes())
}

func TestClientNeverReplaysAnUncertainExchange(t *testing.T) {
	for _, mode := range []string{"write-header", "write-body", "read", "bad-reply", "success"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			p := &clientProbe{badReply: mode == "bad-reply"}
			connection := &exchangeConnection{input: frames("reply")}
			switch mode {
			case "write-header":
				connection.failWrite = 1
			case "write-body":
				connection.failWrite = 2
			case "read":
				connection.input = frames()
			}
			c := newClient(connection, p)
			reply, err := c.Call(ctx, ownerpacket.Command{Operation: "snapshot"})
			if mode == "success" {
				if err != nil || reply.Status.Revision != 9 {
					t.Fatal("successful exchange lost its authenticated reply")
				}
			} else {
				if !errors.Is(err, ownerpacket.ErrUncertain) {
					t.Fatal("dispatched command without a reply was not uncertain")
				}
				writes := connection.writes
				if _, err := c.Call(ctx, ownerpacket.Command{Operation: "snapshot"}); !errors.Is(err, ownerpacket.ErrAuthentication) || p.commands != 1 || connection.writes != writes {
					t.Fatal("failed channel retried or admitted another command")
				}
			}
			c.Close()
			c.Close()
			if connection.closes != 1 || p.closes != 1 {
				t.Fatal("client failed to close owned connection and peer exactly once")
			}
		})
	}
}

type endingHandler struct {
	connection *exchangeConnection
	bounded    bool
}

func (h *endingHandler) Dispatch(context.Context, *ownerpacket.Command) ownerpacket.Reply {
	return ownerpacket.Reply{}
}
func (h *endingHandler) EndLease(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	h.bounded = ok && ctx.Err() == nil && time.Until(deadline) > 0 && time.Until(deadline) <= time.Minute && h.connection.closes == 1
	return errors.New("synthetic-private-lease-diagnostic")
}

func TestServePeerEndsLeaseAfterIOWithAnIndependentBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	connection := &exchangeConnection{input: frames()}
	handler := &endingHandler{connection: connection}
	if err := ServePeer(ctx, connection, nil, handler); !errors.Is(err, ownerpacket.ErrUncertain) || !handler.bounded {
		t.Fatal("peer release ignored failure, leaked diagnostics or reused cancelled context before I/O closure")
	}
}

func TestExecuteProjectsOneReplyAndPreservesFixedRefusals(t *testing.T) {
	for _, code := range []string{"", "stale", "pending", "uncertain"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		p := &clientProbe{errorCode: code}
		c := newClient(&exchangeConnection{input: frames("reply")}, p)
		snapshot, err := c.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
		c.Close()
		cancel()
		if snapshot.Status.Database.Revision != 9 || !errors.Is(err, codeError(code)) || p.commands != 1 || p.replies != 1 {
			t.Fatal("RPC execution changed its atomic snapshot, refusal or message count")
		}
	}
}

func TestClientRequiresABoundBeforeEncodingOrIO(t *testing.T) {
	p := &clientProbe{}
	connection := &exchangeConnection{input: frames()}
	c := newClient(connection, p)
	defer c.Close()
	if _, err := c.Call(context.Background(), ownerpacket.Command{Operation: "snapshot"}); err == nil || p.commands != 0 || connection.writes != 0 {
		t.Fatal("unbounded RPC reached packet encoding or I/O")
	}
}

func TestWaitingClientCallCanCancelBeforeAdmission(t *testing.T) {
	p := &clientProbe{}
	connection := &exchangeConnection{input: frames()}
	c := newClient(connection, p)
	c.gate <- struct{}{}
	defer c.Close()
	defer func() { <-c.gate }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, ownerpacket.Command{Operation: "snapshot"}); err == nil || p.commands != 0 || connection.writes != 0 {
		t.Fatal("waiting RPC ignored cancellation or encoded a command before admission")
	}
}

type blockedConnection struct {
	entered, stopped chan struct{}
	once             sync.Once
	reading          atomic.Bool
}

func (c *blockedConnection) Read(ctx context.Context, _ []byte) (int, error) {
	c.reading.Store(true)
	close(c.entered)
	select {
	case <-ctx.Done():
	case <-c.stopped:
	}
	c.reading.Store(false)
	return 0, io.ErrClosedPipe
}
func (c *blockedConnection) Write(context.Context, []byte) (int, error) { return 1, nil }
func (c *blockedConnection) Close() error {
	c.once.Do(func() { close(c.stopped) })
	return nil
}

func TestClientCloseUnblocksAndJoinsTheActiveExchange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	connection := &blockedConnection{entered: make(chan struct{}), stopped: make(chan struct{})}
	p := &clientProbe{}
	c := newClient(connection, p)
	done := make(chan error, 1)
	go func() { _, err := c.Call(ctx, ownerpacket.Command{Operation: "snapshot"}); done <- err }()
	select {
	case <-connection.entered:
	case <-ctx.Done():
		t.Fatal("exchange did not reach the controlled read barrier")
	}
	c.Close()
	if connection.reading.Load() || p.closes != 1 {
		t.Fatal("client released its peer before the active exchange joined")
	}
	if err := <-done; !errors.Is(err, ownerpacket.ErrUncertain) {
		t.Fatal("interrupted dispatched exchange lost uncertainty")
	}
}

type serverProbe struct {
	command *ownerpacket.Command
	failure string
	closes  int
}

func (p *serverProbe) Hello() ([]byte, error) { return []byte("hello"), nil }
func (p *serverProbe) Authenticate([]byte) ([]byte, error) {
	if p.failure == "authentication" {
		return nil, ownerpacket.ErrAuthentication
	}
	return []byte("ready"), nil
}
func (p *serverProbe) OpenCommand([]byte) (*ownerpacket.Command, error) {
	if p.failure == "command" {
		return nil, ownerpacket.ErrProtocol
	}
	return p.command, nil
}
func (p *serverProbe) Reply(ownerpacket.Reply) ([]byte, error) {
	if p.failure == "reply" {
		return nil, ownerpacket.ErrProtocol
	}
	return []byte("reply"), nil
}
func (p *serverProbe) Deadline() time.Time { return time.Now().Add(time.Minute) }
func (p *serverProbe) Close()              { p.closes++ }

type handlerFunc func(context.Context, *ownerpacket.Command) ownerpacket.Reply

func (f handlerFunc) Dispatch(ctx context.Context, c *ownerpacket.Command) ownerpacket.Reply {
	return f(ctx, c)
}

func TestServerAuthenticatesBeforeDispatchAndClearsAfterEveryOutcome(t *testing.T) {
	for _, mode := range []string{"authentication", "command", "reply", "write", "success"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			private := []byte("synthetic-private-input")
			p := &serverProbe{failure: mode, command: &ownerpacket.Command{Secret: &ownerpacket.SecretChange{Value: private}}}
			connection := &exchangeConnection{input: frames("auth", "command")}
			if mode == "write" {
				connection.failWrite = 5
			}
			calls := 0
			handler := handlerFunc(func(ctx context.Context, command *ownerpacket.Command) ownerpacket.Reply {
				calls++
				if _, bounded := ctx.Deadline(); !bounded || string(command.Secret.Value) != "synthetic-private-input" {
					t.Fatal("dispatch lost its bound or owned private input")
				}
				return ownerpacket.Reply{}
			})
			if err := servePeer(ctx, connection, p, handler); err == nil {
				t.Fatal("finite fixture unexpectedly retained a live peer")
			}
			want := 1
			if mode == "authentication" || mode == "command" {
				want = 0
			}
			if calls != want || p.closes != 1 || connection.closes != 1 {
				t.Fatal("server dispatched before authentication, replayed, or leaked ownership")
			}
			if want == 1 && !bytes.Equal(private, make([]byte, len(private))) {
				t.Fatal("server retained private command buffers after dispatch")
			}
		})
	}
}
