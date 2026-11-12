package mcpbridge

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// notifyingConnection signals the initialized notification, the last write of a
// successful handshake, so a test can cancel strictly after Connect has won.
type notifyingConnection struct {
	*testConnection
	notified chan struct{}
	signal   sync.Once
}

func (c *notifyingConnection) Write(ctx context.Context, m jsonrpc.Message) error {
	err := c.testConnection.Write(ctx, m)
	if req, ok := m.(*jsonrpc.Request); ok && !req.ID.IsValid() {
		c.signal.Do(func() { close(c.notified) })
	}
	return err
}

// TestSessionWonAfterShutdownIsJoinedCleanly forces the interleaving where
// Client.Connect completes while r.ctx is only canceled afterwards: the session
// is published on a failed slot and cleanup must join its owned close as clean
// (an owned close reports io.EOF, as the production exchange does).
func TestSessionWonAfterShutdownIsJoinedCleanly(t *testing.T) {
	conn := &notifyingConnection{testConnection: newTestConnection("2025-06-18"), notified: make(chan struct{})}
	r := testRuntime(t, context.Background(), &testHandle{transport: &testTransport{conn}}, func(context.Context) error { return nil }, false)
	result := make(chan wire.Reply, 1)
	exited := make(chan struct{})
	var responseOnce sync.Once
	locked := false
	releaseResponse := func() { responseOnce.Do(func() { close(conn.response) }) }
	unlock := func() {
		if locked {
			locked = false
			r.mu.Unlock()
		}
	}
	describeAsync(t, r, context.Background(), exited, result)
	t.Cleanup(func() {
		releaseResponse()
		unlock()
		joinExited(t, exited, "operation worker did not exit")
	})
	awaitSignal(t, conn.request, "initialize request was not written")
	r.mu.Lock() // parks initialize before its validity check until cancellation is in place
	locked = true
	releaseResponse()
	awaitSignal(t, conn.notified, "handshake did not complete")
	r.cancel()
	unlock()
	if err := closeBounded(t, r, time.Second); err != nil {
		t.Fatalf("Close did not join the late session cleanly: %v", err)
	}
	if reply := awaitSignal(t, result, "operation outlived Close"); reply.OK {
		t.Fatalf("describe succeeded after shutdown: %+v", reply)
	}
	awaitSignal(t, exited, "operation worker did not exit")
	s := r.slots[0]
	s.mu.Lock()
	failed, installed := s.failed, s.session != nil
	s.mu.Unlock()
	if !failed || !installed {
		t.Fatalf("late session state failed=%v installed=%v, want failed session joined by cleanup", failed, installed)
	}
	if !conn.once.Load() {
		t.Fatal("late session connection did not close")
	}
}
