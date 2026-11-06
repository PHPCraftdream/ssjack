package ownerresource

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

type controlledConsumerClose struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	err     error
}

func (c *controlledConsumerClose) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.err
}

func closeFixture(t *testing.T, adapter io.Closer) (*Resources, *Consumer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runner := remote.StreamRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil })
	server, err := apptransport.Listen(ctx, "synthetic-consumer", runner)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	t.Cleanup(cancel)
	if controlled, ok := adapter.(*controlledConsumerClose); ok {
		t.Cleanup(func() {
			select {
			case <-controlled.release:
			default:
				close(controlled.release)
			}
		})
	}
	r := &Resources{consumers: make(map[*Consumer]struct{})}
	c := &Consumer{owner: r, server: server, adapter: adapter, cancel: cancel, done: make(chan struct{})}
	r.consumers[c] = struct{}{}
	return r, c
}

func TestConsumerShutdownDoesNotFakeJoin(t *testing.T) {
	adapter := &controlledConsumerClose{entered: make(chan struct{}), release: make(chan struct{})}
	r, c := closeFixture(t, adapter)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("unfinished consumer reported a successful close")
	}
	joined, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	select {
	case <-adapter.entered:
	case <-joined.Done():
		t.Fatal("consumer shutdown did not start")
	}
	if err := r.CloseConsumers(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("parent accepted an unfinished consumer shutdown")
	}
	r.consumersMu.Lock()
	retained := len(r.consumers) == 1 && r.consumersClosing
	r.consumersMu.Unlock()
	if !retained {
		t.Fatal("parent lost the unfinished borrower")
	}
	close(adapter.release)
	if err := r.CloseConsumers(joined); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(joined); err != nil {
		t.Fatal(err)
	}
	if consumer, err := r.ServeText(joined, TextRequest{}); err == nil || consumer != nil {
		t.Fatal("closing resource admitted a new consumer")
	}
}

func TestConsumerCloseFailureKeepsRecoveryVisible(t *testing.T) {
	adapter := &controlledConsumerClose{entered: make(chan struct{}), release: make(chan struct{}), err: errors.New("synthetic private diagnostic")}
	close(adapter.release)
	r, c := closeFixture(t, adapter)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.Close(ctx); !errors.Is(err, ErrConsumer) {
		t.Fatal("consumer close failure was lost or disclosed")
	}
	if err := r.CloseConsumers(ctx); !errors.Is(err, ErrConsumer) {
		t.Fatal("repeated parent close silently dropped a failed consumer")
	}
}

func TestConsumerAdmissionBoundPrecedesInstallationAccess(t *testing.T) {
	r := &Resources{consumers: make(map[*Consumer]struct{})}
	for i := 0; i < maxConsumers; i++ {
		r.consumers[&Consumer{}] = struct{}{}
	}
	if consumer, err := r.ServeText(context.Background(), TextRequest{}); err == nil || consumer != nil {
		t.Fatal("consumer bound admitted another transport")
	}
}
