package ownerresource

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const maxConsumers = 16

var ErrConsumer = errors.New("protected text consumer is unavailable")

type TextRequest struct {
	Mode, GrantID, Profile, CredentialDigest string
	Runner                                   remote.StreamRunner
}

// Consumer owns only its transport and adapter, never the installation handles.
type Consumer struct {
	owner   *Resources
	server  *apptransport.Server
	adapter io.Closer
	cancel  context.CancelFunc
	once    sync.Once
	done    chan struct{}
	err     error
}

func (r *Resources) ServeText(ctx context.Context, request TextRequest) (*Consumer, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrConsumer
	}
	r.consumersMu.Lock()
	defer r.consumersMu.Unlock()
	if r.consumersClosing || len(r.consumers) >= maxConsumers || r.Check() != nil {
		return nil, ErrConsumer
	}
	lifetime, cancel := context.WithCancel(ctx)
	server, adapter, err := serveText(lifetime, r, request)
	if err != nil {
		cancel()
		return nil, ErrConsumer
	}
	consumer := &Consumer{owner: r, server: server, adapter: adapter, cancel: cancel, done: make(chan struct{})}
	if r.consumers == nil {
		r.consumers = make(map[*Consumer]struct{})
	}
	r.consumers[consumer] = struct{}{}
	return consumer, nil
}

func (c *Consumer) Bootstrap() apptransport.Bootstrap { return c.server.Bootstrap() }

func (c *Consumer) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		return ErrConsumer
	}
	c.once.Do(func() {
		c.cancel()
		go func() {
			c.server.Close()
			c.err = c.adapter.Close()
			c.owner.consumersMu.Lock()
			if c.err == nil {
				delete(c.owner.consumers, c)
			}
			c.owner.consumersMu.Unlock()
			close(c.done)
		}()
	})
	select {
	case <-c.done:
		if c.err != nil {
			return ErrConsumer
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CloseConsumers joins borrowed users before any parent handle can be released.
func (r *Resources) CloseConsumers(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.consumersMu.Lock()
	r.consumersClosing = true
	consumers := make([]*Consumer, 0, len(r.consumers))
	for consumer := range r.consumers {
		consumers = append(consumers, consumer)
	}
	r.consumersMu.Unlock()
	for _, consumer := range consumers {
		if err := consumer.Close(ctx); err != nil {
			return err
		}
	}
	return nil
}
