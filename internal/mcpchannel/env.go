package mcpchannel

import (
	"context"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// Environment returns a child-only environment, replacing inherited channel
// variables case-insensitively. The input slice and parent environment are untouched.
func Environment(base []string, encoded string) []string {
	result := make([]string, 0, len(base)+1)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, Env) {
			result = append(result, entry)
		}
	}
	if encoded != "" {
		result = append(result, Env+"="+encoded)
	}
	return result
}

type lifecycleHandler interface{ Close(context.Context) error }

func closeLifecycle(handler Handler) (err error) {
	closer, ok := handler.(lifecycleHandler)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = ErrCleanup
		}
	}()
	if closer.Close(ctx) != nil || ctx.Err() != nil {
		return ErrCleanup
	}
	return nil
}

func closeHandlers(handlers []Handler) error {
	var failed bool
	for _, handler := range handlers {
		if handler != nil && closeLifecycle(handler) != nil {
			failed = true
		}
	}
	if failed {
		return ErrCleanup
	}
	return nil
}

func (s *ChannelSet) closeResult() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleanupFailed {
		return ErrCleanup
	}
	return nil
}

func (s *ChannelSet) Descriptors() []Descriptor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Descriptor(nil), s.descriptors...)
}

func (s *ChannelSet) Done() <-chan struct{} { return s.done }

func (s *ChannelSet) OutputGuard() *outputguard.Snapshot { return s.guard }

func (s *ChannelSet) GuardWith(other *outputguard.Snapshot) (*outputguard.Snapshot, error) {
	combined, err := outputguard.Union(s.guard, other)
	if err != nil {
		return nil, ErrSetup
	}
	return combined, nil
}

func (s *ChannelSet) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrCleanup
	}
	s.cancel()
	select {
	case <-s.done:
		return s.closeResult()
	default:
	}
	select {
	case <-s.done:
		return s.closeResult()
	case <-ctx.Done():
		return ErrCleanup
	}
}

func safeDescribe(h Handler, ctx context.Context) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, ErrSetup
		}
	}()
	return h.Describe(ctx)
}

func safeCall(h Handler, ctx context.Context, tool string, input []byte) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out, err = nil, ErrSetup
		}
	}()
	return h.Call(ctx, tool, input)
}

func fixedFailure() wire.Reply { return wire.Reply{Error: "remote MCP channel request failed"} }
