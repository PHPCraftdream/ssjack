// Package mcpbridge supervises one confirmed remote MCP launch inside the
// startup process, exposing only three bounded keeper operations.
package mcpbridge

import (
	"context"
	"net/http"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpexchange"
	"github.com/PHPCraftdream/ssjack/internal/mcphttp"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpstreamHandle interface{ TakeTransport() (mcp.Transport, error) }
type LaunchUpstream struct{ Upstream *mcphttp.Upstream }

func (handle *LaunchUpstream) TakeTransport() (mcp.Transport, error) {
	if handle == nil || handle.Upstream == nil {
		return nil, errUnavailable
	}
	transport, err := handle.Upstream.Take()
	if err != nil || transport == nil || transport.MaxRetries != -1 || transport.HTTPClient == http.DefaultClient || transport.HTTPClient == nil {
		return nil, errUnavailable
	}
	owned, err := mcpexchange.New(transport.Endpoint, transport.HTTPClient)
	if err != nil {
		return nil, errUnavailable
	}
	return owned, nil
}

type ordinalInput struct {
	Ordinal int `json:"ordinal"`
}

type Runtime struct {
	ctx             context.Context
	cancel          context.CancelFunc
	guard           *outputguard.Snapshot
	closeLaunch     func(context.Context) error
	mu              sync.Mutex
	slots           []*slot
	closing         bool
	active          int
	activeDone      chan struct{}
	messages        int
	cleanupStarted  bool
	cleanupTerminal bool
	cleanupFinished bool
	cleanupErr      error
	cleanupAttempt  chan struct{}
	retryCleanup    chan chan struct{}
}

// Open validates and owns immutable copies of the launch-minted capability set.
func Open(parent context.Context, handles []UpstreamHandle, guard *outputguard.Snapshot, closeLaunch func(context.Context) error, bindings []mcpdirectory.Binding) (*Runtime, error) {
	if parent == nil || parent.Err() != nil || guard == nil || closeLaunch == nil || len(handles) != len(bindings) || len(bindings) == 0 || len(bindings) > mcpdirectory.MaxSelections {
		return nil, ErrBridge
	}
	rctx, cancel := context.WithTimeout(parent, RuntimeLease)
	r := &Runtime{ctx: rctx, cancel: cancel, guard: guard, closeLaunch: closeLaunch, activeDone: closedSignal(), retryCleanup: make(chan chan struct{}, 1)}
	namespaces := make(map[string]struct{}, len(bindings))
	accounts := make(map[string]struct{}, len(bindings))
	for i, handle := range handles {
		b := bindings[i]
		_, duplicateNamespace := namespaces[bindingNamespace(b)]
		_, duplicateAccount := accounts[b.AccountID]
		if handle == nil || b.ServerID == "" || b.AccountID == "" || len(b.ServerID) > 256 || len(b.AccountID) > 256 || b.ServerRevision == 0 || b.AccountRevision == 0 || duplicateNamespace || duplicateAccount {
			cancel()
			return nil, ErrBridge
		}
		namespaces[bindingNamespace(b)] = struct{}{}
		accounts[b.AccountID] = struct{}{}
		slotCtx, slotCancel := context.WithCancel(rctx)
		r.slots = append(r.slots, &slot{binding: b, handle: handle, ctx: slotCtx, cancel: slotCancel, ioGate: make(chan struct{}, 1), initDone: make(chan struct{}), closeDone: make(chan struct{}), closeStarted: make(chan struct{})})
	}
	context.AfterFunc(rctx, func() { r.startShutdown() })
	return r, nil
}

func closedSignal() chan struct{} { done := make(chan struct{}); close(done); return done }

func (r *Runtime) admit() bool {
	r.mu.Lock()
	if r.closing || r.ctx.Err() != nil {
		needShutdown := r.ctx.Err() != nil && !r.closing
		r.mu.Unlock()
		if needShutdown {
			r.startShutdown()
		}
		return false
	}
	if r.messages >= MaxRuntimeMessages {
		r.mu.Unlock()
		r.startShutdown()
		return false
	}
	if r.active >= MaxActiveOperations {
		r.mu.Unlock()
		return false
	}
	if r.active == 0 {
		r.activeDone = make(chan struct{})
	}
	r.messages++
	r.active++
	r.mu.Unlock()
	return true
}
func (r *Runtime) release() {
	r.mu.Lock()
	r.active--
	if r.active == 0 {
		close(r.activeDone)
	}
	r.mu.Unlock()
}

// Handle admits at most four active calls and a fixed lifetime message count.
func (r *Runtime) Handle(ctx context.Context, request wire.Request) (wire.Reply, bool) {
	switch request.Operation {
	case OpBindings, OpDescribe, OpCall:
	default:
		return wire.Reply{}, false
	}
	if len(request.Data) > wire.MaxFrame {
		return wire.Reply{Error: errArguments.Error()}, true
	}
	if ctx == nil {
		return wire.Reply{Error: errShutdown.Error()}, true
	}
	if !r.admit() {
		return wire.Reply{Error: errShutdown.Error()}, true
	}
	defer r.release()
	if r.ctx.Err() != nil {
		return wire.Reply{Error: errShutdown.Error()}, true
	}
	switch request.Operation {
	case OpBindings:
		var empty struct{}
		if wire.DecodeStrict(request.Data, &empty) != nil {
			return wire.Reply{Error: errArguments.Error()}, true
		}
		ordinals := make([]int, len(r.slots))
		for i := range r.slots {
			ordinals[i] = i
		}
		return broker.Result(BindingsOutput{Ordinals: ordinals}, nil), true
	case OpDescribe:
		var in ordinalInput
		if wire.DecodeStrict(request.Data, &in, "ordinal") != nil {
			return wire.Reply{Error: errArguments.Error()}, true
		}
		out, err := r.describe(ctx, in.Ordinal)
		if err != nil {
			return wire.Reply{Error: err.Error()}, true
		}
		encoded, err := marshalBounded(out, MaxInventoryBytes)
		if err != nil {
			return wire.Reply{Error: errInventory.Error()}, true
		}
		return broker.Result(InventoryEnvelope{Inventory: string(encoded)}, nil), true
	case OpCall:
		var in CallInput
		if decodeCallWire(request.Data, &in) != nil {
			return wire.Reply{Error: errArguments.Error()}, true
		}
		out, err := r.call(ctx, in)
		if err != nil {
			return wire.Reply{Error: err.Error()}, true
		}
		return broker.Result(out, nil), true
	}
	return wire.Reply{}, false
}

// BindLifetime explicitly binds keeper lifetime; per-message Handle contexts
// remain operation-scoped and never shut down the runtime.
func (r *Runtime) BindLifetime(ctx context.Context) {
	if ctx != nil {
		context.AfterFunc(ctx, func() { r.startShutdown() })
	}
}

// ConfigureOutput atomically unions known output with mandatory launch secrets.
// It is only available before the first keeper message.
func (r *Runtime) ConfigureOutput(known, mandatory *outputguard.Snapshot) error {
	union, err := outputguard.Union(known, mandatory)
	if err != nil {
		return ErrBridge
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.messages != 0 {
		return ErrBridge
	}
	r.guard = union
	return nil
}

func decodeCallWire(data string, out *CallInput) error {
	fields := map[string]any{}
	if err := wire.Decode(data, &fields); err != nil || len(fields) < 2 || len(fields) > 3 {
		return errArguments
	}
	for key := range fields {
		if key != "ordinal" && key != "tool" && key != "arguments" {
			return errArguments
		}
	}
	if _, ok := fields["ordinal"]; !ok {
		return errArguments
	}
	if _, ok := fields["tool"]; !ok {
		return errArguments
	}
	if err := wire.Decode(data, out); err != nil {
		return errArguments
	}
	return nil
}
