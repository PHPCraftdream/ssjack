package mcpgrant

import (
	"context"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcphttp"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

// Launch is the bounded one-shot result of a successful issue: per-account
// capability handles plus the union literal capability of the whole launch.
type Launch struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	stop       func() bool
	propagated <-chan struct{}
	upstreams  []*mcphttp.Upstream
	guard      *outputguard.Snapshot
	closed     bool
}

// Issue admits one explicit confirmed owner choice against the captured state
// and mints at most one bounded launch per capture. Admission, every record
// boundary and the return boundary recheck cancellation and the finite
// lifetime; a cancelled or expired mint never returns a usable launch.
// Preflight mismatches leave the capture unconsumed; any failure after
// admission consumes it, because uncertain partial effects are never replayed.
func (c *Capture) Issue(ctx context.Context, profile string, revision uint64, bindings []mcpdirectory.Binding) (*Launch, error) {
	if c == nil {
		return nil, ErrGrant
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.issued || !c.admissible(ctx) {
		return nil, ErrGrant
	}
	// Preflight admission: no capture consumption on mismatch.
	if profile != c.profile || revision != c.revision {
		return nil, ErrGrant
	}
	if len(bindings) == 0 || len(bindings) > mcpdirectory.MaxSelections {
		return nil, ErrGrant
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, duplicate := seen[binding.AccountID]; duplicate {
			return nil, ErrGrant
		}
		seen[binding.AccountID] = struct{}{}
		record, known := c.records[binding.AccountID]
		if !known {
			return nil, ErrGrant
		}
		if record.ServerID != binding.ServerID ||
			record.Account.ServerID != binding.ServerID ||
			record.Account.Revision != binding.AccountRevision ||
			record.Server.Revision != binding.ServerRevision ||
			!record.Server.Enabled || !record.Account.Enabled {
			return nil, ErrGrant
		}
	}
	// Consume before minting: failures from here on are unrecoverable.
	c.issued = true
	launchCtx, cancel := context.WithCancel(ctx)
	// Both cancellation scopes govern the exchange lifetime: the capture's
	// construction parent and the caller's issuance context.
	// The capture-parent callback must complete propagation, not merely start
	// it: this channel closes after cancel returns, so waiting on it also
	// waits for the upstream flow contexts to be revoked.
	propagated := make(chan struct{})
	stop := context.AfterFunc(c.ctx, func() {
		cancel()
		close(propagated)
	})
	launch := &Launch{cancel: cancel, stop: stop, propagated: propagated}
	for _, binding := range bindings {
		if !c.admissible(ctx) {
			return nil, c.abandon(launch)
		}
		record := c.records[binding.AccountID]
		upstream, err := mcphttp.NewUpstream(launchCtx, record.Server.URL, record.Account)
		if err != nil {
			return nil, c.abandon(launch)
		}
		launch.upstreams = append(launch.upstreams, upstream)
		snapshot, err := upstream.OutputGuard()
		if err != nil {
			return nil, c.abandon(launch)
		}
		if launch.guard == nil {
			launch.guard = snapshot
			continue
		}
		merged, err := outputguard.Union(launch.guard, snapshot)
		if err != nil {
			return nil, c.abandon(launch)
		}
		launch.guard = merged
	}
	if !c.admissible(ctx) {
		return nil, c.abandon(launch)
	}
	return launch, nil
}

// admissible reports whether the capture context, the issue context and the
// finite admission lifetime all still allow issuance at this exact boundary.
func (c *Capture) admissible(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil || c.ctx == nil || c.ctx.Err() != nil {
		return false
	}
	// The deadline instant itself refuses: issuance requires strictly
	// unexpired admission.
	return c.now().Before(c.deadline)
}

// abandon cancels a failed or invalidated mint, joins what it can and keeps
// any incomplete cleanup reachable through the capture instead of silently
// dropping retained upstreams.
func (c *Capture) abandon(launch *Launch) error {
	launch.abort()
	if len(launch.upstreams) != 0 {
		c.doomed = append(c.doomed, launch.upstreams...)
		launch.upstreams = nil
	}
	return ErrGrant
}

// abort is failed-mint cleanup: it cancels owned contexts, releases the
// parent-cancellation callback and joins the partially minted upstreams.
// Upstreams whose close stays incomplete are retained on the launch so the
// capture can keep retrying their shutdown; individual failures cannot be
// reported here. Mint-time upstreams have no taken transport and no I/O, so
// Close normally returns promptly.
func (l *Launch) abort() {
	if l == nil {
		return
	}
	if l.cancel != nil {
		l.cancel()
	}
	// Repeat-safe stop: abandon paths release the callback exactly here.
	if l.stop != nil {
		l.stop()
	}
	cleanup, stop := context.WithTimeout(context.Background(), abortCloseBudget)
	defer stop()
	kept := make([]*mcphttp.Upstream, 0, len(l.upstreams))
	for _, upstream := range l.upstreams {
		if upstream.Close(cleanup) != nil {
			kept = append(kept, upstream)
		}
	}
	l.upstreams = kept
	l.guard = nil
}

// Upstreams returns the one-shot per-account capability handles in binding
// order. Each handle refuses reuse; the whole launch refuses after Close.
func (l *Launch) Upstreams() []*mcphttp.Upstream {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	return append([]*mcphttp.Upstream{}, l.upstreams...)
}

// Guard returns the union literal capability covering every transmitted
// authentication form of this launch, including Basic's encoded component.
func (l *Launch) Guard() (*outputguard.Snapshot, error) {
	if l == nil {
		return nil, ErrGrant
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.guard == nil {
		return nil, ErrGrant
	}
	return l.guard, nil
}

// Close cancels owned exchange contexts and joins upstream shutdown before
// dropping the guard reference. Failed cleanup retains state and can be waited
// again with a fresh context; it never reports success.
func (l *Launch) Close(ctx context.Context) error {
	if l == nil || ctx == nil {
		return ErrGrant
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cancel == nil {
		return ErrGrant
	}
	if l.closed {
		return nil
	}
	l.cancel()
	// The AfterFunc stop is repeat-safe: later Close attempts call it again.
	if l.stop != nil {
		l.stop()
	}
	failed := false
	for _, upstream := range l.upstreams {
		if upstream.Close(ctx) != nil {
			failed = true
		}
	}
	if failed {
		// Retain state so Close can be retried; the retained handles are
		// already cancelled through the launch context and the parent
		// callback is released.
		return ErrGrant
	}
	l.closed = true
	l.upstreams = nil
	l.guard = nil
	return nil
}
