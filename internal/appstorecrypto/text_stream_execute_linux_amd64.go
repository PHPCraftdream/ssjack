//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"crypto/subtle"
	"io"
	"time"
)

func (c *TextStreamAdapter) Execute(ctx context.Context, ticketID, operationID, file string, input io.ReadCloser) DeliveryOutcome {
	withheld := DeliveryOutcome{DeliveryWithheld}
	if input != nil {
		defer input.Close()
	}
	if c == nil || c.adapter == nil || ctx == nil || input == nil || ctx.Err() != nil || !canonicalID(operationID) || !canonicalID(ticketID) {
		return withheld
	}
	base := c.adapter
	if base.grant.Mode != "hydrate-stream-v2" || file != base.grant.File || !base.operationMu.TryLock() {
		return withheld
	}
	defer base.operationMu.Unlock()
	prepared := c.prepared
	if prepared == nil || prepared.operation != operationID || prepared.file != file || subtle.ConstantTimeCompare([]byte(prepared.id), []byte(ticketID)) != 1 {
		return withheld
	}
	c.prepared = nil
	defer clear(prepared.mac[:])
	base.mu.Lock()
	if base.closed || base.used {
		base.mu.Unlock()
		return withheld
	}
	base.used = true
	base.mu.Unlock()
	if !prepared.expires.After(time.Now()) || base.check(ctx) != nil {
		return withheld
	}
	current, err := textOperationDigest(operationID, file, base.grant)
	if err != nil || current != prepared.base {
		return withheld
	}
	opctx, cancel := context.WithDeadline(ctx, prepared.expires)
	base.mu.Lock()
	if base.closed {
		base.mu.Unlock()
		cancel()
		return withheld
	}
	base.cancel = cancel
	base.mu.Unlock()
	defer func() { base.mu.Lock(); base.cancel = nil; base.mu.Unlock(); cancel() }()
	selection, err := base.captureTextStream(opctx)
	if err != nil {
		return withheld
	}
	defer selection.close()
	if selection.check(opctx) != nil {
		return withheld
	}
	outcome := runTextStream(opctx, base.runner, base.grant.Profile, base.grant.Command, input, selection.mappings, &base.binding, prepared, func() error { return base.check(opctx) })
	if outcome.Status == DeliveryReceived && selection.check(opctx) != nil {
		return DeliveryOutcome{DeliveryUnknown}
	}
	return outcome
}
