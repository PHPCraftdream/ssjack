//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

// ReverseCopyStream writes tentative reference-only bytes. The caller must not
// publish them unless the returned outcome is received. Closing output must
// unblock Write; ownership transfers to this call, including refusal paths.
func (c *TextStreamAdapter) ReverseCopyStream(ctx context.Context, operationID, file string, output io.WriteCloser) DeliveryOutcome {
	withheld := DeliveryOutcome{DeliveryWithheld}
	if output != nil {
		defer output.Close()
	}
	if c == nil || c.adapter == nil || ctx == nil || output == nil || ctx.Err() != nil || !canonicalID(operationID) {
		return withheld
	}
	base := c.adapter
	if base.grant.Mode != "reverse-copy-stream-v2" || file != base.grant.File || !base.operationMu.TryLock() {
		return withheld
	}
	defer base.operationMu.Unlock()
	base.mu.Lock()
	if base.closed || base.used {
		base.mu.Unlock()
		return withheld
	}
	base.used = true
	base.mu.Unlock()
	expires, err := time.Parse(time.RFC3339, base.grant.ExpiresAt)
	if err != nil {
		return withheld
	}
	deadline := time.Now().Add(time.Minute)
	if expires.Before(deadline) {
		deadline = expires
	}
	opctx, cancel := context.WithDeadline(ctx, deadline)
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
	outcome := runReverseTextStream(opctx, base.runner, base.grant.Profile, base.grant.Command, output, selection.mappings, func() error { return base.check(opctx) })
	if outcome.Status == DeliveryReceived && selection.check(opctx) != nil {
		return DeliveryOutcome{DeliveryUnknown}
	}
	return outcome
}

func runReverseTextStream(ctx context.Context, runner TextAdapterRunner, profile, command string, output io.WriteCloser, mappings []appstoretext.Mapping, check func() error) DeliveryOutcome {
	withheld := DeliveryOutcome{DeliveryWithheld}
	if ctx == nil || runner == nil || output == nil || check == nil || ctx.Err() != nil || check() != nil {
		return withheld
	}
	probe, err := appstoretext.Replace(nil, mappings, true)
	clear(probe)
	if err != nil {
		return withheld
	}
	refs := make([]appstoreref.Ref, len(mappings))
	for i, mapping := range mappings {
		refs[i] = mapping.Reference
	}
	if _, err := appstoretextstream.ValidateTemplate(ctx, bytes.NewReader(nil), refs, appstoretextstream.MaxBytes); err != nil {
		return withheld
	}
	pipeline, cancel := context.WithCancel(ctx)
	defer cancel()
	rawR, rawW := io.Pipe()
	textR, textW := io.Pipe()
	defer rawR.Close()
	defer rawW.Close()
	defer textR.Close()
	defer textW.Close()
	stop := func() {
		cancel()
		rawR.CloseWithError(ErrDelivery)
		rawW.CloseWithError(ErrDelivery)
		textR.CloseWithError(ErrDelivery)
		textW.CloseWithError(ErrDelivery)
		output.Close()
	}
	stopWatch, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-pipeline.Done():
			stop()
		case <-stopWatch:
		}
	}()
	transformed, validated := make(chan error, 1), make(chan error, 1)
	go func() {
		input := &streamCountReader{ctx: pipeline, input: rawR, check: check}
		err := appstoretext.ReplaceStream(pipeline, input, textW, mappings, true, appstoretext.StreamLimits{Input: appstoretextstream.MaxBytes, Output: appstoretextstream.MaxBytes})
		if err != nil {
			stop()
		} else {
			textW.Close()
		}
		transformed <- err
	}()
	go func() {
		_, err := appstoretextstream.ValidateTemplate(pipeline, io.TeeReader(textR, output), refs, appstoretextstream.MaxBytes)
		if err != nil {
			stop()
		}
		validated <- err
	}()
	exit, runErr := runner(pipeline, profile, command, bytes.NewReader(nil), rawW, io.Discard)
	if runErr != nil || exit != 0 || ctx.Err() != nil {
		stop()
	} else {
		rawW.Close()
	}
	transformErr, validationErr := <-transformed, <-validated
	close(stopWatch)
	<-watchDone
	if runErr != nil || exit != 0 || transformErr != nil || validationErr != nil || ctx.Err() != nil || check() != nil {
		return DeliveryOutcome{DeliveryUnknown}
	}
	return DeliveryOutcome{DeliveryReceived}
}
