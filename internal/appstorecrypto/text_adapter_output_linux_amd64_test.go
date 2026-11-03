//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestTextAdapterOutputUncertain(t *testing.T) {
	for _, mode := range []string{"exit", "error", "partial", "cancel", "late-check"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, checks := 0, 0
			runner := TextAdapterRunner(func(_ context.Context, _, _ string, input io.Reader, stdout, stderr io.Writer) (int, error) {
				calls++
				if stdout != io.Discard || stderr != io.Discard {
					t.Fatal("destination output was not suppressed")
				}
				if mode == "partial" {
					_, _ = input.Read(make([]byte, 1))
				} else {
					_, _ = io.Copy(io.Discard, input)
				}
				if mode == "cancel" {
					cancel()
				}
				if mode == "exit" {
					return 1, nil
				}
				if mode == "error" {
					return -1, errors.New("synthetic destination error")
				}
				return 0, nil
			})
			check := func() error {
				checks++
				if mode == "late-check" && checks > 1 {
					return ErrDelivery
				}
				return nil
			}
			outcome := deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), check)
			if outcome.Status != DeliveryUnknown || calls != 1 {
				t.Fatalf("status=%v calls=%d", outcome.Status, calls)
			}
		})
	}
}

func TestTextAdapterOutputWithheldBeforeEffects(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	runner := TextAdapterRunner(func(_ context.Context, _, _ string, input io.Reader, _ io.Writer, _ io.Writer) (int, error) {
		calls++
		_, _ = io.Copy(io.Discard, input)
		return 0, nil
	})
	outcome := deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), func() error { return nil })
	if outcome.Status != DeliveryReceived || calls != 1 {
		t.Fatalf("live context status=%v calls=%d", outcome.Status, calls)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	calls = 0
	outcome = deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), func() error { return nil })
	if outcome.Status != DeliveryWithheld || calls != 0 {
		t.Fatalf("cancelled context status=%v calls=%d", outcome.Status, calls)
	}

	ctx = context.Background()
	calls = 0
	outcome = deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), func() error { return ErrDelivery })
	if outcome.Status != DeliveryWithheld || calls != 0 {
		t.Fatalf("failed check status=%v calls=%d", outcome.Status, calls)
	}
}
