//go:build linux && amd64

package textadapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestTextAdapterEngineRunnerBoundary(t *testing.T) {
	reference, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := appstoreplaceholder.Encode(reference)
	if err != nil {
		t.Fatal(err)
	}
	selection := append([]byte("ordinary prefix "), placeholder...)
	selection = append(selection, []byte(" ordinary suffix")...)
	secret := []byte("synthetic-secret")
	transformed, err := appstoretext.Replace(selection, []appstoretext.Mapping{{Reference: reference, Value: secret}}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(transformed)
	var received []byte
	runner := TextAdapterRunner(func(_ context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
		if profile != "approved" || command != "approved-command" || stdout != io.Discard || stderr != io.Discard {
			t.Error("unexpected destination binding")
		}
		var readErr error
		received, readErr = io.ReadAll(input)
		_, _ = stdout.Write(secret)
		_, _ = stderr.Write(secret)
		return 0, readErr
	})
	outcome := deliverTextAdapterOutput(context.Background(), runner, "approved", "approved-command", transformed, func() error { return nil })
	if outcome.Status != delivery.DeliveryReceived {
		t.Fatalf("delivery outcome=%v", outcome.Status)
	}
	defer clear(received)
	if !bytes.Equal(received, []byte("ordinary prefix synthetic-secret ordinary suffix")) {
		t.Fatal("literal substitution or ordinary text preservation failed")
	}
}

func TestTextAdapterHydrateRefusals(t *testing.T) {
	var runnerCalls int
	runner := TextAdapterRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		runnerCalls++
		return 0, nil
	})
	grant := declarativeauthority.TextAdapterGrant{
		File:      "/approved/file",
		Mode:      "hydrate-v1",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	adapter := &TextAdapter{
		grant:  grant,
		runner: runner,
		closed: true,
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		name        string
		adapter     *TextAdapter
		ctx         context.Context
		operationID string
		file        string
		selected    []byte
	}{
		{
			name:        "nil receiver",
			ctx:         context.Background(),
			operationID: "AAECAwQFBgcICQoLDA0ODw",
			file:        grant.File,
		},
		{
			name:        "closed adapter",
			adapter:     adapter,
			ctx:         context.Background(),
			operationID: "AAECAwQFBgcICQoLDA0ODw",
			file:        grant.File,
		},
		{
			name:        "cancelled context",
			adapter:     &TextAdapter{grant: grant, runner: runner},
			ctx:         cancelled,
			operationID: "AAECAwQFBgcICQoLDA0ODw",
			file:        grant.File,
		},
		{
			name:        "invalid operation",
			adapter:     &TextAdapter{grant: grant, runner: runner},
			ctx:         context.Background(),
			operationID: "!",
			file:        grant.File,
		},
		{
			name:        "wrong file",
			adapter:     &TextAdapter{grant: grant, runner: runner},
			ctx:         context.Background(),
			operationID: "AAECAwQFBgcICQoLDA0ODw",
			file:        "/other/file",
		},
		{
			name:        "oversize selection",
			adapter:     &TextAdapter{grant: grant, runner: runner},
			ctx:         context.Background(),
			operationID: "AAECAwQFBgcICQoLDA0ODw",
			file:        grant.File,
			selected:    make([]byte, (32<<10)+1),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.adapter.Hydrate(tc.ctx, tc.operationID, tc.file, tc.selected)
			if got != (delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}) {
				t.Fatalf("Hydrate() = %#v, want withheld", got)
			}
		})
	}
	if runnerCalls != 0 {
		t.Fatalf("runner called %d times", runnerCalls)
	}
}

func TestTextOperationDigestBindsMetadata(t *testing.T) {
	grant := declarativeauthority.TextAdapterGrant{
		ID:      "grant",
		File:    "/approved/file",
		Profile: "profile",
	}
	base, err := textOperationDigest("operation-1", grant.File, grant)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		operation string
		file      string
		grant     declarativeauthority.TextAdapterGrant
	}{
		{
			name:      "operation",
			operation: "operation-2",
			file:      grant.File,
			grant:     grant,
		},
		{
			name:      "file",
			operation: "operation-1",
			file:      "/other/file",
			grant:     grant,
		},
		{
			name:      "grant",
			operation: "operation-1",
			file:      grant.File,
			grant: declarativeauthority.TextAdapterGrant{
				ID:      "different",
				File:    grant.File,
				Profile: grant.Profile,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := textOperationDigest(tc.operation, tc.file, tc.grant)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatal("metadata change did not change digest")
			}
		})
	}
}

func TestPrivateTextBindingBindsInputs(t *testing.T) {
	first, err := delivery.NewTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	second, err := delivery.NewTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Clear()
	defer second.Clear()

	base := strings.Repeat("a", 64)
	selected := []byte("selected text")
	original := first.Digest(base, selected, false)
	if original == second.Digest(base, selected, false) {
		t.Fatal("independent binding keys produced same digest")
	}
	for _, tc := range []struct {
		name     string
		base     string
		selected []byte
		reverse  bool
	}{
		{
			name:     "operation digest",
			base:     strings.Repeat("b", 64),
			selected: selected,
		},
		{
			name:     "selection",
			base:     base,
			selected: []byte("changed text"),
		},
		{
			name:     "direction",
			base:     base,
			selected: selected,
			reverse:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if first.Digest(tc.base, tc.selected, tc.reverse) == original {
				t.Fatal("changed binding input did not change digest")
			}
		})
	}
}

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
					return delivery.ErrDelivery
				}
				return nil
			}
			outcome := deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), check)
			if outcome.Status != delivery.DeliveryUnknown || calls != 1 {
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
	if outcome.Status != delivery.DeliveryReceived || calls != 1 {
		t.Fatalf("live context status=%v calls=%d", outcome.Status, calls)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	calls = 0
	outcome = deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), func() error { return nil })
	if outcome.Status != delivery.DeliveryWithheld || calls != 0 {
		t.Fatalf("cancelled context status=%v calls=%d", outcome.Status, calls)
	}

	ctx = context.Background()
	calls = 0
	outcome = deliverTextAdapterOutput(ctx, runner, "approved", "approved-command", []byte("synthetic text"), func() error { return delivery.ErrDelivery })
	if outcome.Status != delivery.DeliveryWithheld || calls != 0 {
		t.Fatalf("failed check status=%v calls=%d", outcome.Status, calls)
	}
}
