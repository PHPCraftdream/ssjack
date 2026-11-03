//go:build linux && amd64

package appstorecrypto_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func reverseExpiryPositiveControl(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant) {
	t.Helper()

	expires, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil {
		t.Fatalf("parse grant expiry %q: %v", grant.ExpiresAt, err)
	}

	var calls atomic.Int32
	var started time.Time
	runner := remote.StreamRunner(func(runctx context.Context, _, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		calls.Add(1)
		deadline, ok := runctx.Deadline()
		if !ok {
			t.Error("runner context has no deadline")
		} else if expires.Before(started.Add(time.Minute)) {
			if !deadline.Equal(expires) {
				t.Errorf("runner deadline=%v expected grant expiry=%v", deadline, expires)
			}
		} else {
			if deadline.Before(started.Add(time.Minute)) || deadline.After(time.Now().Add(time.Minute)) {
				t.Error("runner deadline not bounded to operation window")
			}
		}
		if !expires.After(time.Now()) {
			t.Error("runner dispatched after grant expiry")
		}
		if _, err := io.WriteString(stdout, connectedSecret); err != nil {
			return 1, err
		}
		return 0, nil
	})

	adapter, err := appstorecrypto.NewReverseTextAdapter(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	if err != nil {
		t.Fatalf("construct reverse adapter: %v", err)
	}
	defer adapter.Close()

	started = time.Now()
	outcome := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
	if outcome.Status != appstorecrypto.DeliveryReceived || string(outcome.Text) != grant.References[0] {
		t.Fatalf("ReverseCopy() status=%d hasText=%v, want received text %q", outcome.Status, outcome.Text != nil, grant.References[0])
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("runner calls=%d, want 1", got)
	}
	clear(outcome.Text)

	replay := adapter.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", grant.File)
	if replay.Status != appstorecrypto.DeliveryWithheld || replay.Text != nil {
		t.Fatalf("replay status=%d hasText=%v, want withheld with nil text", replay.Status, replay.Text != nil)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("runner calls after replay=%d, want 1", got)
	}
}
