//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestStreamGrantCannotInvokeV1Delivery(t *testing.T) {
	calls := 0
	runner := TextAdapterRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		calls++
		return 0, nil
	})
	for _, mode := range []string{"hydrate-stream-v2", "reverse-copy-stream-v2"} {
		base := &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: mode, File: "/approved/config"}, runner: runner}
		if result := base.Hydrate(context.Background(), "AAECAwQFBgcICQoLDA0ODw", "/approved/config", []byte("template")); result != (DeliveryOutcome{DeliveryWithheld}) {
			t.Fatal("stream grant crossed into v1 forward delivery")
		}
		if base.used {
			t.Fatal("v1 forward consumed a v2 operation before rejecting its profile")
		}
		if result := base.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", "/approved/config"); result.Status != DeliveryWithheld || result.Text != nil {
			t.Fatal("stream grant crossed into v1 reverse delivery")
		}
		if base.used {
			t.Fatal("v1 reverse consumed a v2 operation before rejecting its profile")
		}
	}
	if calls != 0 {
		t.Fatal("profile mismatch invoked SSH")
	}
}

func TestStreamScopeDirectionsRemainSeparate(t *testing.T) {
	for _, mode := range []string{"hydrate-stream-v2", "reverse-copy-stream-v2"} {
		c := &TextStreamAdapter{adapter: &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: mode, Profile: "selected", File: "/approved/config", References: []string{"selected-ref"}}}}
		forward := c.MatchScope("selected", "/approved/config", []string{"selected-ref"})
		reverse := c.MatchReverseScope("selected", "/approved/config", []string{"selected-ref"})
		if (forward == nil) != (mode == "hydrate-stream-v2") || (reverse == nil) != (mode == "reverse-copy-stream-v2") {
			t.Fatal("stream scope crossed its granted direction")
		}
		if c.MatchReverseScope("selected", "/approved/config", []string{"selected-ref", "selected-ref"}) == nil || c.MatchReverseScope("selected", "/other/config", []string{"selected-ref"}) == nil {
			t.Fatal("reverse scope accepted another file or duplicate references")
		}
		if c.adapter.used {
			t.Fatal("metadata matching consumed execution authority")
		}
	}
}

func TestStreamConstructionRequiresAuthenticatedInstallationAndRunner(t *testing.T) {
	if adapter, err := NewTextStreamAdapter(context.Background(), nil, "grant", "profile", "digest", nil); err == nil || adapter != nil {
		t.Fatal("stream construction accepted missing authenticated state")
	}
	if adapter, err := NewReverseTextStreamAdapter(context.Background(), nil, "grant", "profile", "digest", nil); err == nil || adapter != nil {
		t.Fatal("reverse stream construction accepted missing authenticated state")
	}
	if validTextAdapterMode("unknown") {
		t.Fatal("unknown adapter authority mode accepted")
	}
	if _, err := loadTextAdapterGrant("unknown", "caller-approval", 1000, time.Now()); err == nil {
		t.Fatal("unknown profile acquired authority")
	}
	if err := (*TextStreamAdapter)(nil).Close(); err != nil {
		t.Fatal(err)
	}
}
