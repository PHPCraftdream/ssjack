//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestTextReverseModeGuards(t *testing.T) {
	t.Run("forward grant rejected before use", func(t *testing.T) {
		adapter := &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "hydrate-v1", File: "/approved/config"}}
		got := adapter.ReverseCopy(context.Background(), "ICEiIyQlJicoKSorLC0uLw", "/approved/config")
		if got.Status != DeliveryWithheld || got.Text != nil {
			t.Fatalf("ReverseCopy() = %#v, want withheld with nil text", got)
		}
		if adapter.used {
			t.Fatal("ReverseCopy consumed forward grant before rejecting its mode")
		}
	})

	t.Run("reverse grant rejected before use", func(t *testing.T) {
		adapter := &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "reverse-copy-v1", File: "/approved/config"}}
		got := adapter.Hydrate(context.Background(), "ICEiIyQlJicoKSorLC0uLw", "/approved/config", nil)
		if got.Status != DeliveryWithheld {
			t.Fatalf("Hydrate() = %#v, want withheld", got)
		}
		if adapter.used {
			t.Fatal("Hydrate consumed reverse grant before rejecting its mode")
		}
	})
}

func TestTextReverseNilAndCanceledGuards(t *testing.T) {
	calls := 0
	runner := func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		calls++
		return 0, nil
	}
	adapter := &TextAdapter{
		grant:  declarativeauthority.TextAdapterGrant{Mode: "reverse-copy-v1", File: "/approved/config"},
		runner: runner,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name    string
		adapter *TextAdapter
		ctx     context.Context
	}{
		{name: "nil receiver", ctx: context.Background()},
		{name: "nil context", adapter: adapter},
		{name: "canceled context", adapter: adapter, ctx: ctx},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.adapter.ReverseCopy(tc.ctx, "ICEiIyQlJicoKSorLC0uLw", "/approved/config")
			if got.Status != DeliveryWithheld || got.Text != nil {
				t.Fatalf("ReverseCopy() = %#v, want withheld with nil text", got)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("runner called %d times, want 0", calls)
	}
}
