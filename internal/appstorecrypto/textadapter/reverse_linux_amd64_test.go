//go:build linux && amd64

package textadapter

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestTextReverseModeGuards(t *testing.T) {
	t.Run("forward grant rejected before use", func(t *testing.T) {
		adapter := &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "hydrate-v1", File: "/approved/config"}}
		got := adapter.ReverseCopy(context.Background(), "ICEiIyQlJicoKSorLC0uLw", "/approved/config")
		if got.Status != delivery.DeliveryWithheld || got.Text != nil {
			t.Fatalf("ReverseCopy() = %#v, want withheld with nil text", got)
		}
		if adapter.used {
			t.Fatal("ReverseCopy consumed forward grant before rejecting its mode")
		}
	})

	t.Run("reverse grant rejected before use", func(t *testing.T) {
		adapter := &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "reverse-copy-v1", File: "/approved/config"}}
		got := adapter.Hydrate(context.Background(), "ICEiIyQlJicoKSorLC0uLw", "/approved/config", nil)
		if got.Status != delivery.DeliveryWithheld {
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
			if got.Status != delivery.DeliveryWithheld || got.Text != nil {
				t.Fatalf("ReverseCopy() = %#v, want withheld with nil text", got)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("runner called %d times, want 0", calls)
	}
}

func newCapture() *reverseCapture {
	return &reverseCapture{data: make([]byte, reverseTextLimit)}
}

func TestReverseCaptureBoundsAndSeal(t *testing.T) {
	t.Run("exact limit", func(t *testing.T) {
		c := newCapture()
		data := bytes.Repeat([]byte{'x'}, reverseTextLimit)
		if n, err := c.Write(data); n != len(data) || err != nil {
			t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(data))
		}
		if len(c.data) != reverseTextLimit || c.length != reverseTextLimit {
			t.Fatalf("data length/length = %d/%d, want %d/%d", len(c.data), c.length, reverseTextLimit, reverseTextLimit)
		}
		n, overflow := c.seal()
		if overflow || n != len(data) || !bytes.Equal(c.data[:n], data) {
			t.Fatal("seal did not return the exact captured input")
		}
	})

	t.Run("overflow and sealed writer", func(t *testing.T) {
		c := newCapture()
		prefix := []byte("prefix")
		if n, err := c.Write(prefix); n != len(prefix) || err != nil {
			t.Fatalf("prefix Write() = (%d, %v)", n, err)
		}
		before := append([]byte(nil), c.data[:c.length]...)
		huge := make([]byte, reverseTextLimit+1)
		if n, err := c.Write(huge); n != 0 || err != io.ErrShortWrite {
			t.Fatalf("overflow Write() = (%d, %v), want (0, %v)", n, err, io.ErrShortWrite)
		}
		if !c.overflow {
			t.Fatal("overflow was not latched")
		}
		if !bytes.Equal(c.data[:c.length], before) {
			t.Fatal("overflow changed captured bytes")
		}
		if n, err := c.Write([]byte("fit")); n != 3 || err != nil {
			t.Fatalf("fitting Write() after overflow = (%d, %v), want (3, nil)", n, err)
		}
		n, overflow := c.seal()
		if n != len(prefix)+3 || !overflow {
			t.Fatalf("seal() = (%d, %v), want (%d, true)", n, overflow, len(prefix)+3)
		}
		sealed := append([]byte(nil), c.data[:n]...)
		if !bytes.Equal(sealed, []byte("prefixfit")) {
			t.Fatalf("sealed data = %q, want %q", sealed, "prefixfit")
		}
		if n, err := c.Write([]byte("after seal")); n != 0 || err != io.ErrClosedPipe {
			t.Fatalf("Write after seal = (%d, %v), want (0, %v)", n, err, io.ErrClosedPipe)
		}
		if !bytes.Equal(c.data[:n], sealed) {
			t.Fatal("write after seal changed captured bytes")
		}
	})

	t.Run("chunk boundary", func(t *testing.T) {
		c := newCapture()
		for _, chunk := range [][]byte{[]byte("before syn"), []byte("thetic-secret after")} {
			if n, err := c.Write(chunk); n != len(chunk) || err != nil {
				t.Fatalf("Write(%q) = (%d, %v)", chunk, n, err)
			}
		}
		n, overflow := c.seal()
		if overflow {
			t.Fatal("unexpected overflow")
		}
		if want := []byte("before synthetic-secret after"); !bytes.Equal(c.data[:n], want) {
			t.Fatalf("sealed data = %q, want %q", c.data[:n], want)
		}
	})
}
