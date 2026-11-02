//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

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
			if got != (DeliveryOutcome{DeliveryWithheld}) {
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
	first, err := newTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.key[:])
	defer clear(second.key[:])

	base := strings.Repeat("a", 64)
	selected := []byte("selected text")
	original := first.digest(base, selected, false)
	if original == second.digest(base, selected, false) {
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
			if first.digest(tc.base, tc.selected, tc.reverse) == original {
				t.Fatal("changed binding input did not change digest")
			}
		})
	}
}
