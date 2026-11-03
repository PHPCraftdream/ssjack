//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type TextStreamAdapter struct {
	adapter *TextAdapter
}

func NewTextStreamAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextStreamAdapter, error) {
	base, err := newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "hydrate-stream-v2")
	if err != nil {
		return nil, err
	}
	return &TextStreamAdapter{adapter: base}, nil
}

func NewReverseTextStreamAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextStreamAdapter, error) {
	base, err := newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "reverse-copy-stream-v2")
	if err != nil {
		return nil, err
	}
	return &TextStreamAdapter{adapter: base}, nil
}

func loadTextAdapterGrant(mode, id string, uid int, now time.Time) (declarativeauthority.TextAdapterGrant, error) {
	switch mode {
	case "hydrate-v1", "reverse-copy-v1":
		return declarativeauthority.LoadTextAdapter(id, uid, now)
	case "hydrate-stream-v2", "reverse-copy-stream-v2":
		return declarativeauthority.LoadTextStream(id, uid, now)
	default:
		return declarativeauthority.TextAdapterGrant{}, ErrDelivery
	}
}

func validTextAdapterMode(mode string) bool {
	switch mode {
	case "hydrate-v1", "reverse-copy-v1", "hydrate-stream-v2", "reverse-copy-stream-v2":
		return true
	default:
		return false
	}
}

func (c *TextStreamAdapter) Close() error {
	if c == nil || c.adapter == nil {
		return nil
	}
	return c.adapter.Close()
}
