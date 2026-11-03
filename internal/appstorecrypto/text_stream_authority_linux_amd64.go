//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type TextStreamAdapter struct {
	adapter  *TextAdapter
	prepared *textStreamTicket
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

func (c *TextStreamAdapter) MatchScope(profile, file string, references []string) error {
	if c == nil || c.adapter == nil || c.adapter.grant.Mode != "hydrate-stream-v2" || c.adapter.grant.Profile != profile || c.adapter.grant.File != file || len(references) != len(c.adapter.grant.References) || len(references) == 0 {
		return ErrDelivery
	}
	selected := make(map[string]bool, len(references))
	for _, ref := range c.adapter.grant.References {
		selected[ref] = true
	}
	for _, ref := range references {
		if !selected[ref] {
			return ErrDelivery
		}
		delete(selected, ref)
	}
	if len(selected) != 0 {
		return ErrDelivery
	}
	return nil
}

func (c *TextStreamAdapter) Close() error {
	if c == nil || c.adapter == nil {
		return nil
	}
	err := c.adapter.Close()
	c.adapter.operationMu.Lock()
	defer c.adapter.operationMu.Unlock()
	if c.prepared != nil {
		clear(c.prepared.mac[:])
		c.prepared = nil
	}
	return err
}
