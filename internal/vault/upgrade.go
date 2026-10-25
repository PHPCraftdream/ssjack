package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

// UpgradePlan holds only authenticated encrypted bytes, never the vault secret.
type UpgradePlan struct {
	path        string
	previous    []byte
	replacement []byte
}

func PrepareUpgrade(ctx context.Context, path string, password []byte) (*UpgradePlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	previous, err := readEncoded(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := keyfile.Open(previous, password)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	v, err := unmarshal(plaintext)
	if err != nil {
		return nil, err
	}
	v.Close()
	version, err := keyfile.Format(previous)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan := &UpgradePlan{path: path, previous: previous}
	if version == 2 {
		return plan, nil
	}
	replacement, err := keyfile.Seal(plaintext, password)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verified, err := keyfile.Open(replacement, password)
	if err != nil {
		return nil, err
	}
	defer clear(verified)
	if !bytes.Equal(verified, plaintext) {
		return nil, errors.New("format upgrade verification changed the vault payload")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plan.replacement = replacement
	return plan, nil
}

func (p *UpgradePlan) Needed() bool { return p.replacement != nil }

func (p *UpgradePlan) Commit(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !p.Needed() {
		current, err := readEncoded(p.path)
		if err != nil {
			return "", err
		}
		if sha256.Sum256(current) != sha256.Sum256(p.previous) {
			return "", errors.New("vault changed after upgrade verification; reload it first")
		}
		return "", nil
	}
	return replaceVerified(ctx, p.path, p.replacement, p.previous, "before-upgrade")
}
