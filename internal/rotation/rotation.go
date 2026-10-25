package rotation

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type Operations struct {
	Preserve func(context.Context) error
	Confirm  func() error
	Add      func(context.Context, vault.Target, []byte) error
	Verify   func(context.Context, vault.Target) error
	Commit   func(context.Context, vault.Target) error
}

// Apply never commits the replacement before its server authentication succeeds.
func Apply(ctx context.Context, original vault.Target, private, public []byte, ops Operations) error {
	if ops.Preserve == nil || ops.Confirm == nil || ops.Add == nil || ops.Verify == nil || ops.Commit == nil {
		return errors.New("rotation requires recovery, confirmation, installation, verification, and commit steps")
	}
	if err := original.Validate(); err != nil {
		return err
	}
	replacement := original
	replacement.PrivateKey = private
	if err := replacement.Validate(); err != nil {
		return err
	}
	want, err := keyfile.PublicSSH(private)
	if err != nil || !bytes.Equal(want, public) {
		return errors.New("replacement public key does not match its private key")
	}
	oldPublic, err := keyfile.PublicSSH(original.PrivateKey)
	if err != nil || bytes.Equal(oldPublic, public) {
		return errors.New("rotation requires a different key identity")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.Preserve(ctx); err != nil {
		return fmt.Errorf("recovery preparation failed; no remote key was changed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.Confirm(); err != nil {
		return fmt.Errorf("rotation not confirmed; recovery files retained: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.Add(ctx, original, public); err != nil {
		return fmt.Errorf("key addition failed; old key was not removed and recovery files retained: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.Verify(ctx, replacement); err != nil {
		return fmt.Errorf("new login verification failed; vault was not switched and old key retained: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.Commit(ctx, replacement); err != nil {
		return fmt.Errorf("vault switch failed; both server keys and encrypted recovery files retained: %w", err)
	}
	return nil
}
