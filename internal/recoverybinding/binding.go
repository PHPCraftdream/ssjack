// Package recoverybinding commits recovery bindings without conferring authority.
package recoverybinding

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/recovery"
)

var ErrInvalid = errors.New("invalid committed recovery binding")

const domain = "ssjack-recovery-binding-v1"

// New requires empty transaction fields and returns a structurally valid binding.
func New(b recovery.Binding) (recovery.Binding, error) {
	if b.Transaction != "" || b.Next.Transaction != "" {
		return recovery.Binding{}, ErrInvalid
	}
	for _, value := range []string{b.Invocation, b.Resource, b.Expected.Resource, b.Expected.Transaction, b.Next.Resource} {
		if len(value) > 128 {
			return recovery.Binding{}, ErrInvalid
		}
	}
	payload := append([]byte(domain), 0, byte(b.Stage))
	text := func(value string) {
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(value)))
		payload = append(payload, value...)
	}
	text(b.Invocation)
	text(b.Resource)
	text(b.Expected.Resource)
	payload = binary.BigEndian.AppendUint64(payload, b.Expected.Generation)
	payload = append(payload, b.Expected.Hash[:]...)
	text(b.Expected.Transaction)
	text(b.Next.Resource)
	payload = binary.BigEndian.AppendUint64(payload, b.Next.Generation)
	payload = append(payload, b.Next.Hash[:]...)
	payload = append(payload, b.RequestHash[:]...)
	sum := sha256.Sum256(payload)
	b.Transaction = hex.EncodeToString(sum[:])
	b.Next.Transaction = b.Transaction
	if !recovery.ValidBinding(b) {
		return recovery.Binding{}, ErrInvalid
	}
	return b, nil
}

// Validate rejects legacy IDs and any change to the committed binding.
func Validate(b recovery.Binding) error {
	if !recovery.ValidBinding(b) {
		return ErrInvalid
	}
	input := b
	input.Transaction, input.Next.Transaction = "", ""
	expected, err := New(input)
	if err != nil || expected != b {
		return ErrInvalid
	}
	return nil
}

// Recover checks the commitment before delegating to the existing state machine.
func Recover(ctx context.Context, machine recovery.Machine, b recovery.Binding) error {
	if ctx == nil || ctx.Err() != nil || Validate(b) != nil {
		return recovery.ErrUnavailable
	}
	return machine.Recover(ctx, b)
}
