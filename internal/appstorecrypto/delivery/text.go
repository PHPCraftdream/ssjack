package delivery

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

// TextBinding keys operation digests to one capability.
type TextBinding struct {
	key         [32]byte
	initialized bool
}

// NewTextBinding creates a binding with a fresh random key.
func NewTextBinding() (TextBinding, error) {
	var binding TextBinding
	if _, err := io.ReadFull(rand.Reader, binding.key[:]); err != nil {
		clear(binding.key[:])
		return TextBinding{}, ErrDelivery
	}
	binding.initialized = true
	return binding, nil
}

// Digest returns the keyed operation digest.
func (b *TextBinding) Digest(base string, selected []byte, reverse bool) string {
	mac := hmac.New(sha256.New, b.key[:])
	_, _ = mac.Write([]byte("ssjack/appstorecrypto/private-text-binding/v1\x00"))
	_, _ = mac.Write([]byte(base))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(selected)))
	_, _ = mac.Write(size[:])
	_, _ = mac.Write(selected)
	if reverse {
		_, _ = mac.Write([]byte{1})
	} else {
		_, _ = mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// BindTextOperation creates an opaque, capability-specific operation digest.
func (c *DeliveryCapability) BindTextOperation(baseOperationDigest string, selected []byte, reverse bool) (string, error) {
	if c == nil || !digestPattern.MatchString(baseOperationDigest) || len(selected) > 32<<10 {
		return "", ErrDelivery
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.textBinding.initialized || c.installation == nil || snapshotstore.MasterOf(c.installation) == nil || snapshotstore.MasterOf(c.installation).Closed() {
		return "", ErrDelivery
	}
	return c.textBinding.Digest(baseOperationDigest, selected, reverse), nil
}

func (c *DeliveryCapability) validTextBinding(operation OperationBinding, base string, selected []byte, reverse bool) bool {
	if c == nil || !digestPattern.MatchString(base) || !digestPattern.MatchString(operation.Digest) || len(selected) > 32<<10 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.textBinding.initialized {
		return false
	}
	want, err := hex.DecodeString(c.textBinding.Digest(base, selected, reverse))
	got, gotErr := hex.DecodeString(operation.Digest)
	return err == nil && gotErr == nil && len(want) == sha256.Size && len(got) == sha256.Size && subtle.ConstantTimeCompare(want, got) == 1
}

func (c *DeliveryCapability) PrepareHydration(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte) *DeliveryPlan {
	return c.prepareText(ctx, operation, baseDigest, selected, false)
}

func (c *DeliveryCapability) PrepareReverseCopy(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte) *DeliveryPlan {
	return c.prepareText(ctx, operation, baseDigest, selected, true)
}

func (c *DeliveryCapability) prepareText(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte, reverse bool) *DeliveryPlan {
	if c == nil || len(selected) > 32<<10 {
		return nil
	}
	owned := append([]byte(nil), selected...)
	defer clear(owned)
	if !c.validTextBinding(operation, baseDigest, owned, reverse) {
		return nil
	}
	return c.prepare(ctx, operation, &textSelection{input: owned, reverse: reverse})
}

// Trusted, internal-only handoff: transformed plaintext is delivered to the fixed sink and never returned.
func (c *DeliveryCapability) HydrateAndDeliver(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte, operationID string, lease *declarativeauthority.TargetLease) DeliveryOutcome {
	return c.textAndDeliver(ctx, operation, baseDigest, selected, operationID, lease, false)
}

func (c *DeliveryCapability) ReverseCopyAndDeliver(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte, operationID string, lease *declarativeauthority.TargetLease) DeliveryOutcome {
	return c.textAndDeliver(ctx, operation, baseDigest, selected, operationID, lease, true)
}

func textHandoffAdmissible(c *DeliveryCapability, ctx context.Context, operationID string, lease *declarativeauthority.TargetLease) bool {
	return c != nil && ctx != nil && lease != nil && canonicalID(operationID)
}

func (c *DeliveryCapability) textAndDeliver(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte, operationID string, lease *declarativeauthority.TargetLease, reverse bool) DeliveryOutcome {
	if !textHandoffAdmissible(c, ctx, operationID, lease) {
		return DeliveryOutcome{DeliveryWithheld}
	}
	if err := ctx.Err(); err != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	var plan *DeliveryPlan
	if reverse {
		plan = c.PrepareReverseCopy(ctx, operation, baseDigest, selected)
	} else {
		plan = c.PrepareHydration(ctx, operation, baseDigest, selected)
	}
	if plan == nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	return c.Deliver(ctx, plan, operationID, lease)
}

// Initialized reports whether the binding key is live.
func (b *TextBinding) Initialized() bool { return b.initialized }

// Clear wipes the key and marks the binding unusable.
func (b *TextBinding) Clear() {
	clear(b.key[:])
	b.initialized = false
}

// NewMAC returns an HMAC-SHA256 keyed by the binding key.
func (b *TextBinding) NewMAC() hash.Hash { return hmac.New(sha256.New, b.key[:]) }
