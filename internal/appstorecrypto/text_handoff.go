package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

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
