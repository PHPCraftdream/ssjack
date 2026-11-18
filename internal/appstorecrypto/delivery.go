package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

type (
	DeliveryCapability = delivery.DeliveryCapability
	DeliveryPlan       = delivery.DeliveryPlan
	DeliveryOutcome    = delivery.DeliveryOutcome
	DeliveryStatus     = delivery.DeliveryStatus
	OperationBinding   = delivery.OperationBinding
)

const (
	DeliveryWithheld = delivery.DeliveryWithheld
	DeliveryReceived = delivery.DeliveryReceived
	DeliveryUnknown  = delivery.DeliveryUnknown
)

var ErrDelivery = delivery.ErrDelivery

func NewDeliveryCapability(ctx context.Context, installation *Installation, ref appstoreref.Ref) (*DeliveryCapability, error) {
	return delivery.NewDeliveryCapability(ctx, installation, ref)
}
