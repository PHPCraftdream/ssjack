package appstorecrypto

import (
	"context"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestTextHandoffRejectsMissingCapabilityOrLease(t *testing.T) {
	ctx := context.Background()
	operationID := "ICEiIyQlJicoKSorLC0uLw"
	lease := &declarativeauthority.TargetLease{}
	if !textHandoffAdmissible(&DeliveryCapability{}, ctx, operationID, lease) {
		t.Fatal("valid structural fixture rejected; this is not evidence of authorization")
	}
	if textHandoffAdmissible(nil, ctx, operationID, lease) {
		t.Fatal("nil capability structurally admissible")
	}
	if textHandoffAdmissible(&DeliveryCapability{}, nil, operationID, lease) {
		t.Fatal("nil context structurally admissible")
	}
	if textHandoffAdmissible(&DeliveryCapability{}, ctx, "invalid", lease) {
		t.Fatal("invalid operation ID structurally admissible")
	}
	if textHandoffAdmissible(&DeliveryCapability{}, ctx, operationID, nil) {
		t.Fatal("nil lease structurally admissible")
	}
	if got := (*DeliveryCapability)(nil).HydrateAndDeliver(ctx, OperationBinding{}, "", nil, operationID, lease); got.Status != DeliveryWithheld {
		t.Fatalf("nil capability status = %v", got.Status)
	}
	if got := (&DeliveryCapability{}).ReverseCopyAndDeliver(ctx, OperationBinding{}, "", nil, operationID, nil); got.Status != DeliveryWithheld {
		t.Fatalf("nil lease status = %v", got.Status)
	}
}
