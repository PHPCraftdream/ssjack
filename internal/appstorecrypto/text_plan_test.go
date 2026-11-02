package appstorecrypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestDeniedTextDeliveryConsumesCapturedSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		used map[string]bool
	}{
		{name: "reused operation", used: map[string]bool{"ICEiIyQlJicoKSorLC0uLw": true}},
		{name: "used operation cap", used: makeUsedOperationIDs()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := []byte("captured plaintext")
			initialUsedCount := len(tc.used)
			state := &deliveryPlanState{
				binding: OperationBinding{SessionID: "EBESExQVFhcYGRobHB0eHw", Deadline: time.Now().Add(time.Minute)},
				text:    &textSelection{input: secret},
			}
			capability := &DeliveryCapability{
				boundSession:      state.binding.SessionID,
				used:              tc.used,
				pendingSelections: map[*deliveryPlanState]struct{}{state: {}},
			}
			state.owner = capability
			lease := &declarativeauthority.TargetLease{}
			result := capability.Deliver(context.Background(), &DeliveryPlan{state: state}, "ICEiIyQlJicoKSorLC0uLw", lease)
			if result.Status != DeliveryWithheld || !state.used || !bytes.Equal(secret, make([]byte, len(secret))) || state.text == nil {
				t.Fatal("denied delivery did not consume and clear captured selection")
			}
			if len(capability.used) != initialUsedCount {
				t.Fatal("denied delivery recorded a new operation")
			}
			if _, pending := capability.pendingSelections[state]; pending {
				t.Fatal("denied selection remains pending")
			}
		})
	}
}

func TestExpiredTextDeliveryConsumesCapturedSelection(t *testing.T) {
	secret := []byte("captured plaintext")
	state := &deliveryPlanState{
		binding: OperationBinding{SessionID: "EBESExQlFhcYGRobHB0eHw", Deadline: time.Now().Add(-time.Second)},
		text:    &textSelection{input: secret},
	}
	capability := &DeliveryCapability{used: map[string]bool{}, pendingSelections: map[*deliveryPlanState]struct{}{state: {}}}
	state.owner = capability
	result := capability.Deliver(context.Background(), &DeliveryPlan{state: state}, "ICEiIyQlJicoKSorLC0uLw", &declarativeauthority.TargetLease{})
	if result.Status != DeliveryWithheld || !state.used || !bytes.Equal(secret, make([]byte, len(secret))) || state.text == nil {
		t.Fatal("expired delivery did not consume and clear captured selection")
	}
	if len(capability.used) != 0 {
		t.Fatal("expired delivery recorded an operation")
	}
	if _, pending := capability.pendingSelections[state]; pending {
		t.Fatal("expired selection remains pending")
	}
}

func TestUninitializedCapabilityCannotPrepareText(t *testing.T) {
	input := []byte("captured plaintext")
	base := strings.Repeat("1", 64)
	if plan := (&DeliveryCapability{}).PrepareHydration(context.Background(), OperationBinding{Digest: strings.Repeat("0", 64)}, base, input); plan != nil {
		t.Fatal("uninitialized capability produced a text plan")
	}
}

func makeUsedOperationIDs() map[string]bool {
	used := make(map[string]bool, 128)
	for i := 0; i < 128; i++ {
		used[base64.RawURLEncoding.EncodeToString([]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})] = true
	}
	return used
}
