package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

// deliveryConsumerAcceptance verifies successful grant admission followed by each native consumer outcome.
func (f *deliveryFixture) deliveryConsumerAcceptance(t *testing.T, ref string, fields map[string]string, artifacts string) {
	t.Helper()
	marker := "/var/lib/ssjack/synthetic/consumer-receipt"
	goldenBytes, err := os.ReadFile(declarativeauthority.ConsumerPath)
	if err != nil {
		t.Fatal("save golden consumer")
	}
	defer func() {
		if err := os.WriteFile(declarativeauthority.ConsumerPath, goldenBytes, 0755); err != nil {
			t.Error("restore golden consumer")
		}
		_ = os.Chown(declarativeauthority.ConsumerPath, 0, 0)
		_ = os.Chmod(declarativeauthority.ConsumerPath, 0755)
		f.registerDeliveryGrant(t, ref, fields, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339))
	}()
	count := func() int {
		b, err := os.ReadFile(marker)
		if os.IsNotExist(err) {
			return 0
		}
		if err != nil {
			t.Fatal("inspect native marker")
		}
		return len(b)
	}
	for _, tc := range []struct {
		mode, harnessMode string
		delta             int
	}{
		{"lost", "unknown", 48},
		{"partial", "unknown", 0},
		{"wrong-secret", "unknown", 0},
		{"wrong-ready", "withheld", 0},
		{"wait", "cancel", 48},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			consumerPath := filepath.Join(artifacts, "consumer-"+tc.mode)
			b, err := os.ReadFile(consumerPath)
			if err != nil || len(b) < 64 || string(b[:4]) != "\x7fELF" {
				t.Fatal("invalid native consumer fixture")
			}
			if err := os.WriteFile(declarativeauthority.ConsumerPath, b, 0755); err != nil {
				t.Fatal("install native consumer")
			}
			if err := os.Chown(declarativeauthority.ConsumerPath, 0, 0); err != nil {
				t.Fatal("own native consumer")
			}
			if err := os.Chmod(declarativeauthority.ConsumerPath, 0755); err != nil {
				t.Fatal("protect native consumer")
			}
			f.registerDeliveryGrant(t, ref, fields, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339))
			before := count()
			out := f.runDeliveryCLIAs(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}}, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, tc.harnessMode)
			if !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
				t.Fatal("actual unlock did not report delivery acceptance")
			}
			if tc.harnessMode == "cancel" && !strings.Contains(out, "DELIVERY_CANCELLED_OUTCOME_UNKNOWN") {
				t.Fatal("caller cancellation outcome was not reported as unknown")
			}
			after := count()
			if delta := after - before; delta != tc.delta {
				t.Fatalf("native marker delta %d, want %d", delta, tc.delta)
			}
		})
	}
}
