package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

// Negative acceptance cases exercise the actual consumer receipt stream, not a mocked delivery result.
func (f *deliveryFixture) deliveryNegativeAcceptance(t *testing.T, ref string, fields map[string]string, artifacts string) {
	t.Helper()
	marker := "/var/lib/ssjack/synthetic/consumer-receipt"
	path := filepath.Join(declarativeauthority.RegistryPath, "delivery-grants.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read delivery metadata")
	}
	defer func() { _ = os.WriteFile(path, original, 0644) }()
	var disk struct {
		Format string                               `json:"format"`
		Grants []declarativeauthority.DeliveryGrant `json:"grants"`
	}
	if json.Unmarshal(original, &disk) != nil || len(disk.Grants) != 1 {
		t.Fatal("invalid delivery metadata fixture")
	}
	grant := disk.Grants[0]
	answers := []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}}
	count := func() int64 {
		b, e := os.ReadFile(marker)
		if os.IsNotExist(e) {
			return 0
		}
		if e != nil {
			t.Fatal("inspect native marker")
		}
		return int64(len(b))
	}
	attempt := func(name, consumer string, expectedDelta int64) {
		t.Helper()
		before := count()
		cmd := []string{"appstore", "unlock", filepath.Join(artifacts, "harness"), ref, consumer}
		_, e := f.tryDeliveryCLIAs(t, 65534, answers, cmd...)
		want := map[string]string{
			"missing-grant": "no-unique-active-grant",
			"recipient-uid": "no-unique-active-grant", "expired": "no-unique-active-grant", "revoked": "no-unique-active-grant", "reference-substitution": "no-unique-active-grant",
			"desired-schema-id": "no-active-grant", "projection-schema-id": "no-active-grant", "target": "no-active-grant", "purpose": "no-active-grant", "policy": "no-active-grant",
			"store-substitution": "application-store-setup", "directory-device": "application-store-setup", "directory-inode": "application-store-setup",
			"driver-digest": "invalid-slice-request", "consumer-digest": "invalid-slice-request", "desired-schema": "invalid-slice-request", "projection-schema": "invalid-slice-request", "installation-digest": "application-store-setup",
		}
		if code, ok := want[name]; ok {
			f.requireDeliveryRefusal(t, e, code)
		} else {
			var refusal *deliveryCLIRefusal
			if !errors.As(e, &refusal) {
				t.Fatalf("%s was not a classified authority refusal", name)
			}
		}
		after := count()
		if delta := after - before; delta != expectedDelta {
			t.Fatalf("%s receipt delta %d, want %d", name, delta, expectedDelta)
		}
	}
	t.Run("infrastructurecontrols", func(t *testing.T) {
		before := count()
		missingCLI := *f
		missingCLI.cli = "/nonexistent/ssjack-delivery-cli"
		_, err := missingCLI.tryDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, "golden")
		var refusal *deliveryCLIRefusal
		if err == nil || errors.As(err, &refusal) {
			t.Fatal("missing CLI was not reported as infrastructure failure")
		}
		missingHarness := *f
		before = count()
		_, err = missingHarness.tryDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", "/nonexistent/ssjack-delivery-harness", ref, "golden")
		if err == nil || errors.As(err, &refusal) {
			t.Fatal("missing harness was not reported as infrastructure failure")
		}
		if delta := count() - before; delta != 0 {
			t.Fatalf("infrastructure failure changed receipt marker by %d", delta)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*declarativeauthority.DeliveryGrant)
	}{
		{"recipient-uid", func(g *declarativeauthority.DeliveryGrant) { g.RecipientUID++ }},
		{"desired-schema-id", func(g *declarativeauthority.DeliveryGrant) { g.DesiredSchemaID += "x" }},
		{"projection-schema-id", func(g *declarativeauthority.DeliveryGrant) { g.ProjectionSchemaID += "x" }},
		{"expired", func(g *declarativeauthority.DeliveryGrant) {
			g.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		}},
		{"revoked", func(g *declarativeauthority.DeliveryGrant) { g.Revoked = true }},
		{"reference-substitution", func(g *declarativeauthority.DeliveryGrant) {
			var refFields map[string]map[string]any
			if json.Unmarshal([]byte(g.Ref), &refFields) != nil || refFields["$ssjack"] == nil {
				t.Fatal("invalid grant reference fixture")
			}
			refFields["$ssjack"]["version_id"] = "11111111111111111111111111111111"
			refFields["$ssjack"]["snapshot_id"] = "22222222222222222222222222222222"
			encoded, err := json.Marshal(refFields)
			if err != nil {
				t.Fatal("marshal substituted reference")
			}
			b, err := canonicaljson.Canonicalize(encoded)
			if err != nil {
				t.Fatal("canonicalize substituted reference")
			}
			g.Ref = string(b)
		}},
		{"store-substitution", func(g *declarativeauthority.DeliveryGrant) { g.StorePath += "x" }},
		{"driver-digest", func(g *declarativeauthority.DeliveryGrant) {
			g.DriverCodeSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"consumer-digest", func(g *declarativeauthority.DeliveryGrant) {
			g.ConsumerSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"target", func(g *declarativeauthority.DeliveryGrant) { g.Target += "x" }},
		{"purpose", func(g *declarativeauthority.DeliveryGrant) { g.Purpose += "x" }},
		{"policy", func(g *declarativeauthority.DeliveryGrant) { g.PolicyRevision += "x" }},
		{"desired-schema", func(g *declarativeauthority.DeliveryGrant) {
			g.DesiredSchemaSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"projection-schema", func(g *declarativeauthority.DeliveryGrant) {
			g.ProjectionSchemaSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"installation-digest", func(g *declarativeauthority.DeliveryGrant) {
			g.InstallationSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"encoded-hash", func(g *declarativeauthority.DeliveryGrant) {
			g.EncodedHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"directory-device", func(g *declarativeauthority.DeliveryGrant) { g.DirectoryDev++ }},
		{"directory-inode", func(g *declarativeauthority.DeliveryGrant) { g.DirectoryIno++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk.Grants[0] = grant
			tc.mutate(&disk.Grants[0])
			encoded, err := json.Marshal(disk)
			if err != nil {
				t.Fatal("marshal test metadata")
			}
			b, err := canonicaljson.Canonicalize(encoded)
			if err != nil {
				t.Fatal("canonicalize test metadata")
			}
			if os.WriteFile(path, b, 0644) != nil {
				t.Fatal("write test metadata")
			}
			defer func() {
				if os.WriteFile(path, original, 0644) != nil {
					t.Error("restore test metadata")
				}
			}()
			if tc.name == "encoded-hash" {
				before := count()
				out, err := f.tryDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, "withheld")
				if err != nil || !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") || count() != before {
					t.Fatalf("encoded hash did not produce withheld acceptance")
				}
				return
			}
			attempt(tc.name, "golden", 0)
		})
	}
	t.Run("missing-grant", func(t *testing.T) {
		if err := os.Remove(path); err != nil {
			t.Fatal("remove grant metadata")
		}
		defer func() {
			if err := os.WriteFile(path, original, 0644); err != nil {
				t.Error("restore grant metadata")
			}
		}()
		attempt("missing-grant", "golden", 0)
	})
	f.deliveryBoundaryAcceptance(t, ref, fields, artifacts)
}
