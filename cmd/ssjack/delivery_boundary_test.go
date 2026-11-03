package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func (f *deliveryFixture) deliveryBoundaryAcceptance(t *testing.T, ref string, fields map[string]string, artifacts string) {
	t.Helper()
	marker := "/var/lib/ssjack/synthetic/consumer-receipt"
	markerBytes := func() []byte {
		b, err := os.ReadFile(marker)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal("inspect native marker")
		}
		return b
	}
	unlock := func() (string, error) {
		return f.tryDeliveryCLIAs(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}}, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, "withheld")
	}
	unchanged := func(before []byte, name string) {
		after := markerBytes()
		if string(after) != string(before) {
			t.Fatalf("%s changed native marker", name)
		}
	}
	grantExpiry := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)

	t.Run("actual-revocation", func(t *testing.T) {
		before := markerBytes()
		f.runDeliveryCLIAs(t, 0, []deliveryAnswer{{"Exact canonical confidential-delivery reference to revoke: ", []byte(ref)}, {"Repeat exact canonical reference: ", []byte(ref)}, {"Type REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ", []byte("REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT")}}, "declarative", "revoke-delivery")
		if _, err := unlock(); err == nil {
			t.Fatal("revoked delivery unexpectedly succeeded")
		} else {
			f.requireDeliveryRefusal(t, err, "no-unique-active-grant")
		}
		unchanged(before, "revoked delivery")
		f.registerDeliveryGrant(t, ref, fields, grantExpiry)
	})

	t.Run("legacy-metadata-only-registration", func(t *testing.T) {
		before := markerBytes()
		driverBytes, err := os.ReadFile(declarativeauthority.DriverPath)
		if err != nil {
			t.Fatal("read installed driver")
		}
		driverHash := sha256.Sum256(driverBytes)
		answers := []deliveryAnswer{
			{"Exact canonical metadata placeholder: ", []byte(ref)}, {"Repeat exact canonical reference: ", []byte(ref)},
			{"Independent installed driver SHA256: ", []byte(hex.EncodeToString(driverHash[:]))}, {"Repeat independently verified SHA256: ", []byte(hex.EncodeToString(driverHash[:]))},
			{"Type the exact target identifier to authorize: ", []byte("target")}, {"Expiry RFC3339 UTC (within 30 days): ", []byte(time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339))},
			{"Keeper effective UID (non-root): ", []byte("65534")}, {"Repeat keeper UID: ", []byte("65534")}, {"Type REGISTER SYNTHETIC METADATA GRANT: ", []byte("REGISTER SYNTHETIC METADATA GRANT")},
		}
		f.runDeliveryCLIAs(t, 0, answers, "declarative", "register")
		path := filepath.Join(declarativeauthority.RegistryPath, "delivery-grants.json")
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("read delivery metadata")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal("temporarily remove delivery metadata")
		}
		defer func() {
			if err := os.WriteFile(path, original, 0644); err != nil {
				t.Error("restore delivery metadata")
			}
		}()
		if _, err := unlock(); err == nil {
			t.Fatal("metadata-only grant unexpectedly delivered")
		} else {
			f.requireDeliveryRefusal(t, err, "no-unique-active-grant")
		}
		unchanged(before, "metadata-only grant")
	})

	t.Run("tampered-snapshot-ciphertext", func(t *testing.T) {
		parsed, err := appstoreplaceholder.Parse([]byte(ref))
		if err != nil {
			t.Fatal("parse canonical reference")
		}
		snapshotID := parsed.SnapshotID()
		path := filepath.Join(f.store, "snapshots", hex.EncodeToString(snapshotID[:])+".bin")
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("read snapshot ciphertext")
		}
		if len(original) <= appstoreheader.Size+12+10 {
			t.Fatal("snapshot ciphertext is too short")
		}
		changed := append([]byte(nil), original...)
		changed[appstoreheader.Size+12+10] ^= 1
		if err := os.WriteFile(path, changed, 0600); err != nil {
			t.Fatal("tamper snapshot ciphertext")
		}
		defer func() {
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Error("restore snapshot ciphertext")
			}
		}()
		before := markerBytes()
		out, err := unlock()
		if err != nil || !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
			t.Fatalf("tampered snapshot was not withheld by harness: %v", err)
		}
		if len(out) > 4096 {
			t.Fatal("tamper rejection output exceeded bound")
		}
		unchanged(before, "tampered snapshot")
	})

	t.Run("anchor-unavailable", func(t *testing.T) {
		before := markerBytes()
		f.anchor.dropped.Store(true)
		f.anchor.denyRead.Store(true)
		defer func() { f.anchor.dropped.Store(false); f.anchor.denyRead.Store(false) }()
		out, err := unlock()
		if err != nil || !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
			t.Fatalf("unavailable anchor was not withheld by harness: %v", err)
		}
		unchanged(before, "unavailable anchor")
	})
}
