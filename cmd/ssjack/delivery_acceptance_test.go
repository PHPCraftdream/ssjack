package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func (f *deliveryFixture) registerDeliveryGrant(t *testing.T, ref string, fields map[string]string, expiry string) {
	t.Helper()
	hash := func(path string) string {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	dev, ino := fields["directory_dev"], fields["directory_ino"]
	answers := []deliveryAnswer{{"Exact canonical confidential-delivery reference: ", []byte(ref)}, {"Repeat exact canonical reference: ", []byte(ref)}, {"Trusted absolute StorePath (human verified, never supplied by model tooling): ", []byte(f.store)}, {"Repeat exact StorePath: ", []byte(f.store)}, {"Verified store directory device number: ", []byte(dev)}, {"Repeat directory device number: ", []byte(dev)}, {"Verified store directory inode number: ", []byte(ino)}, {"Repeat directory inode number: ", []byte(ino)}, {"Independently verified encrypted InstallationSHA256: ", []byte(fields["installation_sha256"])}, {"Current snapshot EncodedHash from independently verified keeper CLI: ", []byte(fields["encoded_hash"])}, {"Independent driver SHA256: ", []byte(hash(declarativeauthority.DriverPath))}, {"Repeat driver SHA256: ", []byte(hash(declarativeauthority.DriverPath))}, {"Independent consumer SHA256: ", []byte(hash(declarativeauthority.ConsumerPath))}, {"Repeat consumer SHA256: ", []byte(hash(declarativeauthority.ConsumerPath))}, {"Type exact target identifier: ", []byte("target")}, {"Expiry RFC3339 UTC (within 24 hours): ", []byte(expiry)}, {"Keeper effective UID (non-root): ", []byte("65534")}, {"Repeat keeper UID: ", []byte("65534")}, {"Type REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ", []byte("REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT")}}
	f.runDeliveryCLIAs(t, 0, answers, "declarative", "register-delivery")
}

// TestDeliveryScopedAcceptance exercises the complete positive delivery route
// using the isolated native fixtures provisioned by delivery_scoped.py.
func TestDeliveryScopedAcceptance(t *testing.T) {
	f := newDeliveryFixture(t)
	if os.Geteuid() != 0 {
		t.Fatal("delivery acceptance requires root provisioning")
	}
	if err := os.MkdirAll("/usr/libexec", 0755); err != nil {
		t.Fatal("create synthetic setup parent")
	}
	if _, err := os.Stat(filepath.Join(declarativeauthority.RegistryPath, declarativeauthority.SetupName)); err != nil {
		f.runDeliveryCLIAs(t, 0, []deliveryAnswer{{"Type SETUP DECLARATIVE SYNTHETIC METADATA ONLY: ", []byte("SETUP DECLARATIVE SYNTHETIC METADATA ONLY")}}, "declarative", "setup")
	}
	artifacts := os.Getenv("SSJACK_DELIVERY_ARTIFACTS")
	for _, item := range []struct{ name, dest string }{
		{"driver", declarativeauthority.DriverPath}, {"consumer", declarativeauthority.ConsumerPath},
	} {
		b, err := os.ReadFile(filepath.Join(artifacts, item.name))
		if err != nil {
			t.Fatalf("missing %s fixture", item.name)
		}
		if len(b) < 64 || string(b[:4]) != "\x7fELF" {
			t.Fatalf("invalid native %s fixture", item.name)
		}
		if err := os.WriteFile(item.dest, b, 0755); err != nil {
			t.Fatalf("install %s fixture", item.name)
		}
		if err := os.Chown(item.dest, 0, 0); err != nil {
			t.Fatalf("own %s fixture", item.name)
		}
		if err := os.Chmod(item.dest, 0755); err != nil {
			t.Fatalf("mode %s fixture", item.name)
		}
	}
	ref := f.setupAndPut(t)
	inspect := f.runDeliveryCLI(t, []deliveryAnswer{{"Application-store master secret: ", []byte(f.anchor.master)}}, "appstore", "inspect", f.store)
	fields := map[string]string{}
	for _, line := range strings.Split(inspect, "\n") {
		p := strings.SplitN(line, "=", 2)
		if len(p) == 2 {
			fields[p[0]] = p[1]
		}
	}
	for _, key := range []string{"installation_sha256", "encoded_hash", "directory_dev", "directory_ino"} {
		if fields[key] == "" {
			t.Fatalf("inspect omitted %s", key)
		}
	}
	if err := filepath.WalkDir(f.store, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		defer clear(b)
		for _, secret := range [][]byte{[]byte(f.anchor.master), []byte(f.anchor.secret)} {
			if len(secret) > 0 && strings.Contains(string(b), string(secret)) {
				return os.ErrInvalid
			}
		}
		return nil
	}); err != nil {
		t.Fatal("secret found in encrypted store artifact or store scan failed")
	}
	expiry := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	f.registerDeliveryGrant(t, ref, fields, expiry)
	stateRaw := []byte(`{"enabled":false,"ref":"","revision":"r0","operation_id":"","plan_digest":"0000000000000000000000000000000000000000000000000000000000000000"}`)
	state, err := canonicaljson.Canonicalize(stateRaw)
	if err != nil {
		t.Fatal("canonicalize initial state")
	}
	statePath := filepath.Join(declarativeauthority.StatePath, "state.json")
	if err := os.WriteFile(statePath, state, 0600); err != nil {
		t.Fatal("reset synthetic state fixture")
	}
	if err := os.Chown(statePath, 65534, 65534); err != nil {
		t.Fatal("own synthetic state fixture")
	}
	if err := os.Chmod(statePath, 0600); err != nil {
		t.Fatal("protect synthetic state fixture")
	}
	marker := "/var/lib/ssjack/synthetic/consumer-receipt"
	before, err := os.ReadFile(marker)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal("cannot inspect consumer marker")
	}
	out := f.runDeliveryCLIAs(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}}, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, "golden")
	if !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
		t.Fatal("native harness did not report successful delivery")
	}
	after, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("consumer marker missing")
	}
	if len(after)-len(before) != 96 {
		t.Fatalf("expected two 48-byte delivery markers, got delta %d", len(after)-len(before))
	}
	f.deliveryForeignAcceptance(t, ref, artifacts)
	f.deliveryConcurrentAcceptance(t, ref, fields, artifacts)
	f.deliveryNegativeAcceptance(t, ref, fields, artifacts)
	f.deliveryConsumerAcceptance(t, ref, fields, artifacts)
}
