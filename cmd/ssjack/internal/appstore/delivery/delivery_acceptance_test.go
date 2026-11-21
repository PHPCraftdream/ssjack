package delivery

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/appanchor"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type deliveryFixture struct {
	anchor     *appanchor.Fixture
	store, cli string
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	if os.Getenv("SSJACK_PUBLIC_CI") != "1" {
		t.Skip("public-CI fixture")
	}
	if !appstoreentry.Supported() {
		t.Skip("Linux appstore acceptance")
	}
	cli := os.Getenv("SSJACK_DELIVERY_CLI")
	if cli == "" {
		t.Fatal("SSJACK_DELIVERY_CLI is required")
	}
	f := appanchor.New(t)
	parent, e := os.MkdirTemp("/tmp", "ssjack-delivery-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(parent, 0755); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "store")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(dir, 65534, 65534); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	f.Dir = dir
	return &deliveryFixture{anchor: f, store: dir, cli: cli}
}

func (f *deliveryFixture) requireDeliveryRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *deliveryCLIRefusal
	if !errors.As(err, &refusal) || refusal.Class != "authority" || refusal.Code != code {
		t.Fatalf("expected typed authority refusal %q", code)
	}
}

func (f *deliveryFixture) runDeliveryCLIAsWithText(t *testing.T, uid int, answers []deliveryAnswer, text []byte, args ...string) string {
	t.Helper()
	out, err := f.tryDeliveryCLIAsWithText(t, uid, answers, text, args...)
	if err != nil {
		t.Fatalf("delivery CLI helper failed: %v", err)
	}
	return out
}

func (f *deliveryFixture) runDeliveryCLIAs(t *testing.T, uid int, answers []deliveryAnswer, args ...string) string {
	t.Helper()
	out, err := f.tryDeliveryCLIAs(t, uid, answers, args...)
	if err != nil {
		t.Fatalf("delivery CLI helper failed: %v", err)
	}
	return out
}
func (f *deliveryFixture) runDeliveryCLI(t *testing.T, answers []deliveryAnswer, args ...string) string {
	return f.runDeliveryCLIAs(t, 65534, answers, args...)
}
func (f *deliveryFixture) setupAndPut(t *testing.T) string {
	t.Helper()
	a := f.anchor
	hexStore := hex.EncodeToString(a.Store[:])
	b64 := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }
	sum := func(b []byte) []byte { x := sha256.Sum256(b); return []byte(hex.EncodeToString(x[:])) }
	chain := make([]string, len(a.ClientChain))
	for i, der := range a.ClientChain {
		chain[i] = base64.StdEncoding.EncodeToString(der)
	}
	ans := []deliveryAnswer{{"Exact HTTPS anchor endpoint: ", []byte(a.Endpoint)}, {"Repeat exact endpoint from independent source: ", []byte(a.Endpoint)}, {"Existing storeID (32 hex characters): ", []byte(hexStore)}, {"Repeat exact storeID from independent source: ", []byte(hexStore)}, {"Anchor signing public key raw 32-byte base64: ", b64(a.ServiceKey)}, {"Repeat signing public key from independent source: ", b64(a.ServiceKey)}, {"CA certificate DER base64 (one root only): ", b64(a.CADER)}, {"Client certificate chain DER base64 (leaf first, max 8): ", []byte(strings.Join(chain, ","))}, {"CA SHA256 fingerprint from independent source: ", sum(a.CADER)}, {"Client leaf SHA256 fingerprint from independent source: ", sum(a.ClientChain[0])}, {"Client PKCS#8 private key DER base64: ", b64(a.PrivateDER)}, {"New application-store master secret: ", []byte(a.Master)}, {"Confirm application-store master secret: ", []byte(a.Master)}}
	out := f.runDeliveryCLI(t, ans, "appstore", "setup", f.store)
	answers := []deliveryAnswer{{"Application-store master secret: ", []byte(a.Master)}, {"Secret (max 16 KiB): ", []byte("scoped secret")}}
	out = f.runDeliveryCLI(t, answers, "appstore", "put", f.store)
	line := strings.SplitN(out, "\n", 2)[0]
	ref, err := appstoreplaceholder.Parse([]byte(line))
	if err != nil || !ref.Valid() {
		t.Fatalf("invalid emitted reference: %v", err)
	}
	return string(line)
}

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
	inspect := f.runDeliveryCLI(t, []deliveryAnswer{{"Application-store master secret: ", []byte(f.anchor.Master)}}, "appstore", "inspect", f.store)
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
		for _, secret := range [][]byte{[]byte(f.anchor.Master), []byte(f.anchor.Secret)} {
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
	out := f.runDeliveryCLIAs(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, "golden")
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
	textBefore := len(after)
	selection := []byte(ref)
	textOut := f.runDeliveryCLIAsWithText(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}, selection, "appstore", "unlock", "--text-mode", "hydrate", "--text-fd", "3", filepath.Join(artifacts, "harness"), ref, "golden")
	clear(selection)
	if !strings.Contains(textOut, "DELIVERY_ACCEPTANCE_OK") {
		t.Fatal("text hydration did not reach the admitted fixed consumer")
	}
	textAfter, err := os.ReadFile(marker)
	if err != nil || len(textAfter)-textBefore != 96 {
		t.Fatal("text hydration did not produce the expected two receipts")
	}
	f.deliveryTextReverseAcceptance(t, ref, fields, artifacts)
	f.deliveryForeignAcceptance(t, ref, artifacts)
	f.deliveryConcurrentAcceptance(t, ref, fields, artifacts)
	f.deliveryNegativeAcceptance(t, ref, fields, artifacts)
	f.deliveryConsumerAcceptance(t, ref, fields, artifacts)
}

func (f *deliveryFixture) deliveryForeignAcceptance(t *testing.T, ref string, artifacts string) {
	t.Helper()
	marker := "/var/lib/ssjack/synthetic/consumer-receipt"
	before, err := os.ReadFile(marker)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal("cannot inspect consumer marker")
	}
	harness := filepath.Join(artifacts, "harness")
	answers := []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}
	first := f.runDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", harness, ref, "export-session")
	if !strings.Contains(first, "FOREIGN_SESSION_EXPORTED") {
		t.Fatal("session export marker missing")
	}
	mid, err := os.ReadFile(marker)
	if err != nil || len(mid)-len(before) != 48 {
		t.Fatal("export session did not consume exactly once")
	}
	second := f.runDeliveryCLIAs(t, 65534, answers, "appstore", "unlock", harness, ref, "foreign-session")
	if !strings.Contains(second, "FOREIGN_SESSION_ACCEPTED") {
		t.Fatal("foreign acceptance marker missing")
	}
	after, err := os.ReadFile(marker)
	if err != nil || len(after)-len(mid) != 48 {
		t.Fatal("foreign session did not consume exactly once")
	}
	st, err := os.Stat("/var/lib/ssjack/synthetic/foreign-session.json")
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("foreign metadata permissions incorrect")
	}
}

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
			out := f.runDeliveryCLIAs(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, tc.harnessMode)
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
		return f.tryDeliveryCLIAs(t, 65534, []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}, "appstore", "unlock", filepath.Join(artifacts, "harness"), ref, "withheld")
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
		f.anchor.Dropped.Store(true)
		f.anchor.DenyRead.Store(true)
		defer func() { f.anchor.Dropped.Store(false); f.anchor.DenyRead.Store(false) }()
		out, err := unlock()
		if err != nil || !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
			t.Fatalf("unavailable anchor was not withheld by harness: %v", err)
		}
		unchanged(before, "unavailable anchor")
	})
}

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
	answers := []deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}}
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

// deliveryTextReverseAcceptance exercises the actual CLI descriptor-to-session
// path and admits only the expected canonical reference at the pinned sink.
func (f *deliveryFixture) deliveryTextReverseAcceptance(t *testing.T, ref string, fields map[string]string, artifacts string) {
	t.Helper()
	consumerPath := declarativeauthority.ConsumerPath
	original, err := os.ReadFile(consumerPath)
	if err != nil {
		t.Fatal("save fixed consumer")
	}
	defer func() {
		if err := os.WriteFile(consumerPath, original, 0755); err != nil {
			t.Error("restore fixed consumer")
		}
		_ = os.Chown(consumerPath, 0, 0)
		_ = os.Chmod(consumerPath, 0755)
		f.registerDeliveryGrant(t, ref, fields, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339))
	}()

	buildDir := t.TempDir()
	consumer := filepath.Join(buildDir, "textconsumer")
	source, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "..", "internal", "appstorecrypto", "delivery", "testdata", "textconsumer"))
	if err != nil {
		t.Fatal("resolve fixed text consumer source")
	}
	expected := sha256.Sum256([]byte(ref))
	target := sha256.Sum256([]byte(declarativeauthority.DeliveryTarget))
	revision := sha256.Sum256([]byte(declarativeauthority.DeliveryPolicyRevision))
	purpose := sha256.Sum256([]byte(declarativeauthority.DeliveryPurpose))
	ldflags := strings.Join([]string{
		"-X main.expectedSHA256=" + hex.EncodeToString(expected[:]),
		"-X main.targetSHA256=" + hex.EncodeToString(target[:]),
		"-X main.revisionSHA256=" + hex.EncodeToString(revision[:]),
		"-X main.purposeSHA256=" + hex.EncodeToString(purpose[:]),
	}, " ")
	build := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", consumer, source)
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		clear(output)
		t.Fatal("build pinned text consumer fixture")
	}
	binary, err := os.ReadFile(consumer)
	if err != nil || len(binary) < 64 || string(binary[:4]) != "\x7fELF" {
		t.Fatal("invalid built text consumer fixture")
	}
	clear(binary)
	if err := os.WriteFile(consumerPath, mustReadFile(t, consumer), 0755); err != nil {
		t.Fatal("install pinned text consumer")
	}
	if err := os.Chown(consumerPath, 0, 0); err != nil {
		t.Fatal("own pinned text consumer")
	}
	if err := os.Chmod(consumerPath, 0755); err != nil {
		t.Fatal("protect pinned text consumer")
	}
	f.registerDeliveryGrant(t, ref, fields, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339))

	unknownSelection := []byte("unregistered synthetic representation")
	defer clear(unknownSelection)
	out := f.runDeliveryCLIAsWithText(t, 65534,
		[]deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}},
		unknownSelection, "appstore", "unlock", "--text-mode", "reverse", "--text-fd", "3",
		filepath.Join(artifacts, "harness"), ref, "unknown")
	if !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
		t.Fatal("unregistered reverse text was not rejected by the pinned fixed consumer")
	}

	selection := []byte(f.anchor.Secret)
	defer clear(selection)
	out = f.runDeliveryCLIAsWithText(t, 65534,
		[]deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.Master)}},
		selection, "appstore", "unlock", "--text-mode", "reverse", "--text-fd", "3",
		filepath.Join(artifacts, "harness"), ref, "golden")
	if !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
		t.Fatal("reverse text copy was not admitted by the pinned fixed consumer")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read pinned text consumer")
	}
	return data
}
