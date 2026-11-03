package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

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
	source, err := filepath.Abs(filepath.Join("..", "..", "internal", "appstorecrypto", "testdata", "textconsumer"))
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
		[]deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}},
		unknownSelection, "appstore", "unlock", "--text-mode", "reverse", "--text-fd", "3",
		filepath.Join(artifacts, "harness"), ref, "unknown")
	if !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
		t.Fatal("unregistered reverse text was not rejected by the pinned fixed consumer")
	}

	selection := []byte(f.anchor.secret)
	defer clear(selection)
	out = f.runDeliveryCLIAsWithText(t, 65534,
		[]deliveryAnswer{{"Exact canonical delivery reference: ", []byte(ref)}, {"Application-store master secret: ", []byte(f.anchor.master)}},
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
