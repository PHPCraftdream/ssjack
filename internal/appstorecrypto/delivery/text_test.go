package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestPrivateTextBindingBindsDirectionAndSelection(t *testing.T) {
	base := strings.Repeat("a", 64)
	selected := []byte("selected")
	first, err := NewTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	forward := first.Digest(base, selected, false)
	if len(forward) != 64 || forward == first.Digest(base, selected, true) || forward == first.Digest(base, []byte("other"), false) || forward == first.Digest(strings.Repeat("b", 64), selected, false) || forward == second.Digest(base, selected, false) {
		t.Fatal("private text binding failed to bind capability or inputs")
	}
	// This synthetic low-entropy selection confirms the removed public formula is not the output.
	old := sha256.New()
	_, _ = old.Write([]byte("ssjack/appstorecrypto/text-operation/v1\x00"))
	_, _ = old.Write([]byte(base))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(selected)))
	_, _ = old.Write(size[:])
	_, _ = old.Write(selected)
	_, _ = old.Write([]byte{0})
	if forward == hex.EncodeToString(old.Sum(nil)) {
		t.Fatal("private digest equals old public unkeyed digest")
	}
}

func TestTransformTextSelection(t *testing.T) {
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("line one\n雪 ☃")
	input := append([]byte("ordinary "), placeholder...)
	input = append(input, []byte(" / ")...)
	input = append(input, placeholder...)
	original := append([]byte(nil), input...)
	got, err := transformTextSelection(ref, secret, input, false)
	if err != nil || !bytes.Equal(got, []byte("ordinary line one\n雪 ☃ / line one\n雪 ☃")) {
		t.Fatalf("hydrate: %q %v", got, err)
	}
	if !bytes.Equal(input, original) {
		t.Fatal("hydration modified selection")
	}
	reverseInput := []byte("keep\nline one\n雪 ☃!")
	reverseOriginal := append([]byte(nil), reverseInput...)
	reversed, err := transformTextSelection(ref, secret, reverseInput, true)
	want := append([]byte("keep\n"), append(placeholder, '!')...)
	if err != nil || !bytes.Equal(reversed, want) {
		t.Fatalf("reverse: %q %v", reversed, err)
	}
	if !bytes.Equal(reverseInput, reverseOriginal) {
		t.Fatal("reverse modified selection")
	}
}

func TestPendingSelectionClearOnClose(t *testing.T) {
	secret := []byte("captured plaintext")
	state := &deliveryPlanState{text: &textSelection{input: secret}}
	binding := TextBinding{initialized: true}
	for i := range binding.key {
		binding.key[i] = byte(i + 1)
	}
	capability := &DeliveryCapability{textBinding: binding, pendingSelections: map[*deliveryPlanState]struct{}{state: {}}}
	if !capability.textBinding.initialized || bytes.Equal(capability.textBinding.key[:], make([]byte, len(capability.textBinding.key))) {
		t.Fatal("test capability was not seeded with a private key")
	}
	if err := capability.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) || state.text != nil || capability.pendingSelections != nil || capability.textBinding.initialized || !bytes.Equal(capability.textBinding.key[:], make([]byte, len(capability.textBinding.key))) {
		t.Fatal("pending selection or private binding key was retained")
	}
}

func TestPrivateTextBindingValidation(t *testing.T) {
	base := strings.Repeat("a", 64)
	selected := []byte("1234")
	var first, second TextBinding
	for i := range first.key {
		first.key[i] = 1
		second.key[i] = 2
	}
	first.initialized, second.initialized = true, true
	capability := &DeliveryCapability{textBinding: first}
	digest := first.Digest(base, selected, false)
	operation := OperationBinding{Digest: digest}
	if !capability.validTextBinding(operation, base, selected, false) {
		t.Fatal("matching private text binding rejected")
	}
	if capability.validTextBinding(OperationBinding{Digest: second.Digest(base, selected, false)}, base, selected, false) {
		t.Fatal("another owner's operation digest validated")
	}
	mutatedDigest := digest[:len(digest)-1] + "0"
	if mutatedDigest == digest {
		mutatedDigest = digest[:len(digest)-1] + "1"
	}
	if capability.validTextBinding(OperationBinding{Digest: mutatedDigest}, base, selected, false) {
		t.Fatal("mutated operation digest validated")
	}
	if digest == legacyTextDigest(base, selected, false) {
		t.Fatal("private HMAC equals public unkeyed digest")
	}
	for _, tc := range []struct {
		name    string
		base    string
		text    []byte
		reverse bool
	}{
		{name: "selection", base: base, text: []byte("1235")},
		{name: "direction", base: base, text: selected, reverse: true},
		{name: "base", base: strings.Repeat("b", 64), text: selected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if capability.validTextBinding(operation, tc.base, tc.text, tc.reverse) {
				t.Fatal("changed private binding inputs accepted")
			}
		})
	}
	closed := &DeliveryCapability{textBinding: first, closed: true}
	if closed.validTextBinding(operation, base, selected, false) {
		t.Fatal("closed capability validated a binding")
	}
}

func legacyTextDigest(base string, selected []byte, reverse bool) string {
	h := sha256.New()
	_, _ = h.Write([]byte("ssjack/appstorecrypto/text-operation/v1\x00"))
	_, _ = h.Write([]byte(base))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(selected)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(selected)
	if reverse {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

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

func TestSyntheticCurrentTextSelectionHydratesPlaceholder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	path, artifact := nativeConsumerFixture(t)
	master, err := derive(ctx, h, []byte("synthetic text delivery"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()

	payload := make([]byte, 20000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	source, err := os.CreateTemp(t.TempDir(), "synthetic-text-input-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Write(payload[17:]); err != nil {
		t.Fatal(err)
	}
	writer, err := snapshotstore.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, []snapshotstore.SnapshotObject{{ObjectID: [16]byte{1}, MediaType: "bin", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	ref := commit.Refs[0]
	token, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	selected := append(append([]byte{}, payload[:17]...), token...)
	before := append([]byte(nil), selected...)
	consumer := boundNativeConsumer(t, path, artifact, ref, commit.EncodedHash)
	result, err := deliverCurrentText(master, ctx, directory, fault.Reader, ref, consumer, &textSelection{input: selected})
	if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != uint64(len(payload)) {
		t.Fatalf("hydrated synthetic text selection: %+v %v", result, err)
	}
	if !bytes.Equal(selected, before) {
		t.Fatal("text selection input was modified")
	}

	wrongVersion := ref.VersionID()
	wrongVersion[0] ^= 1
	if wrongVersion == ([16]byte{}) {
		wrongVersion[1] = 1
	}
	wrong, err := appstoreref.New(ref.StoreID(), ref.ObjectID(), wrongVersion, ref.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	wrongConsumer := boundNativeConsumer(t, path, artifact, wrong, commit.EncodedHash)
	denied, err := deliverCurrentText(master, ctx, directory, fault.Reader, wrong, wrongConsumer, &textSelection{input: selected})
	if !errors.Is(err, appstoreref.ErrNotFound) || denied.MayHaveDelivered || denied.Complete {
		t.Fatalf("wrong version released: %+v %v", denied, err)
	}
}

func TestSyntheticCurrentTextReverseCopyToFixedNativeConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	transport, _, directory, h, _, fault := writerFixtureWithFault(t, appstoreanchorcore.Writer)
	master, err := derive(ctx, h, []byte("synthetic reverse text delivery"), fake)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()

	secret := []byte("synthetic\n雪 secret")
	source, err := os.CreateTemp(t.TempDir(), "synthetic-reverse-input-")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := source.Write(secret); err != nil {
		t.Fatal(err)
	}
	writer, err := snapshotstore.NewSnapshotWriter(directory, transport, master)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := writer.Write(ctx, []snapshotstore.SnapshotObject{{ObjectID: [16]byte{1}, MediaType: "text/plain", Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	ref := commit.Refs[0]
	token, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	selected := append([]byte("ordinary prefix "), secret...)
	selected = append(selected, []byte(" ordinary suffix")...)
	want := append([]byte("ordinary prefix "), token...)
	want = append(want, []byte(" ordinary suffix")...)
	digest := sha256.Sum256(want)

	path := filepath.Join(t.TempDir(), "reverse-fixed-consumer")
	argument := "-X main.expectedSHA256=" + hex.EncodeToString(digest[:])
	command := exec.Command("go", "build", "-ldflags", argument, "-o", path, "./testdata/textconsumer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic reverse consumer: %v\n%s", err, output)
	}
	program, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	consumer := boundNativeConsumer(t, path, sha256.Sum256(program), ref, commit.EncodedHash)
	before := append([]byte(nil), selected...)
	result, err := deliverCurrentText(master, ctx, directory, fault.Reader, ref, consumer, &textSelection{input: selected, reverse: true})
	if err != nil || !result.Complete || !result.MayHaveDelivered || result.Bytes != uint64(len(want)) {
		t.Fatalf("reverse-copied synthetic text selection: %+v %v", result, err)
	}
	if !bytes.Equal(selected, before) {
		t.Fatal("reverse copy modified source selection")
	}
}
