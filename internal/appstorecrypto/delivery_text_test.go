package appstorecrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func TestPrivateTextBindingBindsDirectionAndSelection(t *testing.T) {
	base := strings.Repeat("a", 64)
	selected := []byte("selected")
	first, err := newTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	forward := first.digest(base, selected, false)
	if len(forward) != 64 || forward == first.digest(base, selected, true) || forward == first.digest(base, []byte("other"), false) || forward == first.digest(strings.Repeat("b", 64), selected, false) || forward == second.digest(base, selected, false) {
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
	binding := textBinding{initialized: true}
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
