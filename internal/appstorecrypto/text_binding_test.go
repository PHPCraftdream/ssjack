package appstorecrypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPrivateTextBindingValidation(t *testing.T) {
	base := strings.Repeat("a", 64)
	selected := []byte("1234")
	var first, second textBinding
	for i := range first.key {
		first.key[i] = 1
		second.key[i] = 2
	}
	first.initialized, second.initialized = true, true
	capability := &DeliveryCapability{textBinding: first}
	digest := first.digest(base, selected, false)
	operation := OperationBinding{Digest: digest}
	if !capability.validTextBinding(operation, base, selected, false) {
		t.Fatal("matching private text binding rejected")
	}
	if capability.validTextBinding(OperationBinding{Digest: second.digest(base, selected, false)}, base, selected, false) {
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
