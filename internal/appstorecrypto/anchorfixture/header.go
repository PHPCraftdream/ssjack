package anchorfixture

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

// Header returns the fixed one-chunk test snapshot header.
func Header(t *testing.T) appstoreheader.Header {
	t.Helper()
	literal := "535341505030303100010000" + strings.Repeat("01", 16) + strings.Repeat("02", 16) + strings.Repeat("00", 16) +
		"0010000000000000001000000000000100000000" +
		strings.Repeat("11", 32) + strings.Repeat("22", 32) + strings.Repeat("33", 32) + strings.Repeat("44", 32) + strings.Repeat("55", 12)
	b, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	h, err := appstoreheader.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// FakeKDF is a fast stand-in for the production KDF.
func FakeKDF(password, salt []byte) []byte {
	h := sha256.Sum256(append(append([]byte(nil), password...), salt...))
	return append([]byte(nil), h[:]...)
}
