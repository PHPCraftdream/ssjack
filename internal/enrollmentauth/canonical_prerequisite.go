package enrollmentauth

import (
	"bytes"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

// VerifyCanonicalBytes is a fail-closed prerequisite for enrollment validation.
// It verifies the signature over the exact transmitted manifest bytes and rejects
// bytes that are not already JCS-SSJACK-1. It does not validate the enrollment
// record or schema dialect, establish trust-root provenance, or authorize use.
// In particular, success MUST NOT be treated as v1 enrollment conformance.
func VerifyCanonicalBytes(data []byte, root TrustRoot) (Verified, error) {
	verified, err := Verify(data, root)
	if err != nil {
		return Verified{}, err
	}
	canonical, err := canonicaljson.Canonicalize(verified.manifest)
	if err != nil || !bytes.Equal(canonical, verified.manifest) {
		return Verified{}, errors.New("signed manifest is not canonical JSON")
	}
	return verified, nil
}
