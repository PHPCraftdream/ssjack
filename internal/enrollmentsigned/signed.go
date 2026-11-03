// Package enrollmentsigned composes signature verification and isolated enrollment validation.
// It does not authorize enrollment or connect it to execution.
package enrollmentsigned

import (
	"errors"
	"fmt"

	"github.com/PHPCraftdream/ssjack/internal/enrollmentauth"
	"github.com/PHPCraftdream/ssjack/internal/enrollmentvalidator"
)

// Verify checks the exact signed canonical manifest against the isolated validator.
// The root must come from an independently trusted source. Success does not
// establish full v1 conformance, authorization, freshness, or runtime enforcement.
// On failure it returns no verified manifest.
func Verify(envelope []byte, root enrollmentauth.TrustRoot) (enrollmentauth.Verified, error) {
	verified, err := enrollmentauth.VerifyCanonicalBytes(envelope, root)
	if err != nil {
		return enrollmentauth.Verified{}, fmt.Errorf("verify signed enrollment: %w", err)
	}
	digest, err := enrollmentvalidator.Validate(verified.Manifest())
	if err != nil {
		return enrollmentauth.Verified{}, fmt.Errorf("validate signed enrollment: %w", err)
	}
	if digest != verified.Digest() {
		return enrollmentauth.Verified{}, errors.New("signed enrollment digest mismatch")
	}
	return verified, nil
}
