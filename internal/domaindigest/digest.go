// Package domaindigest provides isolated v1 domain-separated JSON digests.
// It does not validate schemas, authorize values, or implement plan binding.
package domaindigest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

// Domain identifies one of the closed set of v1 digest purposes.
type Domain uint8

const (
	Schema Domain = iota + 1
	ToolSchema
	Plan
	Enrollment
	Desired
	Effects
)

var ErrDomain = errors.New("unknown digest domain")

// Sum canonicalizes raw JSON under canonicaljson's limits and returns the
// lowercase SHA-256 digest of the domain, NUL, and canonical bytes. Callers
// must independently validate the applicable schema and purpose-specific limits.
func Sum(domain Domain, raw []byte) (string, error) {
	var label string
	switch domain {
	case Schema:
		label = "ssjack-schema-v1"
	case ToolSchema:
		label = "ssjack-tool-schema-v1"
	case Plan:
		label = "ssjack-plan-v1"
	case Enrollment:
		label = "ssjack-enrollment-v1"
	case Desired:
		label = "ssjack-desired-v1"
	case Effects:
		label = "ssjack-effects-v1"
	default:
		return "", ErrDomain
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}
