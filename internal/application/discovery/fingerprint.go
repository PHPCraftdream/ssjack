package discovery

import (
	"crypto/sha256"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

// descriptorFingerprint hashes the canonical JSON form of bounded descriptor
// bytes so line-ending or whitespace changes do not invalidate an approval.
// ok is false when canonicalization rejects the buffer; no raw-byte fallback
// exists, so the hash basis is always canonical JSON.
func descriptorFingerprint(data []byte) ([32]byte, bool) {
	canonical, err := canonicaljson.Canonicalize(data)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(canonical), true
}
