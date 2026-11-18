package pathsafe

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Refused returns a ClassRefusedPath error with a fixed message.
func Refused(message string) error {
	return transfercore.Fail(transfercore.ClassRefusedPath, message)
}

// RandomHex returns digits lowercase hex characters from the CSPRNG.
func RandomHex(digits int) (string, error) {
	raw := make([]byte, (digits+1)/2)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw)[:digits], nil
}
