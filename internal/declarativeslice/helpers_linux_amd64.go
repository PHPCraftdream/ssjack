//go:build linux && amd64

package declarativeslice

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func decodeInput(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > maxDocument {
		return ErrInvalid
	}
	if _, err := driverprotocol.ParseJSON(raw); err != nil {
		return ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil || dec.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validateDesired(raw []byte, ref string) error {
	value, err := driverprotocol.ParseJSON(raw)
	if err != nil {
		return ErrInvalid
	}
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 2 {
		return ErrInvalid
	}
	if _, ok := fields["enabled"].(bool); !ok {
		return ErrInvalid
	}
	actual, ok := fields["ref"].(string)
	if !ok || actual != ref || declarativeauthority.ValidateReference(actual) != nil {
		return ErrInvalid
	}
	return nil
}
func fixedSchemaDigest(document string) string {
	canonical, err := driverprotocol.CanonicalSchemaDocument([]byte(document))
	if err != nil {
		return ""
	}
	h := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), canonical...))
	return hex.EncodeToString(h[:])
}
func validID(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == v
}
func validRequestID(v string) bool { return validID(v) }
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
