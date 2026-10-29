package planbinding

import (
	"encoding/json"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

// ValidateAt checks one supplied clock observation, not clock trust or execution authority.
func ValidateAt(raw []byte, now time.Time) (string, error) {
	if now.IsZero() || len(raw) == 0 || len(raw) > canonicaljson.MaxInput {
		return "", ErrInvalid
	}
	owned := append([]byte(nil), raw...)
	defer clear(owned)
	digest, err := Validate(owned)
	if err != nil {
		return "", ErrInvalid
	}
	var fields struct {
		Created string `json:"created_at"`
		Expires string `json:"expires_at"`
	}
	if err := json.Unmarshal(owned, &fields); err != nil {
		return "", ErrInvalid
	}
	created, err := time.Parse("2006-01-02T15:04:05.000Z", fields.Created)
	if err != nil {
		return "", ErrInvalid
	}
	expires, err := time.Parse("2006-01-02T15:04:05.000Z", fields.Expires)
	if err != nil || !created.Before(expires) || now.Before(created) || !now.Before(expires) {
		return "", ErrInvalid
	}
	return digest, nil
}
