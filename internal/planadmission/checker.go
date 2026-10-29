// Package planadmission composes plan preflight checks without granting authority.
package planadmission

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/planbinding"
)

var ErrPin = errors.New("invalid fixed plan schema pin")
var ErrInvalid = errors.New("plan does not match fixed schema preflight")
var name = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

type Config struct {
	Document []byte
	ID       string
	Digest   string
	Target   string
	Kind     string
}

type Checker struct {
	document []byte
	id       string
	digest   string
	target   string
	kind     string
}

// New owns canonical schema bytes; supplied pin provenance remains the caller's responsibility.
func New(config Config) (*Checker, error) {
	if len(config.Document) == 0 || len(config.Document) > canonicaljson.MaxInput || !name.MatchString(config.Target) || !name.MatchString(config.Kind) {
		return nil, ErrPin
	}
	canonical, err := driverprotocol.CanonicalSchemaDocument(config.Document)
	if err != nil || driverprotocol.ValidateSchemaDocument(canonical, config.ID, config.Digest) != nil {
		return nil, ErrPin
	}
	return &Checker{document: canonical, id: config.ID, digest: config.Digest, target: config.Target, kind: config.Kind}, nil
}

// Check returns only the canonical plan digest, not an executable plan or freshness capability.
func (c *Checker) Check(raw []byte, now time.Time) (string, error) {
	if c == nil || len(c.document) == 0 {
		return "", ErrPin
	}
	if len(raw) == 0 || len(raw) > canonicaljson.MaxInput {
		return "", ErrInvalid
	}
	owned := append([]byte(nil), raw...)
	defer clear(owned)
	digest, err := planbinding.ValidateAt(owned, now)
	if err != nil {
		return "", ErrInvalid
	}
	var fields struct {
		Target       string          `json:"target"`
		Kind         string          `json:"kind"`
		SchemaID     string          `json:"desired_schema_id"`
		SchemaDigest string          `json:"desired_schema_digest"`
		Desired      json.RawMessage `json:"desired"`
	}
	if err := json.Unmarshal(owned, &fields); err != nil || fields.SchemaID != c.id || fields.SchemaDigest != c.digest || fields.Target != c.target || fields.Kind != c.kind {
		return "", ErrInvalid
	}
	if err := driverprotocol.ValidatePinnedValue(c.document, c.id, c.digest, c.target, c.kind, fields.Target, fields.Kind, fields.SchemaID, fields.Desired, driverprotocol.MaxDesired); err != nil {
		return "", ErrInvalid
	}
	return digest, nil
}
