//go:build linux && amd64

package declarativeauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const (
	deliveryName     = "delivery-grants.json"
	deliveryFormat   = "ssjack-confidential-delivery-grants-v1"
	deliveryPurpose  = "synthetic-confidential-delivery"
	deliveryRevision = "synthetic-delivery-v1"
)

type DeliveryGrant struct {
	RecipientUID           int    `json:"recipient_uid"`
	Ref                    string `json:"ref"`
	StorePath              string `json:"store_path"`
	DirectoryDev           uint64 `json:"directory_dev"`
	DirectoryIno           uint64 `json:"directory_ino"`
	InstallationSHA256     string `json:"installation_sha256"`
	EncodedHash            string `json:"encoded_hash"`
	DriverCodeSHA256       string `json:"driver_code_sha256"`
	ConsumerSHA256         string `json:"consumer_sha256"`
	Target                 string `json:"target"`
	Purpose                string `json:"purpose"`
	DesiredSchemaID        string `json:"desired_schema_id"`
	DesiredSchemaSHA256    string `json:"desired_schema_sha256"`
	ProjectionSchemaID     string `json:"projection_schema_id"`
	ProjectionSchemaSHA256 string `json:"projection_schema_sha256"`
	PolicyRevision         string `json:"policy_revision"`
	ExpiresAt              string `json:"expires_at"`
	Revoked                bool   `json:"revoked"`
}
type deliveryDisk struct {
	Format string          `json:"format"`
	Grants []DeliveryGrant `json:"grants"`
}
type DeliverySnapshot struct{ grants []DeliveryGrant }

func (s DeliverySnapshot) Grants() []DeliveryGrant { return append([]DeliveryGrant(nil), s.grants...) }

// DeliveryGrant metadata does not itself approve production consumption; an authenticated installation must also match it.
func (g DeliveryGrant) Active(now time.Time) bool { return validateDelivery(g, true, now) == nil }

// RegisterDelivery is an explicit root-only registration; it does not infer delivery permission from metadata grants.
func RegisterDelivery(g DeliveryGrant) error {
	if os.Geteuid() != 0 || LoadSetup() != nil || validateDelivery(g, true, time.Now()) != nil {
		return ErrAuthority
	}
	driver, e := DeliveryDriverDigest()
	if e != nil || driver != g.DriverCodeSHA256 {
		return ErrAuthority
	}
	consumer, e := DeliveryCodeDigest()
	if e != nil || consumer != g.ConsumerSHA256 {
		return ErrAuthority
	}
	d, err := readDelivery()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrAuthority
	}
	if errors.Is(err, os.ErrNotExist) {
		d = deliveryDisk{deliveryFormat, []DeliveryGrant{}}
	}
	for i, old := range d.Grants {
		if old.Ref == g.Ref {
			exp, _ := time.Parse(time.RFC3339, old.ExpiresAt)
			if !old.Revoked && exp.After(time.Now()) && old.RecipientUID != g.RecipientUID {
				return ErrAuthority
			}
			d.Grants[i] = g
			return writeDelivery(d)
		}
	}
	if len(d.Grants) >= 128 {
		return ErrAuthority
	}
	d.Grants = append(d.Grants, g)
	return writeDelivery(d)
}
func RevokeDelivery(ref string) error {
	if os.Geteuid() != 0 || LoadSetup() != nil || ValidateReference(ref) != nil {
		return ErrAuthority
	}
	d, e := readDelivery()
	if e != nil {
		return ErrAuthority
	}
	for i := range d.Grants {
		if d.Grants[i].Ref == ref {
			d.Grants[i].Revoked = true
			return writeDelivery(d)
		}
	}
	return ErrAuthority
}

// LoadDelivery returns only active metadata for one recipient and rejects ambiguous exact-reference records.
func LoadDelivery(ref string, uid int, now time.Time) (DeliverySnapshot, error) {
	if ValidateReference(ref) != nil || uid <= 0 || LoadSetup() != nil {
		return DeliverySnapshot{}, ErrAuthority
	}
	d, e := readDelivery()
	if errors.Is(e, os.ErrNotExist) {
		return DeliverySnapshot{[]DeliveryGrant{}}, nil
	}
	if e != nil {
		return DeliverySnapshot{}, ErrAuthority
	}
	out := []DeliveryGrant{}
	for _, g := range d.Grants {
		if g.Ref == ref && g.RecipientUID == uid && validateDelivery(g, true, now) == nil {
			out = append(out, g)
		}
	}
	if len(out) > 1 {
		return DeliverySnapshot{}, ErrAuthority
	}
	return DeliverySnapshot{out}, nil
}
func validateDelivery(g DeliveryGrant, active bool, now time.Time) error {
	clean := filepath.Clean(g.StorePath)
	if ValidateReference(g.Ref) != nil || g.RecipientUID <= 0 || !filepath.IsAbs(g.StorePath) || clean != g.StorePath || g.DirectoryDev == 0 || g.DirectoryIno == 0 || g.Target != target || g.Purpose != deliveryPurpose || g.PolicyRevision != deliveryRevision || g.DesiredSchemaID != desiredSchemaID || g.ProjectionSchemaID != projectionSchemaID {
		return ErrAuthority
	}
	for _, v := range []string{g.InstallationSHA256, g.EncodedHash, g.DriverCodeSHA256, g.ConsumerSHA256, g.DesiredSchemaSHA256, g.ProjectionSchemaSHA256} {
		if !digestPattern.MatchString(v) {
			return ErrAuthority
		}
	}
	exp, e := time.Parse(time.RFC3339, g.ExpiresAt)
	if e != nil || exp.UTC().Format(time.RFC3339) != g.ExpiresAt {
		return ErrAuthority
	}
	if active && (g.Revoked || !exp.After(now) || exp.Sub(now) > 24*time.Hour) {
		return ErrAuthority
	}
	return nil
}
func readDelivery() (deliveryDisk, error) {
	var d deliveryDisk
	b, e := readTrusted(filepath.Join(RegistryPath, deliveryName), maxFile)
	if e != nil {
		return d, e
	}
	c, e := canonicaljson.Canonicalize(b)
	if e != nil || string(c) != string(b) {
		return d, ErrAuthority
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || d.Format != deliveryFormat || d.Grants == nil || len(d.Grants) > 128 || dec.Decode(new(any)) != io.EOF {
		return deliveryDisk{}, ErrAuthority
	}
	for i, g := range d.Grants {
		if validateDelivery(g, false, time.Now()) != nil {
			return deliveryDisk{}, ErrAuthority
		}
		for _, prior := range d.Grants[:i] {
			if prior.Ref == g.Ref {
				return deliveryDisk{}, ErrAuthority
			}
		}
	}
	return d, nil
}
func writeDelivery(d deliveryDisk) error {
	if d.Format != deliveryFormat || d.Grants == nil || len(d.Grants) > 128 {
		return ErrAuthority
	}
	for i, g := range d.Grants {
		if validateDelivery(g, false, time.Now()) != nil {
			return ErrAuthority
		}
		for _, p := range d.Grants[:i] {
			if p.Ref == g.Ref {
				return ErrAuthority
			}
		}
	}
	b, e := json.Marshal(d)
	if e != nil {
		return ErrAuthority
	}
	b, e = canonicaljson.Canonicalize(b)
	if e != nil || len(b) > maxFile {
		return ErrAuthority
	}
	return atomicNamed(deliveryName, b)
}

// DeliveryCodeDigest hashes only the fixed, root-owned consumer executable.
func DeliveryCodeDigest() (string, error) {
	if safeDeliveryCodeDirectory() != nil {
		return "", ErrAuthority
	}
	b, e := readTrusted(ConsumerPath, 64<<20)
	if e != nil {
		return "", ErrAuthority
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
