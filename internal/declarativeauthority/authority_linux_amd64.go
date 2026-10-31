//go:build linux && amd64

package declarativeauthority

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const (
	RegistryPath       = "/etc/ssjack/declarative"
	SetupName          = "setup.json"
	GrantsName         = "grants.json"
	DriverPath         = "/usr/libexec/ssjack-synthetic-driver"
	StatePath          = "/var/lib/ssjack/synthetic"
	MaxLifetime        = 30 * 24 * time.Hour
	maxFile            = 64 << 10
	setupFormat        = "ssjack-declarative-synthetic-setup-v1"
	grantFormat        = "ssjack-declarative-synthetic-grants-v1"
	target             = "target"
	desiredSchemaID    = "cache.desired"
	projectionSchemaID = "cache.projection"
	purpose            = "synthetic-metadata"
)

var (
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	ErrAuthority  = errors.New("declarative authority unavailable or invalid")
)

type Grant struct {
	RecipientUID           int    `json:"recipient_uid"`
	Ref                    string `json:"ref"`
	CodeSHA256             string `json:"code_sha256"`
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

type disk struct {
	Format string  `json:"format"`
	Grants []Grant `json:"grants"`
}

type Snapshot struct{ grants []Grant }

func (s Snapshot) Grants() []Grant { return append([]Grant(nil), s.grants...) }

func ValidateReference(raw string) error {
	r, err := appstoreplaceholder.Parse([]byte(raw))
	if err != nil || !r.Valid() {
		return ErrAuthority
	}
	canonical, err := appstoreplaceholder.Encode(r)
	if err != nil || string(canonical) != raw {
		return ErrAuthority
	}
	return nil
}

func (g Grant) Active(now time.Time) bool { return validateGrant(g, true, now) == nil }

func Setup() error {
	if os.Geteuid() != 0 || safeDirectory(true) != nil {
		return ErrAuthority
	}
	marker, err := json.Marshal(struct {
		Format string `json:"format"`
		Scope  string `json:"scope"`
	}{setupFormat, "synthetic metadata only; no secret release"})
	if err != nil {
		return ErrAuthority
	}
	marker, err = canonicaljson.Canonicalize(marker)
	if err != nil {
		return ErrAuthority
	}
	return createMarker(marker)
}

func Register(g Grant) error {
	if os.Geteuid() != 0 || validateGrant(g, true, time.Now()) != nil || LoadSetup() != nil {
		return ErrAuthority
	}
	path := filepath.Join(RegistryPath, GrantsName)
	d, err := readDisk(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrAuthority
	}
	if errors.Is(err, os.ErrNotExist) {
		d = disk{Format: grantFormat, Grants: []Grant{}}
	}
	found := false
	for i := range d.Grants {
		if d.Grants[i].Ref == g.Ref {
			previous := d.Grants[i]
			previousExpiry, _ := time.Parse(time.RFC3339, previous.ExpiresAt)
			if !previous.Revoked && previousExpiry.After(time.Now()) && previous.RecipientUID != g.RecipientUID {
				return ErrAuthority
			}
			d.Grants[i], found = g, true
			break
		}
	}
	if !found {
		if len(d.Grants) >= 128 {
			return ErrAuthority
		}
		d.Grants = append(d.Grants, g)
	}
	return writeDisk(d)
}

func Revoke(ref string) error {
	if os.Geteuid() != 0 || ValidateReference(ref) != nil || LoadSetup() != nil {
		return ErrAuthority
	}
	d, err := readDisk(filepath.Join(RegistryPath, GrantsName))
	if err != nil {
		return ErrAuthority
	}
	for i := range d.Grants {
		if d.Grants[i].Ref == ref {
			d.Grants[i].Revoked = true
			return writeDisk(d)
		}
	}
	return ErrAuthority
}

func LoadSetup() error {
	if safeDirectory(false) != nil {
		return ErrAuthority
	}
	b, err := readTrusted(filepath.Join(RegistryPath, SetupName), 4096)
	if err != nil {
		return ErrAuthority
	}
	canonical, err := canonicaljson.Canonicalize(b)
	if err != nil || string(canonical) != string(b) {
		return ErrAuthority
	}
	var marker struct {
		Format string `json:"format"`
		Scope  string `json:"scope"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&marker) != nil || marker.Format != setupFormat || marker.Scope != "synthetic metadata only; no secret release" || dec.Decode(new(any)) != io.EOF {
		return ErrAuthority
	}
	return nil
}

func Load() (Snapshot, error) {
	if LoadSetup() != nil {
		return Snapshot{}, ErrAuthority
	}
	d, err := readDisk(filepath.Join(RegistryPath, GrantsName))
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{grants: []Grant{}}, nil
	}
	if err != nil {
		return Snapshot{}, ErrAuthority
	}
	return Snapshot{grants: append([]Grant(nil), d.Grants...)}, nil
}

func validateGrant(g Grant, active bool, now time.Time) error {
	if ValidateReference(g.Ref) != nil || g.RecipientUID <= 0 || !digestPattern.MatchString(g.CodeSHA256) || g.Target != target || g.Purpose != purpose || g.DesiredSchemaID != desiredSchemaID || g.ProjectionSchemaID != projectionSchemaID || !digestPattern.MatchString(g.DesiredSchemaSHA256) || !digestPattern.MatchString(g.ProjectionSchemaSHA256) || !namePattern.MatchString(g.PolicyRevision) {
		return ErrAuthority
	}
	exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || exp.UTC().Format(time.RFC3339) != g.ExpiresAt {
		return ErrAuthority
	}
	if active && (g.Revoked || !exp.After(now) || exp.Sub(now) > MaxLifetime) {
		return ErrAuthority
	}
	return nil
}

func readDisk(path string) (disk, error) {
	var d disk
	b, err := readTrusted(path, maxFile)
	if err != nil {
		return d, err
	}
	canonical, err := canonicaljson.Canonicalize(b)
	if err != nil || string(canonical) != string(b) {
		return disk{}, ErrAuthority
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || d.Format != grantFormat || d.Grants == nil || len(d.Grants) > 128 || dec.Decode(new(any)) != io.EOF {
		return disk{}, ErrAuthority
	}
	seen := make(map[string]bool, len(d.Grants))
	for _, g := range d.Grants {
		if validateGrant(g, false, time.Now()) != nil || seen[g.Ref] {
			return disk{}, ErrAuthority
		}
		seen[g.Ref] = true
	}
	return d, nil
}

func writeDisk(d disk) error {
	if d.Format != grantFormat || d.Grants == nil || len(d.Grants) > 128 {
		return ErrAuthority
	}
	seen := make(map[string]bool, len(d.Grants))
	for _, g := range d.Grants {
		if validateGrant(g, false, time.Now()) != nil || seen[g.Ref] {
			return ErrAuthority
		}
		seen[g.Ref] = true
	}
	b, err := json.Marshal(d)
	if err != nil || len(b) > maxFile {
		return ErrAuthority
	}
	b, err = canonicaljson.Canonicalize(b)
	if err != nil || len(b) > maxFile {
		return ErrAuthority
	}
	return atomicFile(b)
}
