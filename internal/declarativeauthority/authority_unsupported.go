//go:build !linux || !amd64

package declarativeauthority

import (
	"errors"
	"time"
)

const (
	RegistryPath = "/etc/ssjack/declarative"
	SetupName    = "setup.json"
	GrantsName   = "grants.json"
	DriverPath   = "/usr/libexec/ssjack-synthetic-driver"
	StatePath    = "/var/lib/ssjack/synthetic"
	MaxLifetime  = 30 * 24 * time.Hour
)

var ErrAuthority = errors.New("declarative authority unavailable or invalid")

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
type Snapshot struct{}

func (Snapshot) Grants() []Grant        { return nil }
func ValidateReference(string) error    { return ErrAuthority }
func (Grant) Active(time.Time) bool     { return false }
func Setup() error                      { return ErrAuthority }
func Register(Grant) error              { return ErrAuthority }
func Revoke(string) error               { return ErrAuthority }
func LoadSetup() error                  { return ErrAuthority }
func Load() (Snapshot, error)           { return Snapshot{}, ErrAuthority }
func CodeDigest(string) (string, error) { return "", ErrAuthority }
func PrepareState(int) error            { return ErrAuthority }
