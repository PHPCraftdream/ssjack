//go:build !linux || !amd64

package declarativeauthority

import (
	"context"
	"errors"
	"time"
)

const (
	RegistryPath           = "/etc/ssjack/declarative"
	SetupName              = "setup.json"
	GrantsName             = "grants.json"
	DriverPath             = "/usr/libexec/ssjack-synthetic-driver"
	ConsumerPath           = "/usr/libexec/ssjack-synthetic-consumer"
	DeliveryTarget         = "target"
	DeliveryPurpose        = "synthetic-confidential-delivery"
	DeliveryPolicyRevision = "synthetic-delivery-v1"
	StatePath              = "/var/lib/ssjack/synthetic"
	MaxLifetime            = 30 * 24 * time.Hour
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
type DeliverySnapshot struct{}

func (DeliverySnapshot) Grants() []DeliveryGrant { return nil }
func (DeliveryGrant) Active(time.Time) bool      { return false }
func RegisterDelivery(DeliveryGrant) error       { return ErrAuthority }
func RevokeDelivery(string) error                { return ErrAuthority }
func LoadDelivery(string, int, time.Time) (DeliverySnapshot, error) {
	return DeliverySnapshot{}, ErrAuthority
}
func DeliveryCodeDigest() (string, error)   { return "", ErrAuthority }
func DeliveryDriverDigest() (string, error) { return "", ErrAuthority }

// TargetLease is unavailable on unsupported platforms.
type TargetLease struct{}

func AcquireTarget(context.Context) (*TargetLease, error)                { return nil, ErrAuthority }
func (*TargetLease) Admit(context.Context, string, string, string) error { return ErrAuthority }
func (*TargetLease) Check(context.Context, string, string, string) error { return ErrAuthority }
func (*TargetLease) CheckReference(context.Context, string, string, string, string) error {
	return ErrAuthority
}
func (*TargetLease) Close() error { return ErrAuthority }
