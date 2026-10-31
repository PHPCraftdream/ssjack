//go:build !linux || !amd64

package declarativeslice

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/declarativeschemas"
)

var ErrInvalid = errors.New("invalid declarative slice request")

type Session struct{}
type PlanInput struct {
	Target     string         `json:"target"`
	DriverID   string         `json:"driver_id"`
	Kind       string         `json:"kind"`
	SchemaID   string         `json:"schema_id"`
	ResourceID string         `json:"resource_id"`
	Desired    map[string]any `json:"desired"`
	RequestID  string         `json:"request_id"`
}
type PlanResult struct {
	PlanID       string   `json:"plan_id"`
	Digest       string   `json:"digest"`
	ExpiresAt    string   `json:"expires_at"`
	Effects      []Effect `json:"effects"`
	Precondition *string  `json:"precondition"`
}
type Effect struct {
	Class       string `json:"class"`
	SummaryID   string `json:"summary_id"`
	Destructive bool   `json:"destructive"`
}
type ApplyInput struct {
	PlanID    string `json:"plan_id"`
	RequestID string `json:"request_id"`
}
type ApplyResult struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
}
type ContractInfo struct {
	Target                 string
	Kind                   string
	DesiredSchemaID        string
	DesiredSchemaSHA256    string
	ProjectionSchemaID     string
	ProjectionSchemaSHA256 string
}

func New() (*Session, error)                                        { return nil, ErrInvalid }
func (*Session) Close() error                                       { return ErrInvalid }
func (*Session) Describe() ([]declarativeschemas.Tool, error)       { return nil, ErrInvalid }
func (*Session) Plan(context.Context, []byte) (PlanResult, error)   { return PlanResult{}, ErrInvalid }
func (*Session) Apply(context.Context, []byte) (ApplyResult, error) { return ApplyResult{}, ErrInvalid }
func Contract() ContractInfo                                        { return ContractInfo{} }
