//go:build linux && amd64

package declarativeslice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeschemas"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/immutableexec"
)

const maxDocument = 32768

var ErrInvalid = errors.New("invalid declarative slice request")

type Session struct {
	mu       sync.Mutex
	id       string
	runner   *immutableexec.Runner
	grant    declarativeauthority.Grant
	plans    map[string]*planEntry
	requests map[string]string
	closed   bool
}
type planEntry struct {
	desired                       []byte
	revision, digest, resource    string
	expires                       time.Time
	requestID, operationID, state string
}
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
type ContractInfo struct{ Target, Kind, DesiredSchemaID, DesiredSchemaSHA256, ProjectionSchemaID, ProjectionSchemaSHA256 string }

func Contract() ContractInfo {
	return ContractInfo{Target: "target", Kind: "cache", DesiredSchemaID: "cache.desired", DesiredSchemaSHA256: fixedSchemaDigest(desiredSchema), ProjectionSchemaID: "cache.projection", ProjectionSchemaSHA256: fixedSchemaDigest(projectionSchema)}
}
func New() (*Session, error) {
	if os.Geteuid() == 0 {
		return nil, declarativeauthority.ErrAuthority
	}
	snap, err := declarativeauthority.Load()
	if err != nil {
		return nil, declarativeauthority.ErrAuthority
	}
	contract := Contract()
	if contract.DesiredSchemaSHA256 == "" || contract.ProjectionSchemaSHA256 == "" || driverprotocol.ValidateSchemaDocument([]byte(desiredSchema), contract.DesiredSchemaID, contract.DesiredSchemaSHA256) != nil || driverprotocol.ValidateSchemaDocument([]byte(projectionSchema), contract.ProjectionSchemaID, contract.ProjectionSchemaSHA256) != nil {
		return nil, declarativeauthority.ErrAuthority
	}
	var g declarativeauthority.Grant
	found := false
	for _, candidate := range snap.Grants() {
		if candidate.Active(time.Now()) && candidate.Target == contract.Target && candidate.RecipientUID == os.Geteuid() {
			if found {
				return nil, declarativeauthority.ErrAuthority
			}
			g = candidate
			found = true
		}
	}
	if !found || g.RecipientUID != os.Geteuid() || g.DesiredSchemaID != contract.DesiredSchemaID || g.DesiredSchemaSHA256 != contract.DesiredSchemaSHA256 || g.ProjectionSchemaID != contract.ProjectionSchemaID || g.ProjectionSchemaSHA256 != contract.ProjectionSchemaSHA256 {
		return nil, declarativeauthority.ErrAuthority
	}
	code, err := declarativeauthority.CodeDigest(declarativeauthority.DriverPath)
	if err != nil || code != g.CodeSHA256 {
		return nil, declarativeauthority.ErrAuthority
	}
	b, err := hex.DecodeString(code)
	if err != nil || len(b) != sha256.Size {
		return nil, declarativeauthority.ErrAuthority
	}
	var pin [sha256.Size]byte
	copy(pin[:], b)
	runner, err := immutableexec.Bind(declarativeauthority.DriverPath, pin)
	if err != nil {
		return nil, declarativeauthority.ErrAuthority
	}
	id, err := randomID()
	if err != nil {
		_ = runner.Close()
		return nil, ErrInvalid
	}
	return &Session{id: id, runner: runner, grant: g, plans: map[string]*planEntry{}, requests: map[string]string{}}, nil
}
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.runner != nil {
		return s.runner.Close()
	}
	return nil
}
func (s *Session) Describe() ([]declarativeschemas.Tool, error) {
	if s == nil {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrInvalid
	}
	tools, err := declarativeschemas.Catalog()
	if err != nil {
		return nil, ErrInvalid
	}
	out := make([]declarativeschemas.Tool, 0, 2)
	for _, tool := range tools {
		if tool.Name == "resource_plan" || tool.Name == "plan_apply" {
			out = append(out, tool)
		}
	}
	if len(out) != 2 {
		return nil, ErrInvalid
	}
	return out, nil
}
func (s *Session) Plan(ctx context.Context, input []byte) (PlanResult, error) {
	var out PlanResult
	if s == nil || ctx == nil {
		return out, ErrInvalid
	}
	var in PlanInput
	if decodeInput(input, &in) != nil || !validRequestID(in.RequestID) {
		return out, ErrInvalid
	}
	if in.Target != s.grant.Target || in.DriverID != "synthetic" || in.Kind != "cache" || in.SchemaID != s.grant.DesiredSchemaID || in.ResourceID != "synthetic" {
		return out, ErrInvalid
	}
	desired, err := json.Marshal(in.Desired)
	if err != nil || len(desired) > maxDocument || validateDesired(desired, s.grant.Ref) != nil || driverprotocol.ValidatePinnedValue([]byte(desiredSchema), s.grant.DesiredSchemaID, s.grant.DesiredSchemaSHA256, s.grant.Target, "cache", s.grant.Target, "cache", s.grant.DesiredSchemaID, desired, driverprotocol.MaxDesired) != nil {
		return out, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.plans) >= 128 || !s.currentGrant() {
		return out, ErrInvalid
	}
	revision, err := s.observe(ctx, in, desired)
	if err != nil {
		return out, ErrInvalid
	}
	id, err := randomID()
	if err != nil {
		return out, ErrInvalid
	}
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	grantExp, _ := time.Parse(time.RFC3339, s.grant.ExpiresAt)
	if expiry.After(grantExp) {
		expiry = grantExp.Truncate(time.Second)
	}
	if !expiry.After(time.Now()) {
		return out, ErrInvalid
	}
	binding := struct {
		Session  string                     `json:"session"`
		PlanID   string                     `json:"plan_id"`
		Grant    declarativeauthority.Grant `json:"grant"`
		Desired  json.RawMessage            `json:"desired"`
		Resource string                     `json:"resource_id"`
		Revision string                     `json:"observed_revision"`
		Expires  string                     `json:"expires_at"`
	}{s.id, id, s.grant, desired, in.ResourceID, revision, expiry.UTC().Format(time.RFC3339)}
	raw, err := json.Marshal(binding)
	if err != nil {
		return out, ErrInvalid
	}
	canon, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return out, ErrInvalid
	}
	sum := sha256.Sum256(canon)
	digest := hex.EncodeToString(sum[:])
	s.plans[id] = &planEntry{desired: desired, revision: revision, digest: digest, resource: in.ResourceID, expires: expiry}
	return PlanResult{PlanID: id, Digest: digest, ExpiresAt: expiry.UTC().Format(time.RFC3339), Effects: []Effect{{Class: "metadata", SummaryID: "cache.update", Destructive: false}}, Precondition: &revision}, nil
}
func (s *Session) Apply(ctx context.Context, input []byte) (ApplyResult, error) {
	var out ApplyResult
	if s == nil || ctx == nil {
		return out, ErrInvalid
	}
	var in ApplyInput
	if decodeInput(input, &in) != nil || !validID(in.PlanID) || !validRequestID(in.RequestID) {
		return out, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.currentGrant() {
		return out, ErrInvalid
	}
	p := s.plans[in.PlanID]
	if p == nil {
		return out, ErrInvalid
	}
	if p.operationID != "" {
		if p.requestID != in.RequestID {
			return out, ErrInvalid
		}
		if p.state == "FAILED" || p.state == "SUCCEEDED" {
			return ApplyResult{OperationID: p.operationID, State: p.state}, nil
		}
		if err := s.reconcile(ctx, p); err != nil {
			return ApplyResult{OperationID: p.operationID, State: "UNKNOWN"}, nil
		}
		return ApplyResult{OperationID: p.operationID, State: p.state}, nil
	}
	if !time.Now().Before(p.expires) || s.requests[in.RequestID] != "" {
		return out, ErrInvalid
	}
	operation, err := randomID()
	if err != nil {
		return out, ErrInvalid
	}
	p.operationID, p.requestID, p.state = operation, in.RequestID, "UNKNOWN"
	s.requests[in.RequestID] = in.PlanID
	observed, err := s.observe(ctx, PlanInput{Target: s.grant.Target, DriverID: "synthetic", Kind: "cache", SchemaID: s.grant.DesiredSchemaID, ResourceID: p.resource}, p.desired)
	if err != nil || observed != p.revision {
		p.state = "FAILED"
		return ApplyResult{OperationID: operation, State: "FAILED"}, nil
	}
	if err = s.exchange(ctx, "apply", operation, p); err != nil {
		if s.reconcile(ctx, p) == nil {
			return ApplyResult{OperationID: operation, State: p.state}, nil
		}
		return ApplyResult{OperationID: operation, State: "UNKNOWN"}, nil
	}
	p.state = "SUCCEEDED"
	return ApplyResult{OperationID: operation, State: p.state}, nil
}
func (s *Session) currentGrant() bool {
	snap, err := declarativeauthority.Load()
	if err != nil {
		return false
	}
	for _, g := range snap.Grants() {
		if g == s.grant && g.Active(time.Now()) {
			d, e := declarativeauthority.CodeDigest(declarativeauthority.DriverPath)
			return e == nil && d == g.CodeSHA256
		}
	}
	return false
}
