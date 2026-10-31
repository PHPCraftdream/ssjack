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

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/declarativeschemas"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/immutableexec"
)

const maxDocument = 32768
const DeliveryProtocol = "ssjack-synthetic-confidential-delivery-1"

var ErrInvalid = errors.New("invalid declarative slice request")

type Session struct {
	mu         sync.Mutex
	id         string
	runner     *immutableexec.Runner
	grant      declarativeauthority.Grant
	capability *appstorecrypto.DeliveryCapability
	plans      map[string]*planEntry
	requests   map[string]string
	closed     bool
}
type planEntry struct {
	desired                                 []byte
	revision, digest, resource              string
	expires                                 time.Time
	requestID, operationID, state, delivery string
	deliveryPlan                            *appstorecrypto.DeliveryPlan
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
	Delivery    string `json:"delivery,omitempty"`
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
	if !validContract(contract) {
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
	return newSession(g, nil)
}
func NewDelivery(ctx context.Context, installation *appstorecrypto.Installation, ref appstoreref.Ref) (*Session, error) {
	if ctx == nil || !ref.Valid() || os.Geteuid() == 0 {
		return nil, ErrInvalid
	}
	capability, err := appstorecrypto.NewDeliveryCapability(ctx, installation, ref)
	if err != nil {
		return nil, ErrInvalid
	}
	g, r := capability.Metadata()
	contract := Contract()
	if r != ref || g.Ref == "" || g.Target != contract.Target || g.DesiredSchemaID != contract.DesiredSchemaID || g.DesiredSchemaSHA256 != contract.DesiredSchemaSHA256 || g.ProjectionSchemaID != contract.ProjectionSchemaID || g.ProjectionSchemaSHA256 != contract.ProjectionSchemaSHA256 || g.PolicyRevision != declarativeauthority.DeliveryPolicyRevision {
		_ = capability.Close()
		return nil, ErrInvalid
	}
	if err = capability.Check(ctx); err != nil {
		_ = capability.Close()
		return nil, ErrInvalid
	}
	private := declarativeauthority.Grant{RecipientUID: g.RecipientUID, Ref: g.Ref, CodeSHA256: g.DriverCodeSHA256, Target: g.Target, Purpose: g.Purpose, DesiredSchemaID: g.DesiredSchemaID, DesiredSchemaSHA256: g.DesiredSchemaSHA256, ProjectionSchemaID: g.ProjectionSchemaID, ProjectionSchemaSHA256: g.ProjectionSchemaSHA256, PolicyRevision: g.PolicyRevision, ExpiresAt: g.ExpiresAt, Revoked: g.Revoked}
	s, err := newSession(private, capability)
	if err != nil {
		_ = capability.Close()
		return nil, err
	}
	return s, nil
}
func validContract(c ContractInfo) bool {
	return c.DesiredSchemaSHA256 != "" && c.ProjectionSchemaSHA256 != "" && driverprotocol.ValidateSchemaDocument([]byte(desiredSchema), c.DesiredSchemaID, c.DesiredSchemaSHA256) == nil && driverprotocol.ValidateSchemaDocument([]byte(projectionSchema), c.ProjectionSchemaID, c.ProjectionSchemaSHA256) == nil
}
func newSession(g declarativeauthority.Grant, capability *appstorecrypto.DeliveryCapability) (*Session, error) {
	c := Contract()
	if !validContract(c) || g.DesiredSchemaID != c.DesiredSchemaID || g.DesiredSchemaSHA256 != c.DesiredSchemaSHA256 || g.ProjectionSchemaID != c.ProjectionSchemaID || g.ProjectionSchemaSHA256 != c.ProjectionSchemaSHA256 {
		return nil, declarativeauthority.ErrAuthority
	}
	code, err := declarativeauthority.CodeDigest(declarativeauthority.DriverPath)
	if err != nil || code != g.CodeSHA256 {
		if capability != nil {
			_ = capability.Close()
		}
		return nil, declarativeauthority.ErrAuthority
	}
	b, err := hex.DecodeString(code)
	if err != nil || len(b) != sha256.Size {
		if capability != nil {
			_ = capability.Close()
		}
		return nil, declarativeauthority.ErrAuthority
	}
	var pin [sha256.Size]byte
	copy(pin[:], b)
	runner, err := immutableexec.Bind(declarativeauthority.DriverPath, pin)
	if err != nil {
		if capability != nil {
			_ = capability.Close()
		}
		return nil, declarativeauthority.ErrAuthority
	}
	id, err := randomID()
	if err != nil {
		_ = runner.Close()
		if capability != nil {
			_ = capability.Close()
		}
		return nil, ErrInvalid
	}
	return &Session{id: id, runner: runner, grant: g, capability: capability, plans: map[string]*planEntry{}, requests: map[string]string{}}, nil
}
func (s *Session) IsDelivery() bool { return s != nil && s.capability != nil }
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	// Cancel an in-flight delivery before waiting for the session lock, which
	// Apply holds while delivering.
	if s.capability != nil {
		_ = s.capability.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var e error
	if s.runner != nil {
		e = s.runner.Close()
	}
	return e
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
	for _, t := range tools {
		if t.Name == "resource_plan" || t.Name == "plan_apply" {
			out = append(out, t)
		}
	}
	if len(out) != 2 {
		return nil, ErrInvalid
	}
	return out, nil
}
func (s *Session) currentGrant(ctx context.Context) bool {
	if s.capability != nil {
		return s.capability.Check(ctx) == nil
	}
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
func (s *Session) Plan(ctx context.Context, input []byte) (PlanResult, error) {
	var out PlanResult
	if s == nil || ctx == nil {
		return out, ErrInvalid
	}
	var in PlanInput
	if decodeInput(input, &in) != nil || !validRequestID(in.RequestID) || in.Target != s.grant.Target || in.DriverID != "synthetic" || in.Kind != "cache" || in.SchemaID != s.grant.DesiredSchemaID || in.ResourceID != "synthetic" {
		return out, ErrInvalid
	}
	desired, err := json.Marshal(in.Desired)
	if err != nil || len(desired) > maxDocument || driverprotocol.ValidatePinnedValue([]byte(desiredSchema), s.grant.DesiredSchemaID, s.grant.DesiredSchemaSHA256, s.grant.Target, "cache", s.grant.Target, "cache", s.grant.DesiredSchemaID, desired, driverprotocol.MaxDesired) != nil || validateDesired(desired, s.grant.Ref) != nil {
		return out, ErrInvalid
	}
	if s.capability != nil {
		var requested struct {
			Enabled bool   `json:"enabled"`
			Ref     string `json:"ref"`
		}
		if json.Unmarshal(desired, &requested) != nil || !requested.Enabled || requested.Ref != s.grant.Ref {
			return out, ErrInvalid
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.plans) >= 128 || !s.currentGrant(ctx) {
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
		Session  string          `json:"session"`
		PlanID   string          `json:"plan_id"`
		Grant    any             `json:"grant"`
		Desired  json.RawMessage `json:"desired"`
		Resource string          `json:"resource_id"`
		Revision string          `json:"observed_revision"`
		Expires  string          `json:"expires_at"`
		Policy   string          `json:"policy"`
		Consumer string          `json:"consumer_code"`
	}{s.id, id, s.grant, desired, in.ResourceID, revision, expiry.UTC().Format(time.RFC3339), s.grant.PolicyRevision, "/usr/libexec/ssjack-synthetic-consumer"}
	if s.capability != nil {
		g, _ := s.capability.Metadata()
		binding.Grant = g
	}
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
	p := &planEntry{desired: desired, revision: revision, digest: digest, resource: in.ResourceID, expires: expiry}
	class, summary := "metadata", "cache.update"
	if s.capability != nil {
		deadline := p.expires
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		p.deliveryPlan = s.capability.Prepare(ctx, appstorecrypto.OperationBinding{SessionID: s.id, PlanID: id, Digest: digest, ObservedRevision: revision, Policy: s.grant.PolicyRevision, Deadline: deadline})
		if p.deliveryPlan == nil {
			return out, ErrInvalid
		}
	}
	s.plans[id] = p
	if s.capability != nil {
		class, summary = "confidential_delivery", "synthetic.confidential_delivery"
	}
	return PlanResult{PlanID: id, Digest: digest, ExpiresAt: expiry.UTC().Format(time.RFC3339), Effects: []Effect{{Class: class, SummaryID: summary, Destructive: false}}, Precondition: &revision}, nil
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
	if s.closed || !s.currentGrant(ctx) {
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
		if p.delivery != "" {
			if p.delivery == "RECEIVED" && p.state == "UNKNOWN" {
				if s.reconcile(ctx, p) != nil {
					return ApplyResult{OperationID: p.operationID, State: "UNKNOWN", Delivery: p.delivery}, nil
				}
			}
			return ApplyResult{OperationID: p.operationID, State: p.state, Delivery: p.delivery}, nil
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
	applyCtx, cancel := context.WithDeadline(ctx, p.expires)
	defer cancel()
	lease, err := declarativeauthority.AcquireTarget(applyCtx)
	if err != nil {
		p.state = "FAILED"
		if s.capability != nil {
			p.delivery = "WITHHELD"
			return ApplyResult{OperationID: operation, State: p.state, Delivery: p.delivery}, nil
		}
		return ApplyResult{OperationID: operation, State: p.state}, nil
	}
	defer lease.Close()
	observed, err := s.observe(applyCtx, PlanInput{Target: s.grant.Target, DriverID: "synthetic", Kind: "cache", SchemaID: s.grant.DesiredSchemaID, ResourceID: p.resource}, p.desired)
	if err != nil || observed != p.revision {
		p.state = "FAILED"
		if s.capability != nil {
			p.delivery = "WITHHELD"
		}
		return ApplyResult{OperationID: operation, State: "FAILED", Delivery: p.delivery}, nil
	}
	if s.capability != nil {
		if err = s.exchange(applyCtx, "apply", operation, p); err != nil {
			if s.reconcile(applyCtx, p) != nil {
				p.state, p.delivery = "UNKNOWN", "WITHHELD"
				return ApplyResult{OperationID: operation, State: p.state, Delivery: p.delivery}, nil
			}
		}
		if lease.Admit(applyCtx, p.revision, operation, p.digest) != nil {
			p.state, p.delivery = "UNKNOWN", "WITHHELD"
			return ApplyResult{OperationID: operation, State: p.state, Delivery: p.delivery}, nil
		}
		result := s.capability.Deliver(applyCtx, p.deliveryPlan, operation, lease)
		switch result.Status {
		case appstorecrypto.DeliveryReceived:
			p.delivery, p.state = "RECEIVED", "SUCCEEDED"
		case appstorecrypto.DeliveryUnknown:
			p.delivery, p.state = "UNKNOWN", "UNKNOWN"
		default:
			p.delivery, p.state = "WITHHELD", "UNKNOWN"
		}
		return ApplyResult{OperationID: operation, State: p.state, Delivery: p.delivery}, nil
	}
	if err = s.exchange(applyCtx, "apply", operation, p); err != nil {
		if s.reconcile(applyCtx, p) == nil {
			return ApplyResult{OperationID: operation, State: p.state}, nil
		}
		return ApplyResult{OperationID: operation, State: "UNKNOWN"}, nil
	}
	p.state = "SUCCEEDED"
	return ApplyResult{OperationID: operation, State: p.state}, nil
}
