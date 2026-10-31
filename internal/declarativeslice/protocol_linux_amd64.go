//go:build linux && amd64

package declarativeslice

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

const desiredSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"enabled":{"type":"boolean"},"ref":{"type":"string","maxLength":1024}},"required":["enabled","ref"],"type":"object"}`
const projectionSchema = desiredSchema

func (s *Session) observe(ctx context.Context, in PlanInput, desired []byte) (string, error) {
	payload, _, err := s.call(ctx, "observe", "", nil, in.ResourceID)
	if err != nil {
		return "", ErrInvalid
	}
	v, err := driverprotocol.ParseJSON(payload)
	if err != nil {
		return "", ErrInvalid
	}
	env, ok := v.(map[string]any)
	if !ok || env["outcome"] != "ok" {
		return "", ErrInvalid
	}
	data, ok := env["data"].(map[string]any)
	if !ok || data["state"] != "present" {
		return "", ErrInvalid
	}
	rev, ok := data["revision"].(string)
	if !ok || len(rev) == 0 || len(rev) > 128 {
		return "", ErrInvalid
	}
	projection, ok := data["projection"].(map[string]any)
	if !ok {
		return "", ErrInvalid
	}
	if rev == "r0" {
		if projection["enabled"] != false || projection["ref"] != "" {
			return "", ErrInvalid
		}
	} else {
		if _, ok := projection["enabled"].(bool); !ok || projection["ref"] != s.grant.Ref {
			return "", ErrInvalid
		}
	}
	_ = desired
	return rev, nil
}
func (s *Session) exchange(ctx context.Context, action, operation string, p *planEntry) error {
	payload, _, err := s.call(ctx, action, operation, p, p.resource)
	if err != nil {
		return ErrInvalid
	}
	v, err := driverprotocol.ParseJSON(payload)
	if err != nil {
		return ErrInvalid
	}
	env, ok := v.(map[string]any)
	if !ok || env["outcome"] != "ok" {
		return ErrInvalid
	}
	data, ok := env["data"].(map[string]any)
	if !ok || data["verified"] != true || data["state"] != "present" {
		return ErrInvalid
	}
	rev, ok := data["applied_revision"].(string)
	if !ok || rev == "" || len(rev) > 128 || rev == p.revision {
		return ErrInvalid
	}
	if err = s.validateProjection(data["projection"], p.desired); err != nil {
		return err
	}
	p.state = "SUCCEEDED"
	return nil
}
func (s *Session) reconcile(ctx context.Context, p *planEntry) error {
	payload, _, err := s.call(ctx, "reconcile", p.operationID, p, p.resource)
	if err != nil {
		return ErrInvalid
	}
	v, err := driverprotocol.ParseJSON(payload)
	if err != nil {
		return ErrInvalid
	}
	env, ok := v.(map[string]any)
	if !ok || env["outcome"] != "ok" {
		return ErrInvalid
	}
	data, ok := env["data"].(map[string]any)
	if !ok || data["verified"] != true || data["state"] != "present" {
		return ErrInvalid
	}
	rev, ok := data["applied_revision"].(string)
	if !ok || rev == "" || rev == p.revision {
		return ErrInvalid
	}
	if err = s.validateProjection(data["projection"], p.desired); err != nil {
		return err
	}
	p.state = "SUCCEEDED"
	return nil
}
func (s *Session) validateProjection(value any, expected []byte) error {
	b, err := json.Marshal(value)
	if err != nil {
		return ErrInvalid
	}
	contract := Contract()
	if driverprotocol.ValidatePinnedValue([]byte(projectionSchema), contract.ProjectionSchemaID, contract.ProjectionSchemaSHA256, contract.Target, contract.Kind, contract.Target, contract.Kind, contract.ProjectionSchemaID, b, driverprotocol.MaxProjection) != nil {
		return ErrInvalid
	}
	if expected != nil {
		want, e := driverprotocol.ParseJSON(expected)
		got, g := driverprotocol.ParseJSON(b)
		if e != nil || g != nil || !equalJSON(want, got) {
			return ErrInvalid
		}
	}
	return nil
}
func equalJSON(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && string(x) == string(y)
}
func (s *Session) current() bool {
	return s.currentGrant(context.Background())
}

func (s *Session) call(ctx context.Context, action, operation string, p *planEntry, resource string) ([]byte, driverprotocol.StructuralRequest, error) {
	var zero driverprotocol.StructuralRequest
	if s == nil || ctx == nil || s.runner == nil || action != "observe" && action != "apply" && action != "reconcile" {
		return nil, zero, ErrInvalid
	}
	deadline := time.Now().Add(5 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if !time.Now().Before(deadline) {
		return nil, zero, ErrInvalid
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	id, err := randomID()
	if err != nil {
		return nil, zero, ErrInvalid
	}
	var desired, revision, digest, op any
	if p != nil {
		if action == "apply" {
			desired = json.RawMessage(p.desired)
			revision = p.revision
		}
		digest = p.digest
		op = operation
	}
	request := struct {
		Protocol         int    `json:"protocol"`
		RequestID        string `json:"request_id"`
		Action           string `json:"action"`
		Target           string `json:"target"`
		Kind             string `json:"kind"`
		SchemaID         string `json:"schema_id"`
		ResourceID       string `json:"resource_id"`
		Desired          any    `json:"desired"`
		ExpectedRevision any    `json:"expected_revision"`
		PlanDigest       any    `json:"plan_digest"`
		AllowedEffects   []any  `json:"allowed_effects"`
		Deadline         int64  `json:"deadline_unix_ms"`
		Max              int    `json:"max_response_bytes"`
		Operation        any    `json:"operation_id"`
	}{1, id, action, s.grant.Target, "cache", s.grant.DesiredSchemaID, resource, desired, revision, digest, []any{}, deadline.UnixMilli(), 8192, op}
	b, err := json.Marshal(request)
	if err != nil {
		return nil, zero, ErrInvalid
	}
	validated, err := driverprotocol.ValidateStructuralRequest(b)
	if err != nil {
		return nil, zero, ErrInvalid
	}
	if action == "apply" && s.capability == nil && !s.currentGrant(context.Background()) {
		return nil, zero, ErrInvalid
	}
	response, err := s.runner.Exchange(callCtx, []string{"LANG=C", "LC_ALL=C"}, "/", b)
	if err != nil {
		return nil, zero, ErrInvalid
	}
	if _, err = driverprotocol.ValidateStructuralResponse(validated, response); err != nil {
		return nil, zero, ErrInvalid
	}
	if action == "apply" && s.capability == nil && !s.currentGrant(context.Background()) {
		return nil, zero, ErrInvalid
	}
	if _, err = driverprotocol.ValidatePinnedProjection(validated, response, []byte(projectionSchema), s.grant.DesiredSchemaID, s.grant.ProjectionSchemaID, s.grant.ProjectionSchemaSHA256, s.grant.Target, "cache", s.grant.ProjectionSchemaID); err != nil {
		return nil, zero, ErrInvalid
	}
	return response, validated, nil
}
