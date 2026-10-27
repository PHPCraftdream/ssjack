package driverprotocol

import (
	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

func ValidateStructuralResponse(req StructuralRequest, data []byte) (StructuralResponse, error) {
	if req.id == "" || req.maxStructuralResponse < 1 || req.maxStructuralResponse > driverframe.MaxPayload || len(data) > req.maxStructuralResponse {
		return StructuralResponse{}, ErrInvalid
	}
	v, e := ParseJSON(data)
	if e != nil {
		return StructuralResponse{}, e
	}
	m, ok := object(v)
	if !ok || !closed(m, "protocol", "request_id", "outcome", "error_code", "data") || !intRange(m["protocol"], 1, 1) || m["request_id"] != req.id {
		return StructuralResponse{}, ErrInvalid
	}
	out, ok := stringValue(m["outcome"])
	if !ok {
		return StructuralResponse{}, ErrInvalid
	}
	d := m["data"]
	if out != "ok" {
		codes := map[string]string{"conflict": "PRECONDITION_FAILED", "unsupported": "POLICY_DENIED", "no_effect_failure": "BACKEND_FAILED", "unknown": "OUTCOME_UNKNOWN"}
		if codes[out] == "" || m["error_code"] != codes[out] || d != nil {
			return StructuralResponse{}, ErrInvalid
		}
		return StructuralResponse{}, nil
	}
	if m["error_code"] != nil {
		return StructuralResponse{}, ErrInvalid
	}
	dm, ok := object(d)
	if !ok || !responseData(req.action, dm) {
		return StructuralResponse{}, ErrInvalid
	}
	if p, ok := dm["projection"]; ok && !bounded(p, MaxProjection) {
		return StructuralResponse{}, ErrInvalid
	}
	return StructuralResponse{}, nil
}
func responseData(a string, m map[string]any) bool {
	switch a {
	case "observe":
		return closed(m, "state", "revision", "projection") && stateValue(m["state"]) && nullable(m["revision"], "revision", false) && mapObject(m["projection"])
	case "plan":
		v, ok := m["effects"].([]any)
		return closed(m, "effects", "precondition") && nullable(m["precondition"], "revision", false) && ok && len(v) <= 256 && effectList(v)
	case "apply":
		_, b := m["verified"].(bool)
		return closed(m, "state", "applied_revision", "verified", "projection") && stateValue(m["state"]) && nullable(m["applied_revision"], "revision", false) && b && mapObject(m["projection"])
	case "cancel":
		s, ok := stringValue(m["cancellation"])
		return closed(m, "cancellation") && ok && (s == "confirmed" || s == "unsupported" || s == "pending")
	case "reconcile":
		_, b := m["verified"].(bool)
		return closed(m, "state", "applied_revision", "delivered_revision", "observed_revision", "adopted_revision", "verified", "projection") && stateValue(m["state"]) && nullable(m["applied_revision"], "revision", false) && nullable(m["delivered_revision"], "revision", false) && nullable(m["observed_revision"], "revision", false) && nullable(m["adopted_revision"], "revision", false) && b && mapObject(m["projection"])
	}
	return false
}
func stateValue(v any) bool {
	s, ok := stringValue(v)
	return ok && (s == "present" || s == "absent" || s == "unknown")
}
