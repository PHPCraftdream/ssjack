package driverprotocol

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

func ReadStructuralRequest(r io.Reader) (StructuralRequest, error) {
	b, e := driverframe.Read(r)
	if e != nil {
		return StructuralRequest{}, e
	}
	if e = driverframe.RequireEOF(r); e != nil {
		return StructuralRequest{}, e
	}
	return ValidateStructuralRequest(b)
}
func ReadStructuralResponse(q StructuralRequest, r io.Reader) (StructuralResponse, error) {
	b, e := driverframe.Read(r)
	if e != nil {
		return StructuralResponse{}, e
	}
	if e = driverframe.RequireEOF(r); e != nil {
		return StructuralResponse{}, e
	}
	return ValidateStructuralResponse(q, b)
}

// WriteStructuralFrame checks only bounded JSON syntax; it does not structurally validate a request or response.
func WriteStructuralFrame(w io.Writer, payload []byte) error {
	if _, e := ParseJSON(payload); e != nil {
		return ErrInvalid
	}
	return driverframe.Write(w, payload)
}

func ValidatePinnedProjection(req StructuralRequest, data, schemaBytes []byte, requestSchemaID, expectedProjectionID, expectedDigest, target, kind, actualID string) (StructuralResponse, error) {
	r, err := ValidateStructuralResponse(req, data)
	if err != nil {
		return StructuralResponse{}, err
	}
	if req.action != "observe" && req.action != "apply" && req.action != "reconcile" {
		return StructuralResponse{}, ErrInvalid
	}
	if target != req.target || kind != req.kind || requestSchemaID != req.schemaID {
		return StructuralResponse{}, ErrSchema
	}
	v, err := ParseJSON(data)
	if err != nil {
		return StructuralResponse{}, err
	}
	m, _ := object(v)
	if m["outcome"] != "ok" {
		return StructuralResponse{}, ErrInvalid
	}
	d, _ := object(m["data"])
	projection, ok := d["projection"]
	if !ok {
		return StructuralResponse{}, ErrInvalid
	}
	b, err := canonicalBytes(projection)
	if err != nil {
		return StructuralResponse{}, ErrInvalid
	}
	if err = ValidatePinnedValue(schemaBytes, expectedProjectionID, expectedDigest, target, kind, req.target, req.kind, actualID, b, MaxProjection); err != nil {
		return StructuralResponse{}, err
	}
	return r, nil
}
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

// Re-encode with sorted ASCII keys, no whitespace, and shortest integer forms before applying canonical-byte limits.
func canonicalBytes(v any) ([]byte, error) { return appendCanonical(nil, v) }
func appendCanonical(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case int64:
		return strconv.AppendInt(dst, x, 10), nil
	case string:
		b, e := json.Marshal(x)
		return append(dst, b...), e
	case []any:
		dst = append(dst, '[')
		for i, item := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var e error
			dst, e = appendCanonical(dst, item)
			if e != nil {
				return nil, e
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			b, _ := json.Marshal(k)
			dst = append(dst, b...)
			dst = append(dst, ':')
			var e error
			dst, e = appendCanonical(dst, x[k])
			if e != nil {
				return nil, e
			}
		}
		return append(dst, '}'), nil
	}
	return nil, ErrInvalid
}
func hasHTMLSensitiveString(v any) bool {
	switch x := v.(type) {
	case string:
		for _, r := range x {
			if r == '<' || r == '>' || r == '&' {
				return true
			}
		}
	case map[string]any:
		for k, value := range x {
			if hasHTMLSensitiveString(k) || hasHTMLSensitiveString(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if hasHTMLSensitiveString(value) {
				return true
			}
		}
	}
	return false
}
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
func bounded(v any, n int) bool { b, e := canonicalBytes(v); return e == nil && len(b) <= n }
