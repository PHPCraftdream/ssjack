package driverprotocol

import (
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/drivertext"
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
	b, err := canonicalValueBytes(projection)
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

// canonicalBytes is package-internal serialization for already bounded protocol values.
func canonicalBytes(v any) ([]byte, error) { return appendCanonicalValue(nil, v) }
func appendCanonicalValue(dst []byte, value any) ([]byte, error) {
	switch x := value.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		return appendCanonicalBool(dst, x), nil
	case int64:
		return strconv.AppendInt(dst, x, 10), nil
	case string:
		return appendCanonicalString(dst, x)
	case []any:
		return appendCanonicalArray(dst, x)
	case map[string]any:
		return appendCanonicalObject(dst, x)
	default:
		return nil, ErrInvalid
	}
}
func appendCanonicalBool(dst []byte, value bool) []byte {
	if value {
		return append(dst, "true"...)
	}
	return append(dst, "false"...)
}
func appendCanonicalString(dst []byte, value string) ([]byte, error) {
	b, err := json.Marshal(value)
	return append(dst, b...), err
}
func appendCanonicalArray(dst []byte, values []any) ([]byte, error) {
	dst = append(dst, '[')
	for i, value := range values {
		if i > 0 {
			dst = append(dst, ',')
		}
		var err error
		dst, err = appendCanonicalValue(dst, value)
		if err != nil {
			return nil, err
		}
	}
	return append(dst, ']'), nil
}
func appendCanonicalObject(dst []byte, values map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortStrings(keys)
	dst = append(dst, '{')
	for i, key := range keys {
		if i > 0 {
			dst = append(dst, ',')
		}
		b, _ := json.Marshal(key)
		dst = append(dst, b...)
		dst = append(dst, ':')
		var err error
		dst, err = appendCanonicalValue(dst, values[key])
		if err != nil {
			return nil, err
		}
	}
	return append(dst, '}'), nil
}
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
func hasSchemaSerializationSensitiveString(v any) bool {
	switch x := v.(type) {
	case string:
		for _, r := range x {
			if r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029' {
				return true
			}
		}
	case map[string]any:
		for k, value := range x {
			if hasSchemaSerializationSensitiveString(k) || hasSchemaSerializationSensitiveString(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if hasSchemaSerializationSensitiveString(value) {
				return true
			}
		}
	}
	return false
}
func canonicalValueBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(b)
}

func bounded(v any, n int) bool { b, e := canonicalValueBytes(v); return e == nil && len(b) <= n }
func matches(s, v any, d int) bool {
	if d > 16 {
		return false
	}
	m, ok := object(s)
	if !ok || !matchesEnum(m, v) {
		return false
	}
	if x, ok := m["const"]; ok && !jsonEqual(x, v) {
		return false
	}
	typ := ""
	nullable := false
	if t, present := m["type"]; present {
		typ, nullable, ok = schemaType(t)
		if !ok {
			return false
		}
	} else {
		if !hasObjectSchemaKeyword(m) {
			return true
		}
		if _, ok := object(v); !ok {
			return true
		}
		typ = "object"
	}
	if nullable && v == nil {
		return true
	}
	switch typ {
	case "object":
		x, ok := object(v)
		p, _ := object(m["properties"])
		if !ok || len(x) != len(p) {
			return false
		}
		if q, ok := m["minProperties"].(int64); ok && int64(len(x)) < q {
			return false
		}
		if q, ok := m["maxProperties"].(int64); ok && int64(len(x)) > q {
			return false
		}
		for k, value := range x {
			q, yes := p[k]
			if !yes || !matches(q, value, d+1) {
				return false
			}
		}
		return true
	case "array":
		a, ok := v.([]any)
		if !ok || (m["minItems"] != nil && int64(len(a)) < m["minItems"].(int64)) || (m["maxItems"] != nil && int64(len(a)) > m["maxItems"].(int64)) {
			return false
		}
		for i, x := range a {
			if !matches(m["items"], x, d+1) {
				return false
			}
			if unique, _ := m["uniqueItems"].(bool); unique {
				for _, previous := range a[:i] {
					if jsonEqual(x, previous) {
						return false
					}
				}
			}
		}
		return true
	case "string":
		x, ok := v.(string)
		if !ok || !drivertext.ValidText(x) {
			return false
		}
		n := int64(utf8.RuneCountInString(x))
		if q, ok := m["minLength"].(int64); ok && n < q {
			return false
		}
		if q, ok := m["maxLength"].(int64); ok && n > q {
			return false
		}
		return true
	case "integer":
		x, ok := v.(int64)
		if !ok {
			return false
		}
		if q, ok := m["minimum"].(int64); ok && x < q {
			return false
		}
		if q, ok := m["maximum"].(int64); ok && x > q {
			return false
		}
		if q, ok := m["exclusiveMinimum"].(int64); ok && x <= q {
			return false
		}
		if q, ok := m["exclusiveMaximum"].(int64); ok && x >= q {
			return false
		}
		if q, ok := m["multipleOf"].(int64); ok && (q <= 0 || x%q != 0) {
			return false
		}
		return true
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	}
	return false
}
