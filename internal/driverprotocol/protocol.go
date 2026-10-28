package driverprotocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

const MaxDepth = 16
const MaxNodes = 4096
const MaxDesired = 32768
const MaxProjection = 8192

var ErrInvalid = errors.New("invalid driver protocol JSON")

type StructuralRequest struct {
	id, action, target, kind, schemaID string
	maxStructuralResponse              int
}
type StructuralResponse struct{}

// Action returns the validated request action.
func (q StructuralRequest) Action() string { return q.action }

// ParseJSON accepts bounded printable-ASCII JSON, rejecting duplicate keys and non-safe integers.
func ParseJSON(data []byte) (any, error) {
	if len(data) == 0 || len(data) > driverframe.MaxPayload || !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	n := 0
	v, e := parseValue(d, 0, &n)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}
func parseValue(d *json.Decoder, depth int, n *int) (any, error) {
	t, e := d.Token()
	if e != nil {
		return nil, ErrInvalid
	}
	*n++
	if depth > MaxDepth || *n > MaxNodes {
		return nil, ErrInvalid
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			for d.More() {
				k0, e := d.Token()
				if e != nil {
					return nil, ErrInvalid
				}
				k, ok := k0.(string)
				if !ok || !ascii(k) {
					return nil, ErrInvalid
				}
				if _, ok = m[k]; ok {
					return nil, ErrInvalid
				}
				v, e := parseValue(d, depth+1, n)
				if e != nil {
					return nil, e
				}
				m[k] = v
				if len(m) > 128 {
					return nil, ErrInvalid
				}
			}
			if _, e = d.Token(); e != nil {
				return nil, ErrInvalid
			}
			return m, nil
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				v, e := parseValue(d, depth+1, n)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
				if len(a) > 256 {
					return nil, ErrInvalid
				}
			}
			if _, e = d.Token(); e != nil {
				return nil, ErrInvalid
			}
			return a, nil
		}
		return nil, ErrInvalid
	case string:
		if !ascii(x) {
			return nil, ErrInvalid
		}
		return x, nil
	case json.Number:
		s := string(x)
		i, e := strconv.ParseInt(s, 10, 64)
		if e != nil || s == "-0" || i > 9007199254740991 || i < -9007199254740991 {
			return nil, ErrInvalid
		}
		return i, nil
	case bool, nil:
		return x, nil
	}
	return nil, ErrInvalid
}
func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func object(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func stringValue(v any) (string, bool)    { s, ok := v.(string); return s, ok }
func intRange(v any, min, max int64) bool { i, ok := v.(int64); return ok && i >= min && i <= max }
func closed(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func idValue(v any) bool {
	s, ok := stringValue(v)
	if !ok || len(s) != 22 {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == s
}
func grammar(s, kind string) bool {
	if len(s) == 0 {
		return false
	}
	switch kind {
	case "name":
		if len(s) > 64 {
			return false
		}
		for i, c := range s {
			if !(c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-')) {
				return false
			}
		}
		return true
	case "resource":
		if len(s) > 128 {
			return false
		}
		for i, c := range s {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == ':' || c == '-')) {
				return false
			}
		}
		return true
	case "revision":
		if len(s) > 128 {
			return false
		}
		for _, c := range s {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == ':' || c == '-') {
				return false
			}
		}
		return true
	case "digest":
		if len(s) != 64 {
			return false
		}
		for _, c := range s {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	return false
}
func nullable(v any, kind string, required bool) bool {
	if v == nil {
		return !required
	}
	s, ok := stringValue(v)
	return ok && grammar(s, kind)
}

func ValidateStructuralRequest(data []byte) (StructuralRequest, error) {
	var empty StructuralRequest
	v, e := ParseJSON(data)
	if e != nil {
		return empty, e
	}
	m, ok := object(v)
	if !ok || !closed(m, "protocol", "request_id", "action", "target", "kind", "schema_id", "resource_id", "desired", "expected_revision", "plan_digest", "allowed_effects", "deadline_unix_ms", "max_response_bytes", "operation_id") {
		return empty, ErrInvalid
	}
	if !intRange(m["protocol"], 1, 1) || !idValue(m["request_id"]) || !intRange(m["deadline_unix_ms"], 0, 9007199254740991) || !intRange(m["max_response_bytes"], 1, 65536) || !(m["operation_id"] == nil || idValue(m["operation_id"])) {
		return empty, ErrInvalid
	}
	for _, k := range []string{"target", "kind", "schema_id"} {
		s, ok := stringValue(m[k])
		if !ok || !grammar(s, "name") {
			return empty, ErrInvalid
		}
	}
	s, ok := stringValue(m["resource_id"])
	if !ok || !grammar(s, "resource") {
		return empty, ErrInvalid
	}
	action, ok := stringValue(m["action"])
	if !ok {
		return empty, ErrInvalid
	}
	effects, ok := m["allowed_effects"].([]any)
	if !ok || len(effects) > 256 || !effectList(effects) {
		return empty, ErrInvalid
	}
	desired := m["desired"]
	switch action {
	case "observe":
		if desired != nil || m["expected_revision"] != nil || m["plan_digest"] != nil || m["operation_id"] != nil || len(effects) != 0 {
			return empty, ErrInvalid
		}
	case "plan":
		if !mapObject(desired) || !bounded(desired, MaxDesired) || !nullable(m["expected_revision"], "revision", false) || m["plan_digest"] != nil || m["operation_id"] != nil || len(effects) != 0 {
			return empty, ErrInvalid
		}
	case "apply":
		if !mapObject(desired) || !bounded(desired, MaxDesired) || !nullable(m["expected_revision"], "revision", false) || !nullable(m["plan_digest"], "digest", true) || !idValue(m["operation_id"]) {
			return empty, ErrInvalid
		}
	case "cancel", "reconcile":
		if desired != nil || m["expected_revision"] != nil || !nullable(m["plan_digest"], "digest", true) || !idValue(m["operation_id"]) || len(effects) != 0 {
			return empty, ErrInvalid
		}
	default:
		return empty, ErrInvalid
	}
	return StructuralRequest{id: m["request_id"].(string), action: action, target: m["target"].(string), kind: m["kind"].(string), schemaID: m["schema_id"].(string), maxStructuralResponse: int(m["max_response_bytes"].(int64))}, nil
}
func mapObject(v any) bool { _, ok := object(v); return ok }
func effectList(v []any) bool {
	seen := map[string]bool{}
	for _, x := range v {
		m, ok := object(x)
		if !ok || !closed(m, "class", "summary_id", "destructive") {
			return false
		}
		c, cok := stringValue(m["class"])
		s, sok := stringValue(m["summary_id"])
		_, bok := m["destructive"].(bool)
		if !cok || !sok || !grammar(c, "name") || !grammar(s, "name") || !bok {
			return false
		}
		key := c + "\x00" + s
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
