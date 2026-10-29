package driverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"unicode/utf8"
)

const maxSchemaBytes = 65536

var ErrSchema = errors.New("invalid enrolled schema")

// CanonicalSchemaDocument returns bytes for the bounded schema subset only; this is partial and not v1 canonicalization.
func CanonicalSchemaDocument(raw []byte) ([]byte, error) {
	doc, err := parseSchemaDocument(raw)
	if err != nil {
		return nil, err
	}
	b, err := canonicalBytes(doc)
	if err != nil || len(b) > maxSchemaBytes {
		return nil, ErrSchema
	}
	return b, nil
}
func parseSchemaDocument(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > maxSchemaBytes || !utf8.Valid(raw) {
		return nil, ErrSchema
	}
	doc, err := ParseJSON(raw)
	if err != nil || validateSchema(doc, true, 0) != nil || hasSchemaSerializationSensitiveString(doc) {
		return nil, ErrSchema
	}
	return doc, nil
}
func ValidateSchemaDocument(sb []byte, id, digest string) error {
	if !grammar(id, "name") || !grammar(digest, "digest") {
		return ErrSchema
	}
	canonical, err := CanonicalSchemaDocument(sb)
	if err != nil {
		return err
	}
	h := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), canonical...))
	if digest != hex.EncodeToString(h[:]) {
		return ErrSchema
	}
	return nil
}
func ValidatePinnedValue(sb []byte, id, digest, target, kind, actualTarget, actualKind, actualID string, vb []byte, limit int) error {
	if !grammar(id, "name") || !grammar(target, "name") || !grammar(kind, "name") || actualID != id || target != actualTarget || kind != actualKind {
		return ErrSchema
	}
	doc, err := parseSchemaDocument(sb)
	if err != nil {
		return err
	}
	canonical, err := canonicalBytes(doc)
	if err != nil || len(canonical) > maxSchemaBytes {
		return ErrSchema
	}
	h := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), canonical...))
	if digest != hex.EncodeToString(h[:]) {
		return ErrSchema
	}
	v, err := ParseJSON(vb)
	if err != nil {
		return err
	}
	if !bounded(v, limit) || !matches(doc, v, 0) {
		return ErrInvalid
	}
	return nil
}
func ValidatePinnedRequest(data, sb []byte, id, digest, target, kind string) (StructuralRequest, error) {
	r, err := ValidateStructuralRequest(data)
	if err != nil {
		return StructuralRequest{}, err
	}
	if r.action != "plan" && r.action != "apply" {
		return StructuralRequest{}, ErrInvalid
	}
	v, err := ParseJSON(data)
	if err != nil {
		return StructuralRequest{}, err
	}
	m, _ := object(v)
	x := m["desired"]
	if x == nil {
		return StructuralRequest{}, ErrInvalid
	}
	b, err := canonicalValueBytes(x)
	if err != nil || r.target != target || r.kind != kind {
		return StructuralRequest{}, ErrSchema
	}
	if err = ValidatePinnedValue(sb, id, digest, target, kind, r.target, r.kind, r.schemaID, b, MaxDesired); err != nil {
		return StructuralRequest{}, err
	}
	return r, nil
}
func validateSchema(v any, root bool, depth int) error {
	if depth > 16 {
		return ErrSchema
	}
	m, ok := object(v)
	if !ok || !validSchemaKeys(m, root) || !validSchemaRoot(m, root) {
		return ErrSchema
	}
	typ, ok := stringValue(m["type"])
	if !ok || !validSchemaShape(m, typ, depth) || !validSchemaConstraints(m, typ) {
		return ErrSchema
	}
	return nil
}
func validSchemaKeys(m map[string]any, root bool) bool {
	allowed := map[string]bool{"$schema": true, "type": true, "enum": true, "const": true, "properties": true, "required": true, "additionalProperties": true, "items": true, "minItems": true, "maxItems": true, "minLength": true, "maxLength": true, "minimum": true, "maximum": true}
	for key := range m {
		if !allowed[key] || (!root && key == "$schema") {
			return false
		}
	}
	return true
}
func validSchemaRoot(m map[string]any, root bool) bool {
	if !root {
		return true
	}
	dialect, ok := m["$schema"].(string)
	return ok && dialect == "https://json-schema.org/draft/2020-12/schema"
}
func validSchemaShape(m map[string]any, typ string, depth int) bool {
	switch typ {
	case "object":
		p, pok := object(m["properties"])
		additional, aok := m["additionalProperties"].(bool)
		r, rok := m["required"].([]any)
		if !pok || !aok || additional || !rok || len(p) > 128 || len(r) != len(p) || !requiredKeys(r, p) {
			return false
		}
		for _, child := range p {
			if validateSchema(child, false, depth+1) != nil {
				return false
			}
		}
	case "array":
		x, ok := m["items"]
		if !ok || validateSchema(x, false, depth+1) != nil {
			return false
		}
		if _, ok = m["maxItems"]; !ok {
			return false
		}
	case "string":
		if _, ok := m["maxLength"]; !ok {
			return false
		}
	case "integer", "boolean", "null":
	default:
		return false
	}
	return true
}
func requiredKeys(required []any, properties map[string]any) bool {
	seen := map[string]bool{}
	for _, item := range required {
		key, ok := stringValue(item)
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
	}
	for key := range properties {
		if !seen[key] {
			return false
		}
	}
	return true
}
func validSchemaConstraints(m map[string]any, typ string) bool {
	for key, value := range m {
		if !applicableSchemaKeyword(key, typ) {
			return false
		}
		lo, hi := keywordBounds(key)
		if lo == hi {
			continue
		}
		n, ok := value.(int64)
		if !ok || n < lo || n > hi {
			return false
		}
	}
	return orderedBounds(m) && validSchemaEnum(m) && validSchemaConst(m)
}
func keywordBounds(key string) (int64, int64) {
	switch key {
	case "minItems", "maxItems":
		return 0, 256
	case "minLength":
		return 0, 4096
	case "maxLength":
		return 1, 4096
	case "minimum", "maximum":
		return -9007199254740991, 9007199254740991
	}
	return 0, 0
}
func orderedBounds(m map[string]any) bool {
	for _, pair := range [][2]string{{"minItems", "maxItems"}, {"minLength", "maxLength"}, {"minimum", "maximum"}} {
		a, ao := m[pair[0]].(int64)
		b, bo := m[pair[1]].(int64)
		if ao && bo && a > b {
			return false
		}
	}
	return true
}
func validSchemaEnum(m map[string]any) bool {
	a, ok := m["enum"].([]any)
	if !ok {
		_, exists := m["enum"]
		return !exists
	}
	if len(a) < 1 || len(a) > 256 {
		return false
	}
	for i, x := range a {
		if !bounded(x, 4096) {
			return false
		}
		for _, y := range a[:i] {
			if jsonEqual(x, y) {
				return false
			}
		}
	}
	return true
}
func validSchemaConst(m map[string]any) bool {
	x, exists := m["const"]
	return !exists || bounded(x, 4096)
}
func matchesEnum(m map[string]any, v any) bool {
	values, ok := m["enum"].([]any)
	if !ok {
		return true
	}
	for _, value := range values {
		if jsonEqual(value, v) {
			return true
		}
	}
	return false
}

func applicableSchemaKeyword(k, typ string) bool {
	switch k {
	case "type", "enum", "const":
		return true
	case "$schema":
		return typ != ""
	case "properties", "required", "additionalProperties":
		return typ == "object"
	case "items", "minItems", "maxItems":
		return typ == "array"
	case "minLength", "maxLength":
		return typ == "string"
	case "minimum", "maximum":
		return typ == "integer"
	}
	return false
}
func jsonEqual(a, b any) bool {
	x, e := canonicalBytes(a)
	if e != nil {
		return false
	}
	y, e := canonicalBytes(b)
	return e == nil && string(x) == string(y)
}
