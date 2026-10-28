package driverprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"unicode/utf8"
)

const maxSchemaBytes = 65536

var ErrSchema = errors.New("invalid enrolled schema")

func ValidatePinnedValue(sb []byte, id, digest, target, kind, actualTarget, actualKind, actualID string, vb []byte, limit int) error {
	if !grammar(id, "name") || !grammar(target, "name") || !grammar(kind, "name") || actualID != id || target != actualTarget || kind != actualKind || len(sb) == 0 || len(sb) > maxSchemaBytes || !utf8.Valid(sb) {
		return ErrSchema
	}
	doc, e := ParseJSON(sb)
	if e != nil {
		return e
	}
	if validateSchema(doc, true, 0) != nil || hasHTMLSensitiveString(doc) {
		return ErrSchema
	}
	b, e := canonicalBytes(doc)
	if e != nil || len(b) > maxSchemaBytes {
		return ErrSchema
	}
	h := sha256.Sum256(append(append([]byte("ssjack-schema-v1"), 0), b...))
	if digest != hex.EncodeToString(h[:]) {
		return ErrSchema
	}
	v, e := ParseJSON(vb)
	if e != nil {
		return e
	}
	if !bounded(v, limit) || !matches(doc, v, 0) {
		return ErrInvalid
	}
	return nil
}
func ValidatePinnedRequest(data, sb []byte, id, digest, target, kind string) (StructuralRequest, error) {
	r, e := ValidateStructuralRequest(data)
	if e != nil {
		return StructuralRequest{}, e
	}
	if r.action != "plan" && r.action != "apply" {
		return StructuralRequest{}, ErrInvalid
	}
	v, e := ParseJSON(data)
	if e != nil {
		return StructuralRequest{}, e
	}
	m, _ := object(v)
	x := m["desired"]
	if x == nil {
		return StructuralRequest{}, ErrInvalid
	}
	b, e := canonicalBytes(x)
	if e != nil || r.target != target || r.kind != kind {
		return StructuralRequest{}, ErrSchema
	}
	if e = ValidatePinnedValue(sb, id, digest, target, kind, r.target, r.kind, r.schemaID, b, MaxDesired); e != nil {
		return StructuralRequest{}, e
	}
	return r, nil
}
func validateSchema(v any, root bool, d int) error {
	if d > 16 {
		return ErrSchema
	}
	m, ok := object(v)
	if !ok {
		return ErrSchema
	}
	allowed := map[string]bool{"$schema": true, "type": true, "enum": true, "const": true, "properties": true, "required": true, "additionalProperties": true, "items": true, "minItems": true, "maxItems": true, "minLength": true, "maxLength": true, "minimum": true, "maximum": true}
	for k := range m {
		if !allowed[k] || (!root && k == "$schema") {
			return ErrSchema
		}
	}
	if root {
		dialect, ok := m["$schema"].(string)
		if !ok || dialect != "https://json-schema.org/draft/2020-12/schema" {
			return ErrSchema
		}
	}
	t, ok := stringValue(m["type"])
	if !ok {
		return ErrSchema
	}
	switch t {
	case "object":
		p, pok := object(m["properties"])
		additional, aok := m["additionalProperties"].(bool)
		if !pok || !aok || len(p) > 128 || additional {
			return ErrSchema
		}
		r, ok := m["required"].([]any)
		if !ok || len(r) != len(p) {
			return ErrSchema
		}
		seen := map[string]bool{}
		for _, x := range r {
			s, ok := stringValue(x)
			if !ok || seen[s] {
				return ErrSchema
			}
			seen[s] = true
		}
		for k, x := range p {
			if !seen[k] || validateSchema(x, false, d+1) != nil {
				return ErrSchema
			}
		}
	case "array":
		x, ok := m["items"]
		if !ok || validateSchema(x, false, d+1) != nil {
			return ErrSchema
		}
		if _, ok = m["maxItems"]; !ok {
			return ErrSchema
		}
	case "string":
		if _, ok = m["maxLength"]; !ok {
			return ErrSchema
		}
	case "integer", "boolean", "null":
	default:
		return ErrSchema
	}
	for k, x := range m {
		if !applicableSchemaKeyword(k, t) {
			return ErrSchema
		}
		lo, hi := int64(0), int64(0)
		switch k {
		case "minItems", "maxItems", "minLength", "maxLength":
			hi = 4096
			if k == "minItems" || k == "maxItems" {
				hi = 256
			}
			if k == "maxLength" {
				lo = 1
			}
		case "minimum", "maximum":
			lo, hi = -9007199254740991, 9007199254740991
		default:
			continue
		}
		n, ok := x.(int64)
		if !ok || n < lo || n > hi {
			return ErrSchema
		}
	}
	for _, p := range [][2]string{{"minItems", "maxItems"}, {"minLength", "maxLength"}, {"minimum", "maximum"}} {
		a, ao := m[p[0]].(int64)
		b, bo := m[p[1]].(int64)
		if ao && bo && a > b {
			return ErrSchema
		}
	}
	if a, ok := m["enum"].([]any); ok {
		if len(a) < 1 || len(a) > 256 {
			return ErrSchema
		}
		for i, x := range a {
			if !bounded(x, 4096) {
				return ErrSchema
			}
			for _, y := range a[:i] {
				if jsonEqual(x, y) {
					return ErrSchema
				}
			}
		}
	} else if _, ok := m["enum"]; ok {
		return ErrSchema
	}
	if x, ok := m["const"]; ok && !bounded(x, 4096) {
		return ErrSchema
	}
	return nil
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
func matches(s, v any, d int) bool {
	if d > 16 {
		return false
	}
	m, ok := object(s)
	if !ok {
		return false
	}
	if a, ok := m["enum"].([]any); ok {
		f := false
		for _, x := range a {
			if jsonEqual(x, v) {
				f = true
			}
		}
		if !f {
			return false
		}
	}
	if x, ok := m["const"]; ok && !jsonEqual(x, v) {
		return false
	}
	switch m["type"] {
	case "object":
		x, ok := object(v)
		p, _ := object(m["properties"])
		if !ok || len(x) != len(p) {
			return false
		}
		for k, v := range x {
			q, yes := p[k]
			if !yes || !matches(q, v, d+1) {
				return false
			}
		}
		return true
	case "array":
		a, ok := v.([]any)
		if !ok {
			return false
		}
		if n, ok := m["minItems"].(int64); ok && int64(len(a)) < n {
			return false
		}
		if n, ok := m["maxItems"].(int64); ok && int64(len(a)) > n {
			return false
		}
		for _, x := range a {
			if !matches(m["items"], x, d+1) {
				return false
			}
		}
		return true
	case "string":
		x, ok := v.(string)
		if !ok || !ascii(x) {
			return false
		}
		n := int64(len(x))
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
		return true
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	}
	return false
}
