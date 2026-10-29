// Package externalschemasubset implements an isolated, fail-closed subset of the
// proposed external schema dialect, not full v1 or JSON Schema conformance.
// It is not connected to production validation or authorization.
package externalschemasubset

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const dialect = "https://json-schema.org/draft/2020-12/schema"

var ErrSchema = errors.New("invalid or unsupported external schema subset")
var ErrValue = errors.New("invalid value for external schema subset")

// parse first applies the existing canonical JSON limits and rejection rules.
func parse(raw []byte) (any, []byte, error) {
	b, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return nil, nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err = d.Decode(&v); err != nil {
		return nil, nil, err
	}
	return v, b, nil
}

// ValidateSchema rejects all keywords and schema shapes outside this subset.
func ValidateSchema(raw []byte) error {
	v, _, err := parse(raw)
	if err != nil || !schema(v, true) {
		return ErrSchema
	}
	return nil
}

// Validate checks both the schema and the value. limit is a positive canonical
// byte cap, at most canonicaljson.MaxOutput; callers choose their context limit.
func Validate(schemaJSON, valueJSON []byte, limit int) error {
	s, _, err := parse(schemaJSON)
	if err != nil || !schema(s, true) {
		return ErrSchema
	}
	if limit <= 0 || limit > canonicaljson.MaxOutput {
		return ErrValue
	}
	v, b, err := parse(valueJSON)
	if err != nil || len(b) > limit || !matches(s.(map[string]any), v) {
		return ErrValue
	}
	return nil
}
func number(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := strconv.ParseInt(string(n), 10, 64)
	return i, e == nil
}
func bound(m map[string]any, key string, lo, hi int64) bool {
	v, ok := m[key]
	if !ok {
		return true
	}
	n, ok := number(v)
	return ok && n >= lo && n <= hi
}
func schema(v any, root bool) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if root {
		if s, ok := m["$schema"].(string); !ok || s != dialect {
			return false
		}
	} else if _, ok := m["$schema"]; ok {
		return false
	}
	typ, _, ok := schemaType(m["type"])
	if !ok {
		if _, hasType := m["type"]; !hasType && m["additionalProperties"] == false {
			typ = "object"
		} else if !valueOnly(m) {
			return false
		}
	}
	for k := range m {
		switch k {
		case "$schema", "type", "enum", "const", "default":
		case "title", "description":
			if _, ok := m[k].(string); !ok {
				return false
			}
		case "examples":
			if _, ok := m[k].([]any); !ok {
				return false
			}
		case "properties", "required", "additionalProperties", "minProperties", "maxProperties":
			if _, explicit := m["type"]; !explicit && typ != "object" {
				return false
			}
		case "items", "minItems", "maxItems", "uniqueItems":
			if _, explicit := m["type"]; !explicit {
				return false
			}
		case "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf":
			if _, explicit := m["type"]; !explicit {
				return false
			}
		default:
			return false
		}
	}
	if !containerKeywords(m) {
		return false
	}
	if e, exists := m["enum"]; exists {
		a, ok := e.([]any)
		if !ok || len(a) == 0 || len(a) > 256 {
			return false
		}
		seen := map[string]bool{}
		for _, v := range a {
			k, err := key(v)
			if err != nil || seen[k] {
				return false
			}
			seen[k] = true
		}
	}
	if !bound(m, "minLength", 0, 4096) || !bound(m, "maxLength", 1, 4096) ||
		!bound(m, "minimum", -9007199254740991, 9007199254740991) ||
		!bound(m, "maximum", -9007199254740991, 9007199254740991) || !numericShape(m) {
		return false
	}
	switch typ {
	case "object":
		p, ok := properties(m)
		additional, valid := m["additionalProperties"].(bool)
		if !ok || !valid || additional {
			return false
		}
		r, ok := m["required"].([]any)
		if _, exists := m["required"]; !exists && len(p) == 0 {
			r, ok = nil, true
		}
		if !ok {
			return false
		}
		seen := map[string]bool{}
		for _, v := range r {
			k, ok := v.(string)
			if !ok || seen[k] {
				return false
			}
			seen[k] = true
		}
		for k := range p {
			if !seen[k] {
				return false
			}
		}
		if !bound(m, "minProperties", 0, 128) || !bound(m, "maxProperties", 0, 128) {
			return false
		}
	case "array":
		max, ok := number(m["maxItems"])
		if !ok || max < 0 || max > 256 || !bound(m, "minItems", 0, 256) {
			return false
		}
		if _, exists := m["items"]; !exists && max != 0 {
			return false
		}
		if v, ok := m["uniqueItems"]; ok {
			if _, ok := v.(bool); !ok {
				return false
			}
		}
	case "string":
		if _, ok := m["maxLength"]; !ok {
			return false
		}
	case "integer":
	case "boolean", "null":
	case "":
		return valueOnly(m)
	default:
		return false
	}
	return true
}
