// Package externalschemasubset implements an isolated, fail-closed subset of the
// proposed external schema dialect, not full v1 or JSON Schema conformance.
// It is not connected to production validation or authorization.
package externalschemasubset

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

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
func ordered(m map[string]any, a, b string) bool {
	x, xok := number(m[a])
	y, yok := number(m[b])
	return !xok || !yok || x <= y
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
	if !ok && !valueOnly(m) {
		return false
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
			if typ != "object" {
				return false
			}
		case "items", "minItems", "maxItems", "uniqueItems":
			if typ != "array" {
				return false
			}
		case "minLength", "maxLength":
			if typ != "string" {
				return false
			}
		case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf":
			if typ != "integer" {
				return false
			}
		default:
			return false
		}
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
		if !ok || len(r) != len(p) {
			return false
		}
		seen := map[string]bool{}
		for _, v := range r {
			k, ok := v.(string)
			if !ok || seen[k] {
				return false
			}
			if _, ok = p[k]; !ok {
				return false
			}
			seen[k] = true
		}
		for _, v := range p {
			if !schema(v, false) {
				return false
			}
		}
		if !bound(m, "minProperties", 0, 128) || !bound(m, "maxProperties", 0, 128) || !ordered(m, "minProperties", "maxProperties") {
			return false
		}
	case "array":
		if !schema(m["items"], false) {
			return false
		}
		if _, ok := m["maxItems"]; !ok {
			return false
		}
		if !bound(m, "minItems", 0, 256) || !bound(m, "maxItems", 0, 256) || !ordered(m, "minItems", "maxItems") {
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
		if !bound(m, "minLength", 0, 4096) || !bound(m, "maxLength", 1, 4096) || !ordered(m, "minLength", "maxLength") {
			return false
		}
	case "integer":
		if !numericShape(m) {
			return false
		}
		if !bound(m, "minimum", -9007199254740991, 9007199254740991) || !bound(m, "maximum", -9007199254740991, 9007199254740991) || !ordered(m, "minimum", "maximum") {
			return false
		}
	case "boolean", "null":
	case "":
		return valueOnly(m)
	default:
		return false
	}
	return true
}
func matches(m map[string]any, v any) bool {
	if c, ok := m["const"]; ok {
		ck, err := key(c)
		if err != nil {
			return false
		}
		vk, err := key(v)
		if err != nil || ck != vk {
			return false
		}
	}
	if e, ok := m["enum"]; ok {
		vk, err := key(v)
		if err != nil {
			return false
		}
		found := false
		for _, x := range e.([]any) {
			k, err := key(x)
			if err != nil {
				return false
			}
			if k == vk {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	typ, nullable, ok := schemaType(m["type"])
	if !ok {
		return valueOnly(m)
	}
	if v == nil && nullable {
		return true
	}
	switch typ {
	case "object":
		o, ok := v.(map[string]any)
		if !ok || !within(m, "minProperties", "maxProperties", int64(len(o))) {
			return false
		}
		p, _ := properties(m)
		if len(o) != len(p) {
			return false
		}
		for k, s := range p {
			x, ok := o[k]
			if !ok || !matches(s.(map[string]any), x) {
				return false
			}
		}
		return true
	case "array":
		a, ok := v.([]any)
		if !ok || !within(m, "minItems", "maxItems", int64(len(a))) {
			return false
		}
		seen := map[string]bool{}
		for _, x := range a {
			if !matches(m["items"].(map[string]any), x) {
				return false
			}
			if m["uniqueItems"] == true {
				k, err := key(x)
				if err != nil || seen[k] {
					return false
				}
				seen[k] = true
			}
		}
		return true
	case "string":
		s, ok := v.(string)
		return ok && within(m, "minLength", "maxLength", int64(utf8.RuneCountInString(s)))
	case "integer":
		n, ok := number(v)
		return ok && within(m, "minimum", "maximum", n) && numericMatches(m, n)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	}
	return false
}
