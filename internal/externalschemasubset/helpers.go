package externalschemasubset

import (
	"bytes"
	"encoding/json"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"unicode/utf8"
)

func properties(m map[string]any) (map[string]any, bool) {
	v, exists := m["properties"]
	if !exists {
		return nil, true
	}
	p, ok := v.(map[string]any)
	return p, ok
}

func containerKeywords(m map[string]any) bool {
	p, ok := properties(m)
	if !ok {
		return false
	}
	for _, child := range p {
		if !schema(child, false) {
			return false
		}
	}
	if v, exists := m["required"]; exists {
		r, ok := v.([]any)
		if !ok {
			return false
		}
		seen := map[string]bool{}
		for _, name := range r {
			s, ok := name.(string)
			if !ok || seen[s] {
				return false
			}
			seen[s] = true
		}
	}
	if v, exists := m["additionalProperties"]; exists {
		if _, ok := v.(bool); !ok {
			return false
		}
	}
	if v, exists := m["items"]; exists && !schema(v, false) {
		return false
	}
	if v, exists := m["uniqueItems"]; exists {
		if _, ok := v.(bool); !ok {
			return false
		}
	}
	return bound(m, "minProperties", 0, 128) && bound(m, "maxProperties", 0, 128) &&
		bound(m, "minItems", 0, 256) && bound(m, "maxItems", 0, 256)
}

func valueOnly(m map[string]any) bool {
	_, hasType := m["type"]
	_, hasEnum := m["enum"]
	_, hasConst := m["const"]
	return !hasType && (hasEnum || hasConst)
}

func schemaType(v any) (string, bool, bool) {
	if s, ok := v.(string); ok {
		return s, false, true
	}
	a, ok := v.([]any)
	if !ok || len(a) != 2 {
		return "", false, false
	}
	x, xok := a[0].(string)
	y, yok := a[1].(string)
	if !xok || !yok {
		return "", false, false
	}
	if x == "null" {
		x, y = y, x
	}
	if y != "null" || x == "null" {
		return "", false, false
	}
	return x, true, true
}

func numericShape(m map[string]any) bool {
	const safe = int64(9007199254740991)
	return bound(m, "exclusiveMinimum", -safe, safe) && bound(m, "exclusiveMaximum", -safe, safe) && bound(m, "multipleOf", 1, safe)
}

func numericMatches(m map[string]any, n int64) bool {
	if x, ok := number(m["exclusiveMinimum"]); ok && n <= x {
		return false
	}
	if x, ok := number(m["exclusiveMaximum"]); ok && n >= x {
		return false
	}
	if x, ok := number(m["multipleOf"]); ok && n%x != 0 {
		return false
	}
	return true
}

// key canonicalizes without HTML escaping, keeping bounded canonical values below
// the canonicalizer's input cap even when U+2028 or U+2029 are escaped.
func key(v any) (string, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return "", err
	}
	c, err := canonicaljson.Canonicalize(b.Bytes())
	return string(c), err
}
func within(m map[string]any, min, max string, n int64) bool {
	if x, ok := number(m[min]); ok && n < x {
		return false
	}
	if x, ok := number(m[max]); ok && n > x {
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
		if _, isObject := v.(map[string]any); !isObject || m["additionalProperties"] != false {
			return true
		}
		typ = "object"
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
		if required, ok := m["required"].([]any); ok {
			for _, name := range required {
				if _, exists := o[name.(string)]; !exists {
					return false
				}
			}
		}
		for k, x := range o {
			if s, exists := p[k]; exists {
				if !matches(s.(map[string]any), x) {
					return false
				}
			} else if m["additionalProperties"] == false {
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
			if item, exists := m["items"]; exists && !matches(item.(map[string]any), x) {
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
