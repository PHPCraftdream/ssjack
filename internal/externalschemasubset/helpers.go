package externalschemasubset

import (
	"bytes"
	"encoding/json"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func enumOnly(m map[string]any) bool {
	_, hasType := m["type"]
	_, hasEnum := m["enum"]
	return !hasType && hasEnum
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
