package driverprotocol

import (
	"encoding/json"
	"strconv"
)

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
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
func bounded(v any, n int) bool { b, e := canonicalBytes(v); return e == nil && len(b) <= n }
