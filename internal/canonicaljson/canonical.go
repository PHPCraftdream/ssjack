// Package canonicaljson implements only bounded JCS-SSJACK-1 JSON encoding.
// It does not validate schemas, authorize values, or compute binding digests.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/drivertext"
)

const (
	MaxInput      = 262144
	MaxOutput     = 65536
	MaxDepth      = 16
	MaxNodes      = 4096
	MaxArray      = 256
	MaxProperties = 128
)

var ErrInvalid = errors.New("invalid or oversized canonical JSON")

// Canonicalize accepts one JSON value. Depth counts edges from the root;
// nodes count values, not object keys. Both input and output have fixed caps.
// Callers must separately validate the applicable closed schema and its limits.
func Canonicalize(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxInput || !utf8.Valid(raw) || !drivertext.ValidEscapes(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	v, err := parse(d, 0, &nodes)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	out := make([]byte, 0, len(raw))
	out = appendValue(out, v)
	if len(out) > MaxOutput {
		return nil, ErrInvalid
	}
	return out, nil
}

func parse(d *json.Decoder, depth int, nodes *int) (any, error) {
	if depth > MaxDepth || *nodes >= MaxNodes {
		return nil, ErrInvalid
	}
	*nodes++
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := make(map[string]any)
			for d.More() {
				if len(m) >= MaxProperties {
					return nil, ErrInvalid
				}
				key, e := d.Token()
				if e != nil {
					return nil, ErrInvalid
				}
				k, ok := key.(string)
				if !ok || !drivertext.ValidText(k) {
					return nil, ErrInvalid
				}
				if _, ok = m[k]; ok {
					return nil, ErrInvalid
				}
				v, e := parse(d, depth+1, nodes)
				if e != nil {
					return nil, e
				}
				m[k] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= MaxArray {
					return nil, ErrInvalid
				}
				v, e := parse(d, depth+1, nodes)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		}
	case string:
		if drivertext.ValidText(x) {
			return x, nil
		}
	case json.Number:
		i, e := strconv.ParseInt(string(x), 10, 64)
		if e == nil && i >= -9007199254740991 && i <= 9007199254740991 {
			return i, nil
		}
	case bool, nil:
		return x, nil
	}
	return nil, ErrInvalid
}

func appendString(out []byte, s string) []byte {
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return append(out, '"')
}

func appendValue(out []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(out, "null"...)
	case bool:
		return strconv.AppendBool(out, x)
	case int64:
		return strconv.AppendInt(out, x, 10)
	case string:
		return appendString(out, x)
	case []any:
		out = append(out, '[')
		for i, v := range x {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendValue(out, v)
		}
		return append(out, ']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out = append(out, '{')
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendString(out, k)
			out = append(out, ':')
			out = appendValue(out, x[k])
		}
		return append(out, '}')
	}
	panic("unreachable JSON value")
}
