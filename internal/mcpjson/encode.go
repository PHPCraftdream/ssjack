package mcpjson

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"unicode/utf8"
)

// Marshal normalizes and encodes without allocating beyond the output bound.
func Marshal(value any, limit int) ([]byte, error) {
	normalized, err := Normalize(value, limit)
	if err != nil {
		return nil, err
	}
	if err := measure(normalized, limit); err != nil {
		return nil, err
	}
	sink := boundedBuffer{limit: limit}
	if err := encode(&sink, normalized, 0); err != nil {
		return nil, ErrLimit
	}
	return append([]byte(nil), sink.Bytes()...), nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrLimit
	}
	return b.Buffer.Write(p)
}

func encode(s *boundedBuffer, value any, depth int) error {
	if depth > 32 {
		return ErrLimit
	}
	put := func(text string) error {
		_, err := s.Write([]byte(text))
		return err
	}
	switch v := value.(type) {
	case nil:
		return put("null")
	case bool:
		if v {
			return put("true")
		}
		return put("false")
	case string:
		return quote(s, v)
	case json.Number:
		if !json.Valid([]byte(v)) {
			return ErrInvalid
		}
		return put(string(v))
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return ErrInvalid
		}
		return put(strconv.FormatFloat(v, 'g', -1, 64))
	case []any:
		if err := put("["); err != nil {
			return err
		}
		for i, child := range v {
			if i > 0 {
				if err := put(","); err != nil {
					return err
				}
			}
			if err := encode(s, child, depth+1); err != nil {
				return err
			}
		}
		return put("]")
	case map[string]any:
		if err := put("{"); err != nil {
			return err
		}
		first := true
		for key, child := range v {
			if !first {
				if err := put(","); err != nil {
					return err
				}
			}
			first = false
			if err := quote(s, key); err != nil {
				return err
			}
			if err := put(":"); err != nil {
				return err
			}
			if err := encode(s, child, depth+1); err != nil {
				return err
			}
		}
		return put("}")
	default:
		return ErrInvalid
	}
}

func measure(value any, limit int) error {
	used := 0
	var visit func(any, int) error
	visit = func(value any, depth int) error {
		if depth > 32 {
			return ErrLimit
		}
		switch v := value.(type) {
		case string:
			if !utf8.ValidString(v) || len(v) > limit-used {
				return ErrLimit
			}
			used += len(v)
		case map[string]any:
			for key, child := range v {
				if !utf8.ValidString(key) || len(key) > limit-used {
					return ErrLimit
				}
				used += len(key)
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(value, 0)
}

func quote(s *boundedBuffer, value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalid
	}
	if _, err := s.Write([]byte{'"'}); err != nil {
		return err
	}
	for len(value) > 0 {
		if value[0] >= ' ' && value[0] != '\\' && value[0] != '"' {
			i := 0
			for i < len(value) && value[i] >= ' ' && value[i] != '\\' && value[i] != '"' {
				i++
			}
			if _, err := s.Write([]byte(value[:i])); err != nil {
				return err
			}
			value = value[i:]
			continue
		}
		var escaped string
		switch value[0] {
		case '"':
			escaped = `\"`
		case '\\':
			escaped = `\\`
		case '\b':
			escaped = `\b`
		case '\f':
			escaped = `\f`
		case '\n':
			escaped = `\n`
		case '\r':
			escaped = `\r`
		case '\t':
			escaped = `\t`
		default:
			escaped = `\u00` + strconv.FormatUint(uint64(value[0])|0x100, 16)[1:]
		}
		if _, err := s.Write([]byte(escaped)); err != nil {
			return err
		}
		value = value[1:]
	}
	_, err := s.Write([]byte{'"'})
	return err
}
