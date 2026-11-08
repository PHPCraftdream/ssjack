package mcpjson

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// Decode parses one bounded JSON value using UseNumber and rejects duplicate keys.
func Decode(data []byte, limit, depth, nodes int) (any, error) {
	if limit < 0 || len(data) > limit || depth < 0 || nodes < 1 {
		return nil, ErrLimit
	}
	if !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	state := decodeState{depth: depth, nodes: nodes, limit: limit}
	value, err := state.value(decoder, 0)
	if err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, ErrInvalid
	}
	return value, nil
}

type decodeState struct{ depth, nodes, limit, textBytes int }

func (s *decodeState) node() error {
	if s.nodes <= 0 {
		return ErrLimit
	}
	s.nodes--
	return nil
}

func (s *decodeState) addText(value string) error {
	if len(value) > s.limit-s.textBytes {
		return ErrLimit
	}
	s.textBytes += len(value)
	return nil
}

func (s *decodeState) value(d *json.Decoder, depth int) (any, error) {
	if depth > s.depth || s.node() != nil {
		return nil, ErrLimit
	}
	token, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			out := make(map[string]any)
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, ErrInvalid
				}
				key, ok := keyToken.(string)
				if !ok || s.addText(key) != nil {
					return nil, ErrLimit
				}
				if s.node() != nil {
					return nil, ErrLimit
				}
				if _, exists := out[key]; exists {
					return nil, ErrInvalid
				}
				child, err := s.value(d, depth+1)
				if err != nil {
					return nil, err
				}
				out[key] = child
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return out, nil
		case '[':
			out := make([]any, 0)
			for d.More() {
				child, err := s.value(d, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, child)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return out, nil
		default:
			return nil, ErrInvalid
		}
	case string:
		if err := s.addText(v); err != nil {
			return nil, err
		}
		return v, nil
	case bool, json.Number, nil:
		return v, nil
	default:
		return nil, ErrInvalid
	}
}
