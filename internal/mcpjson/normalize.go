package mcpjson

import (
	"encoding"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrInvalid and ErrLimit never contain caller-provided data.
var (
	ErrInvalid = errors.New("invalid JSON value")
	ErrLimit   = errors.New("JSON value exceeds limits")
)

var (
	numberType = reflect.TypeOf(json.Number(""))
	rawType    = reflect.TypeOf(json.RawMessage(nil))
	marshaler  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
)

// Normalize converts supported SDK JSON values, preflighting before allocation.
func Normalize(value any, limit int) (any, error) {
	if limit < 0 {
		return nil, ErrLimit
	}
	state := normState{limit: limit, nodes: 8192}
	return state.convert(reflect.ValueOf(value), 0)
}

type normState struct{ limit, nodes, textBytes int }

func (s *normState) node() error {
	if s.nodes <= 0 {
		return ErrLimit
	}
	s.nodes--
	return nil
}

func (s *normState) addText(value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalid
	}
	if len(value) > s.limit-s.textBytes {
		return ErrLimit
	}
	s.textBytes += len(value)
	return nil
}

func (s *normState) convert(v reflect.Value, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrLimit
	}
	for v.IsValid() && (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) {
		if v.IsNil() {
			if err := s.node(); err != nil {
				return nil, err
			}
			return nil, nil
		}
		if v.Kind() == reflect.Pointer && v.Type().Elem() != rawType && customJSON(v.Type()) {
			return nil, ErrInvalid
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		if err := s.node(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if v.Type() == rawType {
		if err := s.node(); err != nil {
			return nil, err
		}
		if v.IsNil() {
			return nil, nil
		}
		raw := v.Bytes()
		if len(raw) > s.limit-s.textBytes {
			return nil, ErrLimit
		}
		decoded, err := Decode(raw, s.limit-s.textBytes, 32-depth, s.nodes)
		if err != nil {
			return nil, err
		}
		used, text := countNodes(decoded), countText(decoded)
		if used > s.nodes || text > s.limit-s.textBytes {
			return nil, ErrLimit
		}
		s.nodes -= used
		s.textBytes += text
		return decoded, nil
	}
	if err := s.node(); err != nil {
		return nil, err
	}
	if v.Type() == numberType {
		number := v.Interface().(json.Number)
		if len(number) > s.limit {
			return nil, ErrLimit
		}
		decoded, err := Decode([]byte(number), len(number), 0, 1)
		if err != nil {
			return nil, ErrInvalid
		}
		if _, ok := decoded.(json.Number); !ok {
			return nil, ErrInvalid
		}
		return decoded, nil
	}
	if customJSON(v.Type()) {
		return nil, ErrInvalid
	}
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return json.Number(strconv.FormatInt(v.Int(), 10)), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return json.Number(strconv.FormatUint(v.Uint(), 10)), nil
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, ErrInvalid
		}
		return json.Number(strconv.FormatFloat(f, 'g', -1, v.Type().Bits())), nil
	case reflect.String:
		value := v.String()
		if err := s.addText(value); err != nil {
			return nil, err
		}
		return value, nil
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return nil, nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil, ErrInvalid
		}
		if v.Len() > s.nodes {
			return nil, ErrLimit
		}
		out := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			child, err := s.convert(v.Index(i), depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	case reflect.Map:
		if v.IsNil() {
			return nil, nil
		}
		keyType := v.Type().Key()
		if keyType.Kind() != reflect.String || customJSON(keyType) {
			return nil, ErrInvalid
		}
		if v.Len() > s.nodes/2 {
			return nil, ErrLimit
		}
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			if err := s.node(); err != nil {
				return nil, err
			}
			key := iter.Key().String()
			if err := s.addText(key); err != nil {
				return nil, err
			}
			child, err := s.convert(iter.Value(), depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = child
		}
		return out, nil
	case reflect.Struct:
		if v.Type().Implements(marshaler) {
			return nil, ErrInvalid
		}
		return s.structValue(v, depth)
	default:
		return nil, ErrInvalid
	}
}

func (s *normState) structValue(v reflect.Value, depth int) (any, error) {
	out := make(map[string]any)
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		if field.Anonymous {
			return nil, ErrInvalid
		}
		name, options, tagged := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		omitEmpty := false
		if tagged && options != "" {
			for _, option := range strings.Split(options, ",") {
				if option == "omitempty" || option == "omitzero" {
					omitEmpty = true
				} else if option != "" {
					return nil, ErrInvalid
				}
			}
		}
		fv := v.Field(i)
		if omitEmpty && fv.IsZero() {
			continue
		}
		if _, exists := out[name]; exists {
			return nil, ErrInvalid
		}
		if err := s.node(); err != nil {
			return nil, err
		}
		if err := s.addText(name); err != nil {
			return nil, err
		}
		child, err := s.convert(fv, depth+1)
		if err != nil {
			return nil, err
		}
		out[name] = child
	}
	return out, nil
}

func customJSON(typ reflect.Type) bool {
	textMarshaler := reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	return typ.Implements(marshaler) || reflect.PointerTo(typ).Implements(marshaler) || typ.Implements(textMarshaler) || reflect.PointerTo(typ).Implements(textMarshaler)
}

func countNodes(value any) int {
	count := 1
	switch v := value.(type) {
	case map[string]any:
		for _, child := range v {
			count += 1 + countNodes(child)
		}
	case []any:
		for _, child := range v {
			count += countNodes(child)
		}
	}
	return count
}

func countText(value any) int {
	count := 0
	switch v := value.(type) {
	case string:
		return len(v)
	case map[string]any:
		for key, child := range v {
			count += len(key) + countText(child)
		}
	case []any:
		for _, child := range v {
			count += countText(child)
		}
	}
	return count
}
