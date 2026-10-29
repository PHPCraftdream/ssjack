// Package enrollmentvalidator validates an isolated proposed enrollment shape.
// It does not authenticate, authorize, or verify any operating-system state.
package enrollmentvalidator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/domaindigest"
)

var ErrInvalid = errors.New("invalid or unsupported enrollment")
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var resourceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate returns the domain-separated digest of the canonical record. Success
// is descriptive only and is not a substitute for authentication or OS checks.
func Validate(raw []byte) (string, error) {
	b, err := canonicaljson.Canonicalize(raw)
	if err != nil || !orderedDigestMaps(raw) {
		return "", ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return "", ErrInvalid
	}
	m, ok := obj(v, "artifact_digests", "aliases", "capabilities", "configuration_digest", "dependency_digests", "driver_id", "driver_protocol", "effects", "enrollment_id", "environment", "executable", "kinds", "limits", "network", "os_identity", "principal", "provenance", "resource_sinks", "schemas", "targets", "working_directory")
	if !ok || !base(m) || !references(m) {
		return "", ErrInvalid
	}
	digest, err := domaindigest.Sum(domaindigest.Enrollment, b)
	if err != nil {
		return "", ErrInvalid
	}
	return digest, nil
}

// orderedDigestMaps examines decoded keys in their original order. The caller
// first runs the strict canonicalizer, which rejects duplicates at every depth.
func orderedDigestMaps(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return false
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return false
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return false
		}
		if key == "artifact_digests" || key == "dependency_digests" {
			if !orderedMap(value) {
				return false
			}
		}
	}
	return true
}

func orderedMap(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return false
	}
	previous := ""
	first := true
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok || (!first && key <= previous) {
			return false
		}
		first, previous = false, key
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return false
		}
	}
	return true
}

func obj(v any, keys ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, k := range keys {
		if _, ok = m[k]; !ok {
			return nil, false
		}
	}
	return m, true
}
func str(v any, max int) bool { s, ok := v.(string); return ok && utf8.RuneCountInString(s) <= max }
func named(v any) bool        { s, ok := v.(string); return ok && nameRE.MatchString(s) }
func resource(v any) bool     { s, ok := v.(string); return ok && resourceRE.MatchString(s) }
func digest(v any) bool       { s, ok := v.(string); return ok && digestRE.MatchString(s) }
func integer(v any, lo, hi int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, e := strconv.ParseInt(string(n), 10, 64)
	return e == nil && i >= lo && i <= hi
}
func list(v any, min, max int) ([]any, bool) {
	a, ok := v.([]any)
	return a, ok && len(a) >= min && len(a) <= max
}
func choice(v any, choices ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, c := range choices {
		if s == c {
			return true
		}
	}
	return false
}
func id(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == s
}
func stringMap(v any, min int) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) < min || len(m) > 128 {
		return false
	}
	for k, v := range m {
		if !named(k) || !digest(v) {
			return false
		}
	}
	return true
}
