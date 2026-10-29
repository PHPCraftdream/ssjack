// Package planbinding validates an isolated structural plan-binding prerequisite.
// It grants no authority and is not connected to production execution.
package planbinding

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/domaindigest"
)

var ErrInvalid = errors.New("invalid plan binding")
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var resourceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var revisionRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate returns the plan-domain digest only after structural validation.
// Input may use alternate JSON spellings; the digest always uses canonical bytes.
func Validate(raw []byte) (string, error) {
	b, err := canonicaljson.Canonicalize(raw)
	if err != nil || !orderedMaps(raw) {
		return "", ErrInvalid
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || !closed(m, "protocol", "plan_id", "session_id", "declaration", "target", "resource_id", "canonical_target", "canonical_resource", "driver_id", "driver_protocol", "code_digest", "dependency_digests", "configuration_digest", "artifact_digests", "principal", "kind", "schema_id", "schema_digest", "policy_revision", "precondition", "desired_schema_id", "desired_schema_digest", "desired", "effects", "effect_digest", "projection_schema_id", "projection_schema_digest", "enrollment_digest", "created_at", "expires_at") {
		return "", ErrInvalid
	}
	if string(m["protocol"]) != "1" || string(m["driver_protocol"]) != "1" || !id(m["plan_id"]) || !id(m["session_id"]) {
		return "", ErrInvalid
	}
	for _, k := range []string{"target", "driver_id", "kind", "schema_id", "desired_schema_id", "projection_schema_id"} {
		if !matches(m[k], nameRE) {
			return "", ErrInvalid
		}
	}
	for _, k := range []string{"resource_id", "canonical_target", "canonical_resource"} {
		if !matches(m[k], resourceRE) {
			return "", ErrInvalid
		}
	}
	for _, k := range []string{"code_digest", "configuration_digest", "schema_digest", "desired_schema_digest", "effect_digest", "projection_schema_digest", "enrollment_digest"} {
		if !matches(m[k], digestRE) {
			return "", ErrInvalid
		}
	}
	if !matches(m["policy_revision"], revisionRE) || (string(m["precondition"]) != "null" && !matches(m["precondition"], revisionRE)) || !digestMap(m["dependency_digests"], 0) || !digestMap(m["artifact_digests"], 1) || !principal(m["principal"]) || !timestamp(m["created_at"]) || !timestamp(m["expires_at"]) {
		return "", ErrInvalid
	}
	var declaration map[string]json.RawMessage
	if json.Unmarshal(m["declaration"], &declaration) != nil || !closed(declaration, "kind", "schema_id", "schema_digest", "resource_id", "target") {
		return "", ErrInvalid
	}
	for k, v := range declaration {
		if !bytes.Equal(v, m[k]) {
			return "", ErrInvalid
		}
	}
	if !bytes.Equal(m["schema_id"], m["desired_schema_id"]) || !bytes.Equal(m["schema_digest"], m["desired_schema_digest"]) {
		return "", ErrInvalid
	}
	var desired map[string]json.RawMessage
	if len(m["desired"]) > 32768 || json.Unmarshal(m["desired"], &desired) != nil || desired == nil || !effects(m["effects"]) {
		return "", ErrInvalid
	}
	effectDigest, err := domaindigest.Sum(domaindigest.Effects, m["effects"])
	var supplied string
	if err != nil || json.Unmarshal(m["effect_digest"], &supplied) != nil || effectDigest != supplied {
		return "", ErrInvalid
	}
	sum, err := domaindigest.Sum(domaindigest.Plan, b)
	if err != nil {
		return "", ErrInvalid
	}
	return sum, nil
}

func closed(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func matches(raw json.RawMessage, re *regexp.Regexp) bool {
	var s string
	return json.Unmarshal(raw, &s) == nil && re.MatchString(s)
}

func id(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == s
}

func timestamp(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) != 24 {
		return false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	return err == nil && t.Format("2006-01-02T15:04:05.000Z") == s
}

func principal(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || !closed(m, "issuer", "subject") {
		return false
	}
	for _, v := range m {
		var s string
		if json.Unmarshal(v, &s) != nil || string(v) == "null" || utf8.RuneCountInString(s) > 256 {
			return false
		}
	}
	return true
}

func digestMap(raw json.RawMessage, min int) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil || len(m) < min || len(m) > 128 {
		return false
	}
	for _, v := range m {
		if !matches(v, digestRE) {
			return false
		}
	}
	return true
}
