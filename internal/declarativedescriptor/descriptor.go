package declarativedescriptor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeschemas"
)

const DescriptorID = "ssjack.descriptor.declarative.v1"

var ErrInvalid = errors.New("invalid declarative descriptor")

type Tool struct {
	Name         string
	InputSchema  string
	OutputSchema string
	SchemaID     string
	SchemaDigest string
}

type Descriptor struct {
	sessionID string
	canonical string
	tools     []Tool
}

func (d Descriptor) SessionID() string {
	return d.sessionID
}

func (d Descriptor) ID() string {
	return DescriptorID
}

func (d Descriptor) CanonicalJSON() string {
	return d.canonical
}

func (d Descriptor) Tools() []Tool {
	return append([]Tool(nil), d.tools...)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func object(raw json.RawMessage, fields ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &m) != nil || len(m) != len(fields) {
		return nil, invalid("expected closed object with required fields")
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			return nil, invalid("missing or unknown field near %q", f)
		}
	}
	return m, nil
}

func text(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func Validate(raw []byte) (Descriptor, error) {
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return Descriptor{}, invalid("JSON: %v", err)
	}
	root, err := object(canonical, "protocol", "min_protocol", "max_protocol", "min_request_bytes", "max_request_bytes", "mode", "session_id", "tools")
	if err != nil {
		return Descriptor{}, invalid("descriptor: %v", err)
	}
	for key, want := range map[string]string{
		"protocol": "1", "min_protocol": "1", "max_protocol": "1",
		"min_request_bytes": "1", "max_request_bytes": "262144",
	} {
		if string(root[key]) != want {
			return Descriptor{}, invalid("descriptor %s: expected %s", key, want)
		}
	}
	mode, ok := text(root["mode"])
	if !ok || mode != "declarative" {
		return Descriptor{}, invalid("descriptor mode")
	}
	session, ok := text(root["session_id"])
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(session)
	if !ok || err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != session {
		return Descriptor{}, invalid("descriptor session_id")
	}
	var entries []json.RawMessage
	if len(root["tools"]) == 0 || root["tools"][0] != '[' || json.Unmarshal(root["tools"], &entries) != nil || len(entries) != 6 {
		return Descriptor{}, invalid("descriptor tools: expected six")
	}
	catalog, err := declarativeschemas.Catalog()
	if err != nil {
		return Descriptor{}, invalid("catalog: %v", err)
	}
	if len(catalog) != 6 {
		return Descriptor{}, invalid("catalog: expected six tools")
	}
	result := Descriptor{sessionID: session, canonical: string(canonical), tools: make([]Tool, 0, 6)}
	for i, entry := range entries {
		m, err := object(entry, "name", "input_schema", "output_schema", "schema_id", "schema_digest")
		if err != nil {
			return Descriptor{}, invalid("tool %d: %v", i, err)
		}
		expected := catalog[i]
		for key, want := range map[string]string{
			"name": expected.Name, "schema_id": expected.SchemaID, "schema_digest": expected.SchemaDigest,
		} {
			got, valid := text(m[key])
			if !valid || got != want {
				return Descriptor{}, invalid("tool %d %s: mismatch", i, key)
			}
		}
		if string(m["input_schema"]) != expected.InputSchema {
			return Descriptor{}, invalid("tool %d input_schema: mismatch", i)
		}
		if string(m["output_schema"]) != expected.OutputSchema {
			return Descriptor{}, invalid("tool %d output_schema: mismatch", i)
		}
		result.tools = append(result.tools, Tool{
			Name: expected.Name, InputSchema: expected.InputSchema, OutputSchema: expected.OutputSchema,
			SchemaID: expected.SchemaID, SchemaDigest: expected.SchemaDigest,
		})
	}
	return result, nil
}
