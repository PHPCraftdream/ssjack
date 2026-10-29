package declarativeschemas

import (
	"encoding/json"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

type node = map[string]any

func object(properties node) node {
	required := make([]string, 0, len(properties))
	for name := range properties {
		required = append(required, name)
	}
	sort.Strings(required)
	return node{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

func stringNode(max int) node {
	return node{"type": "string", "maxLength": max}
}

func integer(min, max int64) node {
	return node{"type": "integer", "minimum": min, "maximum": max}
}

func boolean() node {
	return node{"type": "boolean"}
}

func enumeration(values ...string) node {
	return node{"enum": values}
}

func array(items node, min, max int) node {
	return node{"type": "array", "items": items, "minItems": min, "maxItems": max}
}

func nullable(value node) node {
	value["type"] = []string{value["type"].(string), "null"}
	return value
}

func dynamic() node {
	return node{"type": "object", "maxProperties": 128, "additionalProperties": true}
}

func document(value node) (string, error) {
	value["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

func limits() node {
	return object(node{
		"process_slots":              integer(1, 4),
		"session_operations":         integer(1, 32),
		"global_operations":          integer(1, 64),
		"emergency_cancellations":    integer(1, 16),
		"storage_bytes":              integer(1, 16777216),
		"records":                    integer(1, 256),
		"cancellation_reserve_bytes": integer(4096, 4096),
	})
}

func driver() node {
	return object(node{
		"driver_id":    stringNode(64),
		"protocol":     integer(1, 1),
		"kinds":        array(stringNode(64), 0, 128),
		"capabilities": array(enumeration("observe", "plan", "apply", "conditional_write", "exclusive_owner", "cancel", "reconcile", "verify_adoption"), 1, 8),
		"limits":       limits(),
	})
}

func resourceInput() node {
	return node{
		"target":      stringNode(64),
		"driver_id":   stringNode(64),
		"kind":        stringNode(64),
		"schema_id":   stringNode(64),
		"resource_id": stringNode(128),
	}
}

func state() node {
	return enumeration("RESERVED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN")
}

func revisions() node {
	return object(node{
		"applied":   nullable(stringNode(128)),
		"delivered": nullable(stringNode(128)),
		"observed":  nullable(stringNode(128)),
		"adopted":   nullable(stringNode(128)),
	})
}

func safeResult() node {
	return object(node{"verified": boolean(), "projection": dynamic()})
}

func errorNode() node {
	return object(node{
		"code":         stringNode(64),
		"message":      stringNode(256),
		"retryable":    boolean(),
		"operation_id": nullable(stringNode(22)),
	})
}
