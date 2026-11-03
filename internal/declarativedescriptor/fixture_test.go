package declarativedescriptor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

type spec struct {
	name    string
	in, out map[string]any
}

func obj(p map[string]any) map[string]any {
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return map[string]any{"type": "object", "properties": p, "required": keys, "additionalProperties": false}
}

func str(n int) map[string]any {
	return map[string]any{"type": "string", "maxLength": n}
}

func num(a, b int) map[string]any {
	return map[string]any{"type": "integer", "minimum": a, "maximum": b}
}

func arr(v any, a, b int) map[string]any {
	return map[string]any{"type": "array", "items": v, "minItems": a, "maxItems": b}
}

func enum(v ...string) map[string]any {
	return map[string]any{"enum": v}
}

func nullable(v map[string]any) map[string]any {
	v["type"] = []string{v["type"].(string), "null"}
	return v
}

func dyn() map[string]any {
	return map[string]any{"type": "object", "maxProperties": 128, "additionalProperties": true}
}

func state() map[string]any {
	return enum("RESERVED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN")
}

func doc(v map[string]any) map[string]any {
	v["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	return v
}

func fixture() map[string]any {
	resource := func() map[string]any {
		return map[string]any{
			"target": str(64), "driver_id": str(64), "kind": str(64),
			"schema_id": str(64), "resource_id": str(128),
		}
	}
	plan := resource()
	plan["desired"] = dyn()
	plan["request_id"] = str(22)
	limits := obj(map[string]any{
		"process_slots": num(1, 4), "session_operations": num(1, 32),
		"global_operations": num(1, 64), "emergency_cancellations": num(1, 16),
		"storage_bytes": num(1, 16777216), "records": num(1, 256),
		"cancellation_reserve_bytes": num(4096, 4096),
	})
	driver := obj(map[string]any{
		"driver_id": str(64), "protocol": num(1, 1), "kinds": arr(str(64), 0, 128),
		"capabilities": arr(enum("observe", "plan", "apply", "conditional_write",
			"exclusive_owner", "cancel", "reconcile", "verify_adoption"), 1, 8),
		"limits": limits,
	})
	effect := obj(map[string]any{
		"class": str(64), "summary_id": str(64), "destructive": map[string]any{"type": "boolean"},
	})
	rev := obj(map[string]any{
		"applied": nullable(str(128)), "delivered": nullable(str(128)),
		"observed": nullable(str(128)), "adopted": nullable(str(128)),
	})
	result := nullable(obj(map[string]any{
		"verified": map[string]any{"type": "boolean"}, "projection": dyn(),
	}))
	failure := nullable(obj(map[string]any{
		"code": str(64), "message": str(256), "retryable": map[string]any{"type": "boolean"},
		"operation_id": nullable(str(22)),
	}))
	specs := []spec{
		{"driver_list", obj(map[string]any{}), obj(map[string]any{"drivers": arr(driver, 0, 128)})},
		{"resource_status", obj(resource()), obj(map[string]any{
			"state": enum("present", "absent", "unknown"), "revision": nullable(str(128)),
			"observed_at": str(24), "projection": dyn(),
		})},
		{"resource_plan", obj(plan), obj(map[string]any{
			"plan_id": str(22), "digest": str(64), "expires_at": str(24),
			"effects": arr(effect, 0, 256), "precondition": nullable(str(128)),
		})},
		{"plan_apply", obj(map[string]any{"plan_id": str(22), "request_id": str(22)}),
			obj(map[string]any{"operation_id": str(22), "state": state()})},
		{"operation_read", obj(map[string]any{"operation_id": str(22)}), obj(map[string]any{
			"operation_id": str(22), "state": state(),
			"phase":    enum("queued", "observing", "planning", "applying", "verifying", "reconciling", "cancelling", "complete"),
			"progress": nullable(num(0, 100)), "revisions": rev, "result": result,
			"error": failure, "updated_at": str(24),
		})},
		{"operation_cancel", obj(map[string]any{"operation_id": str(22), "request_id": str(22)}),
			obj(map[string]any{"operation_id": str(22), "state": state(),
				"cancellation": enum("confirmed", "unsupported", "pending")})},
	}
	tools := make([]any, 0, 6)
	for _, s := range specs {
		in, out := doc(s.in), doc(s.out)
		tools = append(tools, map[string]any{
			"name": s.name, "input_schema": in, "output_schema": out,
			"schema_id": "ssjack.tool." + s.name + ".v1", "schema_digest": pairDigest(in, out),
		})
	}
	return map[string]any{
		"protocol": 1, "min_protocol": 1, "max_protocol": 1, "min_request_bytes": 1,
		"max_request_bytes": 262144, "mode": "declarative",
		"session_id": "AAAAAAAAAAAAAAAAAAAAAA", "tools": tools,
	}
}

func pairDigest(in, out any) string {
	b, _ := json.Marshal(map[string]any{"input": in, "output": out})
	h := sha256.New()
	h.Write([]byte("ssjack-tool-schema-v1\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func encode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
