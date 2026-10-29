package enrollmentvalidator

import (
	"bytes"
	"encoding/json"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/domaindigest"
	"github.com/PHPCraftdream/ssjack/internal/externalschemasubset"
)

func references(m map[string]any) bool {
	schemas, ok := list(m["schemas"], 1, 256)
	if !ok {
		return false
	}
	ids := map[string]bool{}
	prev := ""
	for _, v := range schemas {
		x, ok := obj(v, "id", "digest", "document")
		if !ok || !named(x["id"]) || !digest(x["digest"]) {
			return false
		}
		id := x["id"].(string)
		if id <= prev {
			return false
		}
		prev = id
		if _, ok := x["document"].(map[string]any); !ok {
			return false
		}
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if encoder.Encode(x["document"]) != nil {
			return false
		}
		doc, e := canonicaljson.Canonicalize(encoded.Bytes())
		if e != nil || externalschemasubset.ValidateSchema(doc) != nil {
			return false
		}
		digest, e := domaindigest.Sum(domaindigest.Schema, doc)
		if e != nil || digest != x["digest"] {
			return false
		}
		ids[id] = true
	}
	kinds, ok := list(m["kinds"], 1, 128)
	if !ok {
		return false
	}
	ks := map[string]bool{}
	prev = ""
	for _, v := range kinds {
		x, ok := obj(v, "name", "desired_schema_id", "projection_schema_id")
		if !ok || !named(x["name"]) || !named(x["desired_schema_id"]) || !named(x["projection_schema_id"]) {
			return false
		}
		n := x["name"].(string)
		if n <= prev || !ids[x["desired_schema_id"].(string)] || !ids[x["projection_schema_id"].(string)] {
			return false
		}
		prev = n
		ks[n] = true
	}
	targets, ok := list(m["targets"], 1, 128)
	if !ok {
		return false
	}
	ts := map[string]string{}
	prev = ""
	for _, v := range targets {
		x, ok := obj(v, "name", "canonical_target")
		if !ok || !named(x["name"]) || !resource(x["canonical_target"]) {
			return false
		}
		n := x["name"].(string)
		if n <= prev {
			return false
		}
		prev = n
		ts[n] = x["canonical_target"].(string)
	}
	return aliases(m["aliases"], ts, ks) && effects(m["effects"])
}
func aliases(v any, targets map[string]string, kinds map[string]bool) bool {
	a, ok := list(v, 0, 256)
	if !ok {
		return false
	}
	prev := [3]string{}
	for i, v := range a {
		x, ok := obj(v, "target", "kind", "resource_id", "canonical_target", "canonical_resource")
		if !ok || !named(x["target"]) || !named(x["kind"]) || !resource(x["resource_id"]) || !resource(x["canonical_target"]) || !resource(x["canonical_resource"]) {
			return false
		}
		t := x["target"].(string)
		k := x["kind"].(string)
		if targets[t] != x["canonical_target"] || !kinds[k] {
			return false
		}
		cur := [3]string{t, k, x["resource_id"].(string)}
		if i > 0 && !less3(prev, cur) {
			return false
		}
		prev = cur
	}
	return true
}
func less3(a, b [3]string) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
func effects(v any) bool {
	a, ok := list(v, 1, 256)
	if !ok {
		return false
	}
	prev := [3]string{}
	last := false
	for i, v := range a {
		x, ok := obj(v, "class", "summary_id", "decision", "destructive")
		if !ok || !named(x["class"]) || !named(x["summary_id"]) || !choice(x["decision"], "delegated", "approval_required") {
			return false
		}
		d, ok := x["destructive"].(bool)
		if !ok {
			return false
		}
		cur := [3]string{x["class"].(string), x["summary_id"].(string), x["decision"].(string)}
		if i > 0 && !less3(prev, cur) && !(prev == cur && !last && d) {
			return false
		}
		prev = cur
		last = d
	}
	return true
}
