package planbinding

import (
	"bytes"
	"encoding/json"
)

// Map key order is an enrollment constraint, checked before canonicalization.
func orderedMaps(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return false
	}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return false
		}
		if key == "artifact_digests" || key == "dependency_digests" {
			if !orderedMap(v) {
				return false
			}
		}
	}
	return true
}

func orderedMap(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return false
	}
	previous := ""
	first := true
	for d.More() {
		t, err := d.Token()
		s, ok := t.(string)
		if err != nil || !ok || (!first && s <= previous) {
			return false
		}
		first, previous = false, s
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return false
		}
	}
	return true
}

func effects(raw []byte) bool {
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil || a == nil || len(a) > 256 {
		return false
	}
	var prevClass, prevSummary string
	var prevDestructive bool
	for i, item := range a {
		var m map[string]json.RawMessage
		if json.Unmarshal(item, &m) != nil || !closed(m, "class", "summary_id", "destructive") || !matches(m["class"], nameRE) || !matches(m["summary_id"], nameRE) {
			return false
		}
		var class, summary string
		if json.Unmarshal(m["class"], &class) != nil || json.Unmarshal(m["summary_id"], &summary) != nil || (string(m["destructive"]) != "true" && string(m["destructive"]) != "false") {
			return false
		}
		destructive := string(m["destructive"]) == "true"
		if i > 0 && !(prevClass < class || (prevClass == class && (prevSummary < summary || (prevSummary == summary && !prevDestructive && destructive)))) {
			return false
		}
		prevClass, prevSummary, prevDestructive = class, summary, destructive
	}
	return true
}
