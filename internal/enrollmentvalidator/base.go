package enrollmentvalidator

import "strings"

func base(m map[string]any) bool {
	if !stringMap(m["artifact_digests"], 1) || !stringMap(m["dependency_digests"], 0) || !digest(m["configuration_digest"]) || !named(m["driver_id"]) || !integer(m["driver_protocol"], 1, 1) || !id(m["enrollment_id"]) {
		return false
	}
	if _, ok := obj(m["environment"]); !ok {
		return false
	}
	if _, ok := list(m["resource_sinks"], 0, 0); !ok {
		return false
	}
	caps, ok := list(m["capabilities"], 1, 8)
	if !ok {
		return false
	}
	prev := ""
	observe := false
	for _, v := range caps {
		s, ok := v.(string)
		if !ok || s <= prev || !choice(s, "observe", "plan", "apply", "conditional_write", "exclusive_owner", "cancel", "reconcile", "verify_adoption") {
			return false
		}
		prev = s
		observe = observe || s == "observe"
	}
	if !observe {
		return false
	}
	if !executable(m["executable"]) || !working(m["working_directory"]) || !identity(m["os_identity"]) || !limits(m["limits"]) || !network(m["network"]) || !provenance(m["provenance"], m["dependency_digests"]) {
		return false
	}
	p, ok := obj(m["principal"], "issuer", "subject")
	return ok && str(p["issuer"], 256) && str(p["subject"], 256)
}
func executable(v any) bool {
	m, ok := obj(v, "path", "sha256", "interpreter", "argv")
	if !ok || !str(m["path"], 4096) || !digest(m["sha256"]) {
		return false
	}
	i, ok := obj(m["interpreter"], "path", "sha256")
	if !ok || !str(i["path"], 4096) || !digest(i["sha256"]) {
		return false
	}
	a, ok := list(m["argv"], 0, 64)
	if !ok {
		return false
	}
	for _, v := range a {
		if !str(v, 4096) {
			return false
		}
	}
	return true
}
func working(v any) bool {
	m, ok := obj(v, "path", "device", "file_id")
	if !ok || !str(m["path"], 4096) || !str(m["device"], 128) || m["device"] == "" || !str(m["file_id"], 128) || m["file_id"] == "" {
		return false
	}
	p := m["path"].(string)
	return strings.HasPrefix(p, "/") || (len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}
func identity(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	platform, ok := m["platform"].(string)
	if !ok {
		return false
	}
	switch platform {
	case "posix":
		m, ok = obj(v, "platform", "uid", "gid", "groups")
		if !ok || !integer(m["uid"], 0, 4294967295) || !integer(m["gid"], 0, 4294967295) {
			return false
		}
		a, ok := list(m["groups"], 0, 64)
		if !ok {
			return false
		}
		for _, v := range a {
			if !integer(v, 0, 4294967295) {
				return false
			}
		}
		return true
	case "windows":
		m, ok = obj(v, "platform", "sid")
		return ok && str(m["sid"], 184) && m["sid"] != ""
	}
	return false
}
func limits(v any) bool {
	m, ok := obj(v, "process_slots", "session_operations", "global_operations", "emergency_cancellations", "storage_bytes", "records", "cancellation_reserve_bytes")
	if !ok {
		return false
	}
	for k, max := range map[string]int64{"process_slots": 4, "session_operations": 32, "global_operations": 64, "emergency_cancellations": 16, "storage_bytes": 16777216, "records": 256} {
		if !integer(m[k], 1, max) {
			return false
		}
	}
	return integer(m["cancellation_reserve_bytes"], 4096, 4096)
}
func provenance(v, deps any) bool {
	m, ok := obj(v, "source", "revision", "dependencies")
	if !ok || !str(m["source"], 1024) || !str(m["revision"], 256) {
		return false
	}
	a, ok := list(m["dependencies"], 0, 128)
	if !ok {
		return false
	}
	d := deps.(map[string]any)
	if len(a) != len(d) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range a {
		x, ok := obj(v, "name", "path", "sha256")
		if !ok || !named(x["name"]) || !str(x["path"], 4096) || !digest(x["sha256"]) {
			return false
		}
		n := x["name"].(string)
		if seen[n] || d[n] != x["sha256"] {
			return false
		}
		seen[n] = true
	}
	return true
}
