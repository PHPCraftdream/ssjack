package enrollmentvalidator

import (
	"net"
	"strings"
)

func dns(s string) bool {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil || strings.ToLower(s) != s {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func network(v any) bool {
	m, ok := obj(v, "policy", "targets", "policy_digest")
	if !ok || !digest(m["policy_digest"]) || !choice(m["policy"], "deny_all", "allow_list") {
		return false
	}
	a, ok := list(m["targets"], 0, 128)
	if !ok || (m["policy"] == "deny_all" && len(a) != 0) || (m["policy"] == "allow_list" && len(a) == 0) {
		return false
	}
	prevHost := ""
	var prevPort int64
	for i, v := range a {
		x, ok := obj(v, "protocol", "host", "port")
		if !ok || x["protocol"] != "tcp" || !str(x["host"], 253) || !integer(x["port"], 1, 65535) {
			return false
		}
		host := x["host"].(string)
		if !dns(host) {
			return false
		}
		// Compare the numeric port, not its decimal spelling.
		n := x["port"].(interface{ String() string }).String()
		var p int64
		for _, c := range n {
			p = p*10 + int64(c-'0')
		}
		if i > 0 && (host < prevHost || host == prevHost && p <= prevPort) {
			return false
		}
		prevHost = host
		prevPort = p
	}
	return true
}
