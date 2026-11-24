// Package discover integrates bounded startup candidate discovery with owner
// approvals and explicit registrations.
package discover

import (
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
)

// Report writes the pre-unlock candidate and rejection report.
func Report(result discovery.Result, out io.Writer) {
	if result.Overflow {
		fmt.Fprintf(out, "Application discovery overflow (%s; disabled)\n", result.OverflowReason)
		return
	}
	for _, candidate := range result.Candidates {
		path, safe := statusPath(candidate.Path)
		if !safe {
			fmt.Fprintln(out, "Application candidate omitted (status_unsafe; disabled)")
			continue
		}
		name, safe := safeStatusText(candidate.Name)
		if !safe {
			fmt.Fprintf(out, "Application candidate at %s is invalid (candidate_name_unsafe; disabled)\n", path)
			continue
		}
		if candidate.Collision {
			fmt.Fprintf(out, "Application candidate '%s' at %s (name conflict; not approved; review in --interactive)\n", name, path)
		} else {
			fmt.Fprintf(out, "Application candidate '%s' at %s (not approved; review in --interactive)\n", name, path)
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Reason == "additional_rejections" {
			fmt.Fprintln(out, "Further candidate rejections were not reported individually (additional_rejections)")
			continue
		}
		path, safe := statusPath(diagnostic.Path)
		if !safe {
			fmt.Fprintln(out, "Application candidate omitted (status_unsafe; disabled)")
			continue
		}
		reason, safe := safeStatusText(diagnostic.Reason)
		if !safe {
			fmt.Fprintln(out, "Application candidate omitted (status_unsafe; disabled)")
			continue
		}
		fmt.Fprintf(out, "Application candidate at %s is invalid (%s; disabled)\n", path, reason)
	}
}

func PostUnlock(statuses []Status, out io.Writer) {
	for _, status := range statuses {
		name, safe := safeStatusText(status.Name)
		if !safe {
			fmt.Fprintln(out, "Application status omitted (status_unsafe; disabled)")
			continue
		}
		switch status.Kind {
		case "enabled":
			path, safe := statusPath(status.Path)
			if !safe {
				fmt.Fprintf(out, "Application '%s' status omitted (status_unsafe; disabled)\n", name)
				continue
			}
			fmt.Fprintf(out, "Application '%s' approved and enabled at %s\n", name, path)
		case "changed":
			fmt.Fprintf(out, "Application '%s' changed since approval; disabled until owner re-approves\n", name)
		case "absent":
			fmt.Fprintf(out, "Application '%s' rejected/ignored; disabled\n", name)
		case "overflow":
			fmt.Fprintln(out, "Application discovery overflow (overflow_refused; disabled)")
		case "cap_overflow_refused":
			fmt.Fprintln(out, "Application registration cap overflow (cap_overflow_refused; disabled)")
		case "collision_refused":
			fmt.Fprintf(out, "Application '%s' collision refused (collision_refused; disabled)\n", name)
		default:
			fmt.Fprintln(out, "Application status omitted (status_unsafe; disabled)")
		}
	}
}

func safeStatusText(value string) (string, bool) {
	if !utf8.ValidString(value) {
		return "", false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return value, true
}

func statusPath(value string) (string, bool) {
	if _, ok := safeStatusText(value); !ok {
		return "", false
	}
	return displayPath(value), true
}

func displayPath(rel string) string {
	if rel == "." {
		return "."
	}
	return "./" + rel
}
