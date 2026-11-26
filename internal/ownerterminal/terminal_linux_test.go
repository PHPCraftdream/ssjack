//go:build linux

package ownerterminal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() { linuxProbe = linuxProcessProbe }

// linuxProcessProbe reads failure-only, secret-free process evidence from
// /proc: bridge state, signal masks, wait channels, children, and every
// process still holding the child's pseudo-terminal slave.
func linuxProcessProbe(pid int) []string {
	if pid <= 0 {
		return []string{"process probe pid-unavailable"}
	}
	lines := []string{
		"bridge " + procSummary(pid),
		"bridge main wchan " + mainWchan(pid),
		"bridge wchan " + procWchans(pid),
	}
	children, childErr := childPids(pid)
	if len(children) == 0 && childErr != "" {
		lines = append(lines, "children=unknown:"+childErr)
	} else {
		childLine := fmt.Sprintf("children=%d", len(children))
		if childErr != "" {
			childLine += " partial=" + childErr
		}
		lines = append(lines, childLine)
		for _, child := range children {
			lines = append(lines,
				"child "+procSummary(child),
				"child main wchan "+mainWchan(child),
				"child wchan "+procWchans(child))
		}
	}
	pts, ptsLine := slaveDevice(pid, children)
	lines = append(lines, ptsLine)
	if pts != "" {
		lines = append(lines, slaveHolders(pts)...)
	} else {
		lines = append(lines, "slave device unknown")
	}
	return lines
}

func probeError(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "exited"
	case errors.Is(err, fs.ErrPermission):
		return "unknown:permission"
	default:
		return "unknown:read"
	}
}

func procRead(path string) (string, string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", probeError(err)
	}
	return strings.TrimSpace(string(raw)), ""
}

func procSummary(pid int) string {
	prefix := "/proc/" + strconv.Itoa(pid)
	raw, err := os.ReadFile(prefix + "/status")
	if err != nil {
		return fmt.Sprintf("pid=%d state=%s", pid, probeError(err))
	}
	comm, commErr := procRead(prefix + "/comm")
	if commErr != "" {
		comm = "unknown"
	}
	status := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, found := strings.Cut(line, ":"); found {
			status[key] = strings.TrimSpace(value)
		}
	}
	field := func(name string) string {
		if value, ok := status[name]; ok {
			return name + "=" + value
		}
		return name + "=unknown:read"
	}
	return fmt.Sprintf("pid=%d comm=%s %s %s %s %s %s %s", pid, comm,
		field("State"), field("SigPnd"), field("ShdPnd"), field("SigCgt"), field("SigIgn"), field("Threads"))
}

func procWchans(pid int) string {
	prefix := "/proc/" + strconv.Itoa(pid) + "/task"
	entries, err := os.ReadDir(prefix)
	if err != nil {
		return "main=" + probeError(err)
	}
	parts := make([]string, 0, len(entries))
	for i, entry := range entries {
		if i >= 16 {
			parts = append(parts, "...capped")
			break
		}
		value, readErr := procRead(prefix + "/" + entry.Name() + "/wchan")
		if readErr == "exited" {
			readErr = "thread-exited"
		}
		parts = append(parts, "t"+entry.Name()+"="+value+readErr)
	}
	return strings.Join(parts, " ")
}

func mainWchan(pid int) string {
	value, class := procRead("/proc/" + strconv.Itoa(pid) + "/wchan")
	if class == "" {
		return value
	}
	if class == "exited" && processAlive(pid) {
		return "thread-exited"
	}
	return class
}

func processAlive(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/status")
	return err == nil
}

func childPids(pid int) ([]int, string) {
	prefix := "/proc/" + strconv.Itoa(pid) + "/task"
	entries, err := os.ReadDir(prefix)
	if err != nil {
		return nil, probeError(err)
	}
	seen := map[int]bool{}
	var children []int
	status := ""
	for _, entry := range entries {
		raw, err := os.ReadFile(prefix + "/" + entry.Name() + "/children")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if status == "" {
					status = "thread-exited"
				}
				continue
			}
			status = probeError(err)
			continue
		}
		for _, field := range strings.Fields(string(raw)) {
			if value, err := strconv.Atoi(field); err == nil && !seen[value] {
				seen[value] = true
				children = append(children, value)
			}
		}
		if len(children) >= 16 {
			break
		}
	}
	if len(children) == 0 && status != "" {
		return nil, status
	}
	return children, status
}

var ptsPattern = regexp.MustCompile(`^/dev/pts/[0-9]+$`)

func ptsOfLink(target string) string {
	if ptsPattern.MatchString(target) {
		return target
	}
	return ""
}

func slaveDevice(pid int, children []int) (string, string) {
	anyAlive := false
	for _, child := range children {
		target, err := os.Readlink("/proc/" + strconv.Itoa(child) + "/fd/0")
		if err != nil {
			continue
		}
		anyAlive = true
		if pts := ptsOfLink(target); pts != "" {
			return pts, "slave device " + pts + " from child pid=" + strconv.Itoa(child) + " fd/0"
		}
	}
	if !anyAlive {
		prefix := "/proc/" + strconv.Itoa(pid) + "/fd"
		entries, err := os.ReadDir(prefix)
		if err == nil {
			for _, entry := range entries {
				if target, err := os.Readlink(prefix + "/" + entry.Name()); err == nil {
					if pts := ptsOfLink(target); pts != "" {
						return pts, "slave device " + pts + " from bridge pid=" + strconv.Itoa(pid)
					}
				}
			}
		}
	}
	return "", "slave device not determined"
}

func slaveHolders(pts string) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []string{"slave holders unknown:" + probeError(err)}
	}
	links, readErrors := 0, 0
	truncated := false
	pids := map[int]bool{}
scan:
	for _, entry := range entries {
		if !isNumericName(entry.Name()) {
			continue
		}
		fds, err := os.ReadDir("/proc/" + entry.Name() + "/fd")
		if err != nil {
			readErrors++
			continue
		}
		for _, fd := range fds {
			links++
			if links > 8192 {
				truncated = true
				break scan
			}
			target, err := os.Readlink("/proc/" + entry.Name() + "/fd/" + fd.Name())
			if err != nil {
				readErrors++
				continue
			}
			if target == pts {
				pids[pidNumber(entry.Name())] = true
			}
		}
	}
	holders := []string{}
	for _, pid := range sortedKeys(pids) {
		if len(holders) >= 16 {
			break
		}
		holders = append(holders, "holder "+procSummary(pid))
	}
	state := "holders=" + strconv.Itoa(len(pids))
	if len(pids) == 0 && readErrors > 0 {
		state = "holders=unknown"
	}
	return append(holders, fmt.Sprintf("slave %s %s readErrors=%d truncated=%t", pts, state, readErrors, truncated))
}

func sortedKeys(pids map[int]bool) []int {
	keys := make([]int, 0, len(pids))
	for pid := range pids {
		keys = append(keys, pid)
	}
	sort.Ints(keys)
	return keys
}

func isNumericName(name string) bool {
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return name != ""
}

func pidNumber(name string) int {
	value, _ := strconv.Atoi(name)
	return value
}
