package flakediag

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type outcome int

const (
	outcomeUnfinished outcome = iota
	outcomeCompleted
	outcomeFailed
)

func (o outcome) String() string {
	switch o {
	case outcomeFailed:
		return "failed"
	case outcomeCompleted:
		return "completed-ok"
	default:
		return "not-finished"
	}
}

// Flow reports per-flow outcome diagnostics at test cleanup. Failed wins over
// Complete regardless of call order, so deferred errors surface as failed.
type Flow struct {
	label   string
	render  func(full bool) string
	release func()
	mu      sync.Mutex
	outcome outcome
}

// Fail marks the flow failed; it wins over Complete in either order.
func (f *Flow) Fail() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcome = outcomeFailed
}

// Complete marks the flow successfully finished unless it already failed.
func (f *Flow) Complete() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outcome != outcomeFailed {
		f.outcome = outcomeCompleted
	}
}

func (f *Flow) snapshot() outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.outcome
}

type flowGroup struct {
	started time.Time
	scope   *FlowDumpScope
	mu      sync.Mutex
	flows   []*Flow
}

var groups sync.Map // *testing.T -> *flowGroup

// flowDumpScopes maps an exact *testing.T to its bound FlowDumpScope.
var flowDumpScopes sync.Map // *testing.T -> *FlowDumpScope

// FlowDumpScope deduplicates the shared goroutine dump across tests that bind
// to the same scope: only the first failing test's report carries the dump.
// The zero value is ready for use.
type FlowDumpScope struct {
	claimed atomic.Bool
}

// Bind associates t's flow report with this scope; call before the first
// StartFlow for t. The binding is removed when t finishes.
func (s *FlowDumpScope) Bind(t *testing.T) {
	flowDumpScopes.Store(t, s)
	t.Cleanup(func() { flowDumpScopes.Delete(t) })
}

// StartFlow registers a flow under t. The first StartFlow for a given exact
// *testing.T registers ONE cleanup for the whole group (which also deletes
// the group entry); later flows join in order without extra cleanups. Without
// Begin, timing falls back to the first registration time. render(full)
// supplies evidence; it is called with full=false only for completed flows
// and must be secret-free. release, when non-nil, always runs after all
// evidence is rendered, even on pass or render panic.
func StartFlow(t *testing.T, label string, render func(full bool) string, release func()) *Flow {
	flow := &Flow{label: label, render: render, release: release}
	group := &flowGroup{started: time.Now(), flows: []*Flow{flow}}
	if scope, ok := flowDumpScopes.Load(t); ok {
		group.scope = scope.(*FlowDumpScope)
	}
	if existing, loaded := groups.LoadOrStore(t, group); loaded {
		group = existing.(*flowGroup)
		group.mu.Lock()
		group.flows = append(group.flows, flow)
		group.mu.Unlock()
		return flow
	}
	t.Cleanup(func() {
		groups.Delete(t)
		reportFlow(t, group)
	})
	return flow
}

func reportFlow(t *testing.T, group *flowGroup) {
	failed := t.Failed()
	group.mu.Lock()
	flows := append([]*Flow(nil), group.flows...)
	group.mu.Unlock()
	dump := SafeGoroutineDump
	if group.scope != nil {
		scope := group.scope
		dump = func(limit int) string {
			if !scope.claimed.CompareAndSwap(false, true) {
				return ""
			}
			return SafeGoroutineDump(limit)
		}
	}
	renderFlowReport(failed, t.Logf, func() string { return EnvironmentLine(t, group.started) }, flows, dump)
}

// renderFlowReport emits failure-only diagnostics; on pass it stays silent
// and skips all probes. At most one goroutine dump is emitted per report,
// attached to the first failed flow, else the first unfinished flow, else
// standalone without blaming a flow; if the dump callback returns an empty
// string (e.g. a scoped group that does not own the dump), the section is
// omitted. dump is injected for deterministic tests.
func renderFlowReport(failed bool, logf func(string, ...any), environment func() string, flows []*Flow, dump func(limit int) string) {
	defer func() {
		for _, f := range flows {
			if f.release != nil {
				f.release()
			}
		}
	}()
	if !failed {
		return
	}
	dumpTarget := firstFailed(flows)
	if dumpTarget == nil {
		dumpTarget = firstUnfinished(flows)
	}
	body := []string{"flow outcomes:"}
	for _, f := range flows {
		body = append(body, fmt.Sprintf("  %s: %s", f.label, f.snapshot()))
	}
	body = append(body, "flow evidence:")
	for _, f := range flows {
		out := f.snapshot()
		body = append(body, fmt.Sprintf("flow: %s outcome=%s", f.label, out))
		if out == outcomeCompleted {
			body = append(body, safeRender(f, false)...)
			continue
		}
		body = append(body, safeRender(f, true)...)
		if f == dumpTarget {
			if d := dump(64 * 1024); d != "" {
				body = append(body, "goroutine dump:", d)
			}
		}
	}
	if dumpTarget == nil {
		if d := dump(64 * 1024); d != "" {
			body = append(body, "all flows completed; test-level goroutine dump:", d)
		}
	}
	var nonEmpty []string
	for _, l := range body {
		if l != "" {
			nonEmpty = append(nonEmpty, l)
		}
	}
	logf("failure diagnostics:\n%s\n%s", environment(), strings.Join(nonEmpty, "\n"))
}

func firstFailed(flows []*Flow) *Flow {
	for _, f := range flows {
		if f.snapshot() == outcomeFailed {
			return f
		}
	}
	return nil
}

func firstUnfinished(flows []*Flow) *Flow {
	for _, f := range flows {
		if f.snapshot() == outcomeUnfinished {
			return f
		}
	}
	return nil
}

func safeRender(f *Flow, full bool) []string {
	if f.render == nil {
		return nil
	}
	result := []string{"render panicked (details omitted)"}
	func() {
		defer func() {
			_ = recover()
		}()
		result = []string{f.render(full)}
	}()
	return result
}

// SafeGoroutineDump renders the goroutine profile with raw arguments,
// addresses, and source paths stripped: tabbed location lines are omitted,
// and function names keep only the component after the last slash. Output is
// truncated to limit bytes. limit<=0 defaults to 64 KiB.
func SafeGoroutineDump(limit int) string {
	if limit <= 0 {
		limit = 64 * 1024
	}
	sanitized := sanitizeDump(dropTruncationSuffix(GoroutineDump(4 * limit)))
	return limitLines(sanitized, limit)
}

const dumpTruncationMarker = "\n...truncated (full "

// dropTruncationSuffix removes the truncation marker and the partial final
// frame line before it, so a mid-frame cut never reaches sanitizing.
func dropTruncationSuffix(raw string) string {
	i := strings.Index(raw, dumpTruncationMarker)
	if i < 0 {
		return raw
	}
	cut := raw[:i]
	if j := strings.LastIndexByte(cut, '\n'); j >= 0 {
		cut = cut[:j]
	}
	return cut + "\n"
}

// limitLines enforces len(result) <= limit (when limit fits the marker) by
// cutting at a line boundary and appending a bounded marker.
func limitLines(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	marker := "...truncated"
	if limit <= len(marker) {
		return s[:limit]
	}
	cut := s[:limit-len(marker)]
	if i := strings.LastIndexByte(cut, '\n'); i >= 0 {
		cut = cut[:i+1]
	}
	return cut + marker
}

// sanitizeDump strips each non-location frame line: it finds the argument
// delimiter as the parenthesis balanced against the final ")" so addresses
// nested inside aggregate argument text are removed along with the rest of
// the args, while receiver parens like pkg.(*T).Fn are left in the name.
func sanitizeDump(raw string) string {
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "\t") {
			continue
		}
		// Conservative: a line with an unbalanced arg list (e.g. a frame cut
		// mid-arguments) may hold raw addresses; omit it entirely.
		if strings.Contains(line, "(") && argDelimiter(line) == "" {
			continue
		}
		sb.WriteString(stripFrame(line))
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

func stripFrame(line string) string {
	if prefix, rest, found := strings.Cut(line, "created by "); found {
		if head := argDelimiter(rest); head != "" {
			rest = head + "(...)"
		}
		return prefix + "created by " + stripName(rest)
	}
	if head := argDelimiter(line); head != "" {
		return stripName(head) + "(...)"
	}
	return stripName(line)
}

// argDelimiter returns the frame text before the "(" that opens the trailing
// argument list, balancing against the final ")"; empty when there is none.
func argDelimiter(line string) string {
	if !strings.HasSuffix(line, ")") {
		return ""
	}
	depth := 0
	for i := len(line) - 1; i >= 0; i-- {
		switch line[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return line[:i]
			}
		}
	}
	return ""
}

// stripName keeps only the component after the last slash of a qualified
// name, removing package import path components.
func stripName(s string) string {
	if slash := strings.LastIndex(s, "/"); slash >= 0 {
		return s[slash+1:]
	}
	return s
}
