//go:build linux || darwin

package fixture

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

const (
	execDiagnosticLimit = 64
	fixtureEventLimit   = 64
	goroutineDumpLimit  = 16 * 1024
	execStepLimit       = 10
)

type diagnosticStep struct {
	at    time.Duration
	state string
}

type streamDiagnostic struct {
	bytes int64
	issue string
}

type execDiagnostic struct {
	id      uint64
	op      string
	steps   [execStepLimit]diagnosticStep
	nsteps  int
	pid     int
	process processDiagnostic
	ioState string
	stdin   streamDiagnostic
	stdout  streamDiagnostic
	stderr  streamDiagnostic
}

type processDiagnostic struct {
	kind   string
	code   int
	signal int
}

func processResult(state *os.ProcessState) processDiagnostic {
	if state == nil {
		return processDiagnostic{kind: "none"}
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return processDiagnostic{kind: "signaled", signal: int(status.Signal())}
	}
	if code := state.ExitCode(); code >= 0 {
		return processDiagnostic{kind: "exited", code: code}
	}
	return processDiagnostic{kind: "unknown"}
}

type fixtureEvent struct {
	at              time.Duration
	op, direction   string
	kind            string
	id              uint64
	threshold, seen int64
}

type waitDiagnostic struct {
	start, last time.Duration
	op, state   string
	count       int
}

func commandOperation(command string) string {
	switch {
	case strings.HasPrefix(command, "set -eu\nfor tool in cat find xargs tar rm mv wc mkdir chmod ln; do"):
		return "probe"
	case strings.Contains(command, "\n\tprintf 'SSJACK-STAGE created\\n'"):
		return "ensure-staging"
	case strings.Contains(command, "\ntar -c -f - . || exit 24"):
		return "tar-out"
	case strings.Contains(command, "\ntar -x --no-same-owner --no-same-permissions -f - || exit 24"):
		return "tar-in"
	case strings.Contains(command, "\nif ln \"$src\" \"$dst\"") || strings.Contains(command, "\nif perl -e 'exit(link(") || strings.Contains(command, "\nif perl -e 'exit(rename(") ||
		strings.Contains(command, "\n"+core.PerlRenameCommand+" \"$src\" \"$dst\" || exit 24\n") ||
		(strings.Contains(command, "\nsrc=") && strings.Contains(command, "\ndst=") && strings.Contains(command, "\nmv -T -f \"$src\" \"$dst\"")):
		return "publish"
	case strings.Contains(command, "\nif mkdir -m 700 \"$path\""):
		return "create-staging"
	case command == `assembled.$rnd` || strings.Contains(command, "\nasm=\"$stage/assembled.$rnd.tmp\""):
		return "assemble"
	case strings.Contains(command, "\nprintf 'SSJACK-LIST 1\\n'"):
		return "list-parts"
	case strings.Contains(command, "\nif ! (umask 077 && cat > \"$tmp\"); then"):
		return "upload-part"
	case strings.Contains(command, "\ndd if=\"$path\" bs=\"$bs\" skip=\"$skip\" count=1 2>/dev/null") ||
		strings.Contains(command, "\ntail -c \"+$start\" \"$path\" 2>/dev/null | head -c \"$len\""):
		return "read-range"
	case strings.Contains(command, "\ncat > \"$path\" || exit 24") || command == "cat > ":
		return "write-file"
	case strings.Contains(command, "\ncat \"$path\" || exit 24") || command == `cat "$path"`:
		return "read-file"
	case strings.Contains(command, "\nif ! wc_count \"$asm\"; then"):
		return "assemble"
	case strings.Contains(command, "\nif ! printf 'SSJACK-STAGE created\\n'"):
		return "ensure-staging"
	case strings.Contains(command, "\nprintf 'SSJACK-GC %s\\n'"):
		return "gc-staging"
	case strings.Contains(command, "\nrm -rf \"$stage\" || exit 24") || strings.Contains(command, "\nrm -rf \"$path\" || exit 24"):
		return "remove-staging"
	case strings.Contains(command, "\n\trm -f \"$stage/$p\" || exit 24"):
		return "remove-parts"
	case strings.Contains(command, "\ndf -P -k \"$parent\" 2>/dev/null || :"):
		return "disk-space"
	case strings.Contains(command, "\nstat -c '%s %Y' \"$path\"") || strings.Contains(command, "\nstat -f '%z %m' \"$path\""):
		return "stat-source"
	case command == `wc -c < "$path"` || strings.Contains(command, "\nwc -c < \"$path\""):
		return "stat-file"
	default:
		return "other"
	}
}

func errorClass(err error) string {
	var timeout net.Error
	var exit *exec.ExitError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrShortWrite):
		return "short-write"
	case errors.Is(err, os.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		return "not-found"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe), errors.Is(err, syscall.EPIPE):
		return "closed"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.As(err, &exit):
		return "process-exit"
	default:
		return "error"
	}
}

func (s *ExecServer) recordExec(command string) *execDiagnostic {
	op := commandOperation(command)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalExecs++
	s.activeExecs++
	d := &execDiagnostic{id: s.totalExecs, op: op, process: processDiagnostic{kind: "none"}, ioState: "not-started"}
	s.diagnostics[(d.id-1)%execDiagnosticLimit] = d
	s.stepLocked(d, "accepted")
	return d
}

func (s *ExecServer) noteEntered(command string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entered = append(s.entered, command)
	close(s.seen)
	s.seen = make(chan struct{})
}

func (s *ExecServer) stepLocked(d *execDiagnostic, state string) {
	d.steps[d.nsteps] = diagnosticStep{time.Since(s.startedAt), state}
	d.nsteps++
}

func (s *ExecServer) step(d *execDiagnostic, state string) {
	s.mu.Lock()
	s.stepLocked(d, state)
	s.mu.Unlock()
}

func (s *ExecServer) eventLocked(e fixtureEvent) {
	e.at = time.Since(s.startedAt)
	s.events[s.totalEvents%fixtureEventLimit] = e
	s.totalEvents++
}

func (s *ExecServer) faultCallback(d *execDiagnostic, kind, direction string, threshold int64) func(int64) {
	return func(seen int64) {
		s.mu.Lock()
		s.eventLocked(fixtureEvent{kind: kind, direction: direction, threshold: threshold, seen: seen, op: d.op, id: d.id})
		s.mu.Unlock()
	}
}

type streamObserver func(int, string)

func (s *ExecServer) observeStream(stream *streamDiagnostic) streamObserver {
	return func(n int, class string) {
		s.mu.Lock()
		stream.bytes += int64(n)
		if class != "ok" {
			stream.issue = class
		}
		s.mu.Unlock()
	}
}

type diagnosticReader struct {
	upstream io.Reader
	observe  streamObserver
}

func (r *diagnosticReader) Read(p []byte) (int, error) {
	n, err := r.upstream.Read(p)
	if n < 0 || n > len(p) {
		r.observe(0, "invalid-count")
		return n, err
	}
	if class := errorClass(err); class == "eof" {
		r.observe(n, "ok")
	} else {
		r.observe(n, class)
	}
	return n, err
}

type diagnosticWriter struct {
	downstream io.Writer
	observe    streamObserver
}

func (w *diagnosticWriter) Write(p []byte) (int, error) {
	n, err := w.downstream.Write(p)
	class := errorClass(err)
	if n < 0 || n > len(p) {
		w.observe(0, "invalid-count")
		return n, err
	}
	if n < len(p) && err == nil {
		class = "short-write"
	}
	w.observe(n, class)
	return n, err
}

func formatExecDiagnostic(d execDiagnostic) string {
	var b strings.Builder
	fmt.Fprintf(&b, "remote exec %d: op=%s pid=%d process=%s", d.id, d.op, d.pid, d.process.kind)
	switch d.process.kind {
	case "exited":
		fmt.Fprintf(&b, " exit=%d", d.process.code)
	case "signaled":
		fmt.Fprintf(&b, " signal=%d", d.process.signal)
	}
	fmt.Fprintf(&b, " io=%s stdin=%d stdout=%d stderr=%d", d.ioState, d.stdin.bytes, d.stdout.bytes, d.stderr.bytes)
	for i, stream := range [...]streamDiagnostic{d.stdin, d.stdout, d.stderr} {
		if stream.issue != "" {
			fmt.Fprintf(&b, " %s-error=%s", [...]string{"stdin", "stdout", "stderr"}[i], stream.issue)
		}
	}
	return b.String()
}

type timelineEntry struct {
	at      time.Duration
	id      uint64
	step    string
	event   fixtureEvent
	isEvent bool
}

func formatTimeline(records []execDiagnostic, events []fixtureEvent) string {
	entries := make([]timelineEntry, 0, len(records)*execStepLimit+len(events))
	for _, record := range records {
		if record.id == 0 {
			continue
		}
		for _, step := range record.steps[:record.nsteps] {
			entries = append(entries, timelineEntry{at: step.at, id: record.id, step: step.state})
		}
	}
	for _, event := range events {
		entries = append(entries, timelineEntry{at: event.at, event: event, isEvent: true})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].at < entries[j].at })
	var b strings.Builder
	for _, entry := range entries {
		if entry.isEvent {
			e := entry.event
			fmt.Fprintf(&b, "+%s:%s op=%s exec=%d direction=%s threshold=%d observed=%d\n",
				e.at, e.kind, e.op, e.id, e.direction, e.threshold, e.seen)
		} else {
			fmt.Fprintf(&b, "+%s exec=%d step=%s\n", entry.at, entry.id, entry.step)
		}
	}
	return b.String()
}

// RegisterFailureDiagnostics registers a failure snapshot ahead of earlier cleanups.
// Its rendered goroutine dump is argument- and path-free (flakediag.SafeGoroutineDump).
func (s *ExecServer) RegisterFailureDiagnostics(t *testing.T) {
	registeredAt := time.Now()
	t.Cleanup(func() {
		if t.Failed() {
			s.reportOnce.Do(func() {
				t.Logf("failure diagnostics:\n%s\n%s", flakediag.EnvironmentLine(t, registeredAt), s.renderDiagnostics())
			})
		}
	})
}

func orderedExecRecords(records [execDiagnosticLimit]*execDiagnostic, total uint64) []execDiagnostic {
	count := min(total, execDiagnosticLimit)
	ordered := make([]execDiagnostic, 0, count)
	for id := total - count + 1; id <= total; id++ {
		d := records[(id-1)%execDiagnosticLimit]
		if d != nil && d.id == id {
			ordered = append(ordered, *d)
		}
	}
	return ordered
}

func (s *ExecServer) renderDiagnostics() string {
	var snapshot [execDiagnosticLimit]*execDiagnostic
	s.mu.Lock()
	elapsed, active, running := time.Since(s.startedAt), len(s.conns), s.activeExecs
	total, eventTotal := s.totalExecs, s.totalEvents
	events := s.events
	entered, idle := s.lastEnteredWait, s.lastIdleWait
	for i, d := range s.diagnostics {
		if d != nil {
			copy := *d
			snapshot[i] = &copy
		}
	}
	s.mu.Unlock()
	records := orderedExecRecords(snapshot, total)

	var b strings.Builder
	fmt.Fprintf(&b, "exec fixture +%s: active-conns=%d active-execs=%d accepted=%d older-execs=%d older-events=%d\n",
		elapsed, active, running, total, total-min(total, execDiagnosticLimit), eventTotal-min(eventTotal, fixtureEventLimit))
	for _, d := range records {
		if d.id == 0 {
			continue
		}
		fmt.Fprintln(&b, formatExecDiagnostic(d))
	}
	eventRecords := make([]fixtureEvent, 0, min(eventTotal, fixtureEventLimit))
	for i := eventTotal - min(eventTotal, fixtureEventLimit); i < eventTotal; i++ {
		eventRecords = append(eventRecords, events[i%fixtureEventLimit])
	}
	b.WriteString(formatTimeline(records, eventRecords))
	formatWait := func(name string, w waitDiagnostic) {
		if w.state != "" {
			fmt.Fprintf(&b, "%s op=%s budget=%s start=+%s last=+%s condition=%s count=%d\n",
				name, w.op, WaitBudget, w.start, w.last, w.state, w.count)
		}
	}
	formatWait("WaitEntered", entered)
	formatWait("WaitIdle", idle)
	fmt.Fprintf(&b, "goroutines:\n%s", flakediag.SafeGoroutineDump(goroutineDumpLimit))
	return b.String()
}
