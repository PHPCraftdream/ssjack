package ownerrotationtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const rotationEventLimit = 512

type rotationCaptureStats struct {
	known, overflow, readDone  bool
	retained, total, discarded int
}

type rotationChildID struct {
	role string
	seq  int
}

type rotationSnapshotStats struct {
	phase                                  rotationPhase
	revision, savedRevision                uint64
	ownerError, ownerPending, ownerBusy    bool
	databaseError, databasePending, digest bool
}

type rotationCounts struct {
	known              bool
	observed, expected int
}

type rotationEvidence struct {
	diskPhase      rotationPhase
	snapshot       rotationSnapshotStats // nonempty phase means a successful read
	attempts       int
	lastRPCFailure string
	handshakes     rotationCounts
	mcpOperation   rotationMCPEvidence
}

const (
	rotationMCPPrefix  = "SSJACK-ROTATION-MCP-V2 "
	rotationMCPScalars = "%x,%x,%02x,%x,%x,%x,%x,%x!"
	// At most 191 printable bytes: 23-byte prefix, 16 op + 23 class bytes,
	// nine commas, two flag digits, two nonnegative and five signed hex ints,
	// and the terminator.
	rotationMCPFrameLimit = len(rotationMCPPrefix) + 16 + 23 + 9 + 2 + 2*16 + 5*17 + 1
)

type rotationMCPEvidence struct {
	operation, class                 string
	attempts, exitCode               int
	elapsedNS                        int64
	valid, observed                  bool
	done, stdoutMore, stderrMore     bool
	stdoutLost, stderrLost, sameJob  bool
	requestedStdout, requestedStderr int64
	returnedStdout, returnedStderr   int64
}

func (e rotationMCPEvidence) human() string {
	if e.operation == "" {
		return rotationMCPPrefix + "NONE"
	}
	base := fmt.Sprintf(rotationMCPPrefix+"op=%s class=%s attempts=%d elapsed-ns=%d", e.operation, e.class, e.attempts, e.elapsedNS)
	if !e.isRead() {
		return base
	}
	return base + fmt.Sprintf(" valid=%t observed=%t done=%t stdout-more=%t stderr-more=%t requested-stdout=%d requested-stderr=%d returned-stdout=%d returned-stderr=%d stdout-lost=%t stderr-lost=%t same-job=%t exit=%d",
		e.valid, e.observed, e.done, e.stdoutMore, e.stderrMore, e.requestedStdout, e.requestedStderr, e.returnedStdout, e.returnedStderr,
		e.stdoutLost, e.stderrLost, e.sameJob, e.exitCode)
}

// The order of these fields defines the wire flag bits, least significant first.
func (e *rotationMCPEvidence) flagFields() [8]*bool {
	return [8]*bool{&e.valid, &e.observed, &e.done, &e.stdoutMore, &e.stderrMore, &e.stdoutLost, &e.stderrLost, &e.sameJob}
}

func (e rotationMCPEvidence) frame() string {
	if !e.allowed() {
		return rotationMCPPrefix + "NONE!"
	}
	var flags uint8
	for i, field := range e.flagFields() {
		if *field {
			flags |= 1 << i
		}
	}
	return rotationMCPPrefix + e.operation + "," + e.class + "," + fmt.Sprintf(rotationMCPScalars,
		e.attempts, e.elapsedNS, flags, e.requestedStdout, e.requestedStderr, e.returnedStdout, e.returnedStderr, e.exitCode)
}

func decodeRotationMCP(frame []byte) (rotationMCPEvidence, bool) {
	var e rotationMCPEvidence
	if len(frame) > rotationMCPFrameLimit || !bytes.HasPrefix(frame, []byte(rotationMCPPrefix)) {
		return e, false
	}
	text := string(frame)
	if text == e.frame() {
		return e, true
	}
	operation, rest, ok := strings.Cut(text[len(rotationMCPPrefix):], ",")
	if !ok {
		return e, false
	}
	class, scalars, ok := strings.Cut(rest, ",")
	if !ok {
		return e, false
	}
	e.operation, e.class = operation, class
	var flags uint8
	// Scanning needs no field width; the canonical re-encoding enforces two flag digits.
	n, err := fmt.Sscanf(scalars, "%x,%x,%x,%x,%x,%x,%x,%x!", &e.attempts, &e.elapsedNS, &flags,
		&e.requestedStdout, &e.requestedStderr, &e.returnedStdout, &e.returnedStderr, &e.exitCode)
	for i, field := range e.flagFields() {
		*field = flags&(1<<i) != 0
	}
	if err != nil || n != 8 || !e.allowed() {
		return rotationMCPEvidence{}, false
	}
	// Re-encoding rejects noncanonical tokens and trailing text that Sscanf can ignore.
	if text != e.frame() {
		return rotationMCPEvidence{}, false
	}
	return e, true
}

func (e rotationMCPEvidence) isRead() bool {
	switch e.operation {
	case "initial-job", "new-job", "old-job-liveness", "release-job", "old-job-finish":
		return true
	default:
		return false
	}
}

// allowed is the shared encoder/decoder schema. Only tool calls can report tool failures.
func (e rotationMCPEvidence) allowed() bool {
	if e.attempts <= 0 || e.elapsedNS < 0 || (e.valid && !e.observed) ||
		(e.observed && !e.valid && e.attempts < 2) || (!e.done && e.exitCode != 0) ||
		(!e.observed && (e.done || e.stdoutMore || e.stderrMore || e.stdoutLost || e.stderrLost || e.sameJob ||
			e.requestedStdout != 0 || e.requestedStderr != 0 || e.returnedStdout != 0 || e.returnedStderr != 0)) {
		return false
	}
	if (!e.isRead() || e.operation == "old-job-liveness") && e.attempts != 1 {
		return false
	}
	var toolFailure bool
	switch e.class {
	case "transport-error", "nil-result", "tool-error", "result-text-error", "parse-error":
		toolFailure = true
	}
	if e.isRead() {
		if !e.valid {
			return toolFailure
		}
		switch e.class {
		case "matched", "job-mismatch":
			return true
		case "unexpected-done":
			return e.operation == "old-job-liveness"
		case "stdout-mismatch":
			return e.operation != "old-job-liveness" && e.operation != "release-job"
		case "nonzero-exit", "stdout-lost", "stderr-lost", "stdout-offset-backwards", "stderr-offset-backwards", "deadline", "canceled":
			return e.operation != "old-job-liveness"
		default:
			return false
		}
	}
	if e.observed {
		return false
	}
	switch e.operation {
	case "targets":
		return toolFailure || e.class == "matched" || e.class == "target-cardinality"
	case "exec-initial", "exec-hold", "exec-new", "exec-release":
		return toolFailure || e.class == "matched" || e.class == "missing-job-id"
	case "cancel":
		return toolFailure || e.class == "matched"
	case "bootstrap":
		return e.class == "matched" || e.class == "bootstrap-error"
	case "server-connect":
		return e.class == "matched" || e.class == "server-error"
	case "client-connect":
		return e.class == "matched" || e.class == "client-error"
	case "control":
		return e.class == "control-read-error" || e.class == "unexpected-command"
	default:
		return false
	}
}

func inspectRotationMCP(c *ownerterminal.Capture) (e rotationMCPEvidence, found bool) {
	c.Inspect(func(data []byte, _ int, _ bool) {
		prefix := []byte(rotationMCPPrefix)
		start := bytes.Index(data, prefix)
		if start < 0 || bytes.Contains(data[start+len(prefix):], prefix) {
			return
		}
		candidate := data[start:]
		if len(candidate) > rotationMCPFrameLimit {
			candidate = candidate[:rotationMCPFrameLimit]
		}
		if end := bytes.IndexByte(candidate, '!'); end >= 0 {
			e, found = decodeRotationMCP(candidate[:end+1])
		}
	})
	return e, found
}

type rotationPhase string

func safeRotationPhase(phase string) rotationPhase {
	switch phase {
	case vault.RotationPrepared, vault.RotationAttempting, vault.RotationUnknown,
		vault.RotationAdded, vault.RotationVerified, vault.RotationCommitted,
		vault.RotationComplete, vault.RotationCancelled, vault.RotationArchived:
		return rotationPhase(phase)
	default:
		return "unrecognized"
	}
}

type rotationEvent struct {
	name, class string
	child       rotationChildID
	at, elapsed time.Duration
	timed       bool
	capture     rotationCaptureStats
	evidence    rotationEvidence
}

// The timeline contains only fixed test labels and scalar observations made by
// existing operations. Rendering never touches a terminal or capture.
type rotationDiag struct {
	mu      sync.Mutex
	origin  time.Time
	events  []rotationEvent
	omitted int
}

func newRotationDiag(t *testing.T) *rotationDiag {
	d := &rotationDiag{origin: time.Now()}
	flakediag.OnFailure(t, d.render)
	return d
}

func (d *rotationDiag) mark(name string) { d.outcome(name, "mark") }

// name and class must be fixed, non-secret test labels.
func (d *rotationDiag) outcome(name, class string) {
	d.record(name, class, rotationChildID{}, time.Time{}, rotationCaptureStats{})
}

func (d *rotationDiag) record(name, class string, child rotationChildID, start time.Time, stats rotationCaptureStats) {
	d.recordEvidence(name, class, child, start, stats, rotationEvidence{})
}

func (d *rotationDiag) observe(name, class string, start time.Time, evidence rotationEvidence) {
	d.recordEvidence(name, class, rotationChildID{}, start, rotationCaptureStats{}, evidence)
}

func (d *rotationDiag) recordEvidence(name, class string, child rotationChildID, start time.Time, stats rotationCaptureStats, evidence rotationEvidence) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.events) >= rotationEventLimit {
		d.omitted++
		return
	}
	now := time.Now()
	e := rotationEvent{name: name, class: class, child: child, at: now.Sub(d.origin), capture: stats, evidence: evidence}
	if !start.IsZero() {
		e.timed = true
		e.elapsed = now.Sub(start)
	}
	d.events = append(d.events, e)
}

func rotationContextOutcome(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return ""
	}
}

func rotationOperationOutcome(err error, success, failure string) string {
	if err == nil {
		return success
	}
	if class := rotationContextOutcome(err); class != "" {
		return class
	}
	return failure
}

func rotationExitOutcome(err error, closing bool) string {
	switch {
	case err == nil && closing:
		return "closed-cleanly"
	case err == nil:
		return "exited-cleanly"
	case errors.Is(err, ownerterminal.ErrTerminal):
		return "exit-or-backend-wait-failed"
	case rotationContextOutcome(err) == "deadline":
		return "unjoined-deadline"
	case rotationContextOutcome(err) == "canceled":
		return "unjoined-canceled"
	case closing:
		return "close-error"
	default:
		return "wait-error"
	}
}

func (d *rotationDiag) render() string {
	var sb strings.Builder
	sb.WriteString("owner rotation rig evidence\nharness timeline:\n")
	d.mu.Lock()
	for _, e := range d.events {
		fmt.Fprintf(&sb, "  at+%s name=%q outcome=%s", e.at.Round(time.Millisecond), e.name, e.class)
		if e.child.seq != 0 {
			fmt.Fprintf(&sb, " child=%s#%d", e.child.role, e.child.seq)
		}
		if e.timed {
			fmt.Fprintf(&sb, " elapsed=%s", e.elapsed.Round(time.Millisecond))
		}
		if c := e.capture; c.known {
			fmt.Fprintf(&sb, " capture(retained=%d total=%d overflow=%t read-done-observed=%t discarded=%d)", c.retained, c.total, c.overflow, c.readDone, c.discarded)
		}
		if e.name == "keeper-mcp-operation" && e.class == "received" {
			fmt.Fprintf(&sb, " %s", e.evidence.mcpOperation.human())
		}
		if v := e.evidence; v != (rotationEvidence{}) {
			if v.diskPhase != "" {
				fmt.Fprintf(&sb, " disk(phase=%s)", v.diskPhase)
			}
			if s := v.snapshot; s.phase != "" {
				fmt.Fprintf(&sb, " snapshot(phase=%s revision=%d saved-revision=%d owner-error=%t owner-pending=%t owner-busy=%t database-error=%t database-pending=%t cipher-digest-present=%t)", s.phase, s.revision, s.savedRevision, s.ownerError, s.ownerPending, s.ownerBusy, s.databaseError, s.databasePending, s.digest)
			}
			if v.attempts != 0 {
				fmt.Fprintf(&sb, " attempts=%d last-snapshot-rpc-failure=%s", v.attempts, v.lastRPCFailure)
			}
			if c := v.handshakes; c.known {
				fmt.Fprintf(&sb, " handshakes(observed=%d expected=%d)", c.observed, c.expected)
			}
		}
		sb.WriteByte('\n')
	}
	if d.omitted > 0 {
		fmt.Fprintf(&sb, "  omitted=%d\n", d.omitted)
	}
	d.mu.Unlock()
	sb.WriteString("goroutine dump:\n" + rotationGoroutineDump())
	return sb.String()
}

// Runtime frames end in an argument list; preserve parenthesized method
// receivers but discard the argument suffix, including a truncated suffix.
func rotationGoroutineDump() string {
	var sb strings.Builder
	for _, line := range strings.Split(flakediag.GoroutineDump(64*1024), "\n") {
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "...truncated ") {
			if name, rest, ok := strings.Cut(line, "("); ok {
				line = name
				if receiver, tail, ok := strings.Cut(rest, ")."); ok && strings.HasSuffix(name, ".") && !strings.ContainsAny(receiver, "(), \t") {
					method, _, _ := strings.Cut(tail, "(")
					line += "(" + receiver + ")." + method
				}
			}
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}
