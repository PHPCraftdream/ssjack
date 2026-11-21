package ownertest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestOwnerNativeCommandChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_CHILD") != "1" {
		t.Skip("real native owner terminal child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		nativeChildFatal(t, ownerChildStdinNotTTY, "owner child stdin was not a terminal")
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		nativeChildFatal(t, ownerChildStdoutNotTTY, "owner child stdout was not a terminal")
	}
	// Like the existing tmux driver's stty -echo, protect the prompt boundary.
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		nativeChildFatal(t, ownerChildRawSetup, "owner child could not configure raw terminal mode")
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	ownerCommandPTYChild(t)
}

// ownerCommandPTYChild is invoked only by the synthetic native owner-command test.
func ownerCommandPTYChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_COMMAND_CHILD") != "1" {
		t.Skip("synthetic owner-command terminal child only")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
	defer cancel()
	code, err := cli.Run(ctx, args)
	if os.Getenv("SSJACK_OWNER_COMMAND_CANCEL") == "1" {
		if code != 1 {
			nativeChildFatal(t, cancelChildCLICode, "cancelled owner command returned an unexpected CLI code: got=%d want=1", code)
		}
		if !errors.Is(err, ownercommand.ErrCancelled) {
			nativeChildFatal(t, cancelChildCLIVerdict, "cancelled owner command did not return the cancellation verdict")
		}
		return
	}
	if code != 0 {
		nativeChildFatal(t, applyChildCLICode, "confirmed owner command returned an unexpected CLI code: got=%d want=0", code)
	}
	if err != nil {
		nativeChildFatal(t, applyChildCLIError, "confirmed owner command returned an error")
	}
}

type nativeScreenSnapshot struct {
	elapsed time.Duration
	stage   string
	bytes   int
	partial bool
}

type nativeTerminalTrace struct {
	started          time.Time
	terminal         *ownerterminal.Terminal
	capture          *ownerterminal.Capture
	events           strings.Builder
	snapshots        []nativeScreenSnapshot
	fieldTimeline    strings.Builder
	firstFieldChange string
	screenRows       string
	screenNote       string
	childState       string
	cleaned          bool
	failureMarkers   []nativeFailureMarker
	flow             *flakediag.Flow
}

type nativeFailureMarker struct{ class, text string }

type nativeChildFailure string

const (
	ownerChildStdinNotTTY  nativeChildFailure = "owner-stdin-not-tty"
	ownerChildStdoutNotTTY nativeChildFailure = "owner-stdout-not-tty"
	ownerChildRawSetup     nativeChildFailure = "owner-raw-setup"
	cancelChildCLICode     nativeChildFailure = "cancel-cli-code"
	cancelChildCLIVerdict  nativeChildFailure = "cancel-cli-verdict"
	applyChildCLICode      nativeChildFailure = "apply-cli-code"
	applyChildCLIError     nativeChildFailure = "apply-cli-error"

	interactiveChildStdinNotTTY  nativeChildFailure = "interactive-stdin-not-tty"
	interactiveChildStdoutNotTTY nativeChildFailure = "interactive-stdout-not-tty"
	interactiveChildRawSetup     nativeChildFailure = "interactive-raw-setup"
)

func (class nativeChildFailure) marker() string {
	return "[native-child-failure:" + string(class) + "]"
}

// Pass only fixed classes and safe descriptions; never pass raw errors or values.
func nativeChildFatal(t *testing.T, class nativeChildFailure, format string, args ...any) {
	t.Helper()
	t.Fatalf("%s %s", class.marker(), fmt.Sprintf(format, args...))
}

func (trace *nativeTerminalTrace) addChildFailureMarkers(classes ...nativeChildFailure) {
	for _, class := range classes {
		trace.addFailureMarker(string(class), class.marker())
	}
}

func (trace *nativeTerminalTrace) addOwnerCommandChildFailureMarkers() {
	trace.addChildFailureMarkers(ownerChildStdinNotTTY, ownerChildStdoutNotTTY, ownerChildRawSetup,
		cancelChildCLICode, cancelChildCLIVerdict, applyChildCLICode, applyChildCLIError)
}

func (trace *nativeTerminalTrace) addInteractiveTerminalFailureMarkers() {
	trace.addChildFailureMarkers(interactiveChildStdinNotTTY, interactiveChildStdoutNotTTY, interactiveChildRawSetup)
}

func (trace *nativeTerminalTrace) addFailureMarker(class, text string) {
	if text != "" {
		trace.failureMarkers = append(trace.failureMarkers, nativeFailureMarker{class, text})
	}
}

// Labels, stages, operations and diagnostic messages are static, printable
// test descriptions. Never interpolate matchers, terminal data or raw errors.
// newNativeTerminalTrace and attach live beside the other trace helpers in
// native_keeper_shell_fullprofile_test.go to keep this file under its line cap.
func startNativeTerminal(t, diagnostics *testing.T, ctx context.Context, label string, command ownerterminal.Command) *nativeTerminalTrace {
	t.Helper()
	trace := newNativeTerminalTrace(diagnostics, label)
	trace.attach(t, ctx, command)
	return trace
}

func (trace *nativeTerminalTrace) failureEvidence(label string, full bool) string {
	endpoint := "capture unavailable\n"
	if trace.capture != nil {
		trace.capture.Inspect(func(data []byte, total int, overflow bool) {
			endpoint = fmt.Sprintf("capture retained=%d total=%d overflow=%t retained-digest=%s\n",
				len(data), total, overflow, flakediag.Short(data))
			for _, marker := range trace.failureMarkers {
				if bytes.Contains(data, []byte(marker.text)) {
					endpoint += "capture-class=" + marker.class + "\n"
				}
			}
			if full {
				trace.replayScreenSnapshots(data)
			}
		})
	}
	if !full {
		return label + " completed events:\n" + flakediag.Tail(trace.events.String(), 4<<10) + endpoint
	}
	if trace.cleaned {
		endpoint += "child-after-cleanup=" + trace.probeChildState() + "\n"
	}
	return label + " timeline:\n" + flakediag.Tail(trace.events.String(), 16<<10) + endpoint +
		"credential field state timeline:\n" + trace.fieldTimeline.String() + trace.firstFieldChange +
		"last snapshot screen:\n" + trace.screenNote + trace.screenRows
}
func nativeResultClass(err error, other string) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	default:
		return other
	}
}

func (trace *nativeTerminalTrace) record(snapshot nativeScreenSnapshot, stage, format string, args ...any) {
	const maxSnapshots = 96
	if len(trace.snapshots) == maxSnapshots {
		copy(trace.snapshots, trace.snapshots[1:])
		trace.snapshots = trace.snapshots[:maxSnapshots-1]
	}
	trace.snapshots = append(trace.snapshots, snapshot)
	fmt.Fprintf(&trace.events, "+%s %s ", snapshot.elapsed, stage)
	fmt.Fprintf(&trace.events, format, args...)
	trace.events.WriteByte('\n')
}

func (trace *nativeTerminalTrace) recordCaptured(stage, operation, format string, args ...any) {
	snapshot := nativeScreenSnapshot{elapsed: time.Since(trace.started), stage: stage}
	if trace.capture != nil {
		trace.capture.Inspect(func(data []byte, _ int, overflow bool) {
			snapshot.bytes, snapshot.partial = len(data), overflow
		})
	}
	if operation != "" {
		snapshot.stage += "/" + operation
		stage += " " + operation
	}
	trace.record(snapshot, stage, format+"capture-bytes=%d", append(args, snapshot.bytes)...)
}

// write consumes and clears data; clone inputs the caller needs for leak checks.
func (trace *nativeTerminalTrace) write(t *testing.T, stage string, data []byte) {
	t.Helper()
	defer clear(data)
	trace.recordCaptured(stage, "write-attempt", "requested=%d ", len(data))
	n, err := trace.terminal.Input.Write(data)
	class := nativeResultClass(err, "write-error")
	if err == nil && n != len(data) {
		class = "short-write"
	}
	trace.recordCaptured(stage, "write-result", "requested=%d written=%d class=%s ", len(data), n, class)
	report := trace.report(t)
	if err != nil {
		report.Fatalf("%s: terminal write failed: class=%s requested=%d written=%d", stage, class, len(data), n)
	}
	if n != len(data) {
		report.Fatalf("%s: terminal write was short: class=%s requested=%d written=%d", stage, class, len(data), n)
	}
}

type nativeExpectationReporter interface {
	Helper()
	Fatalf(string, ...any)
}

func (trace *nativeTerminalTrace) expect(t nativeExpectationReporter, ctx context.Context, stage, failure string, match func([]byte) bool) {
	t.Helper()
	trace.recordCaptured(stage, "expect-start", "")
	lastObserved := -1
	var matched nativeScreenSnapshot
	err := trace.capture.WaitFor(ctx, func(data []byte) bool {
		lastObserved = len(data)
		if !match(data) {
			return false
		}
		matched = nativeScreenSnapshot{time.Since(trace.started), stage + "/expect-matched", lastObserved, false}
		return true
	})
	if err != nil {
		reason := nativeResultClass(err, "wait-error")
		var endpoint nativeScreenSnapshot
		trace.capture.Inspect(func(data []byte, _ int, overflow bool) {
			endpoint = nativeScreenSnapshot{time.Since(trace.started), stage + "/expect-failed", len(data), overflow}
		})
		switch {
		case errors.Is(err, ownerterminal.ErrTerminal) && endpoint.partial:
			reason = "capture-overflow"
		case errors.Is(err, ownerterminal.ErrTerminal):
			reason = "eof-or-read-error"
		case reason == "deadline" || reason == "cancelled":
			reason = "missing-output-" + reason
		}
		trace.record(endpoint, stage+" expect-failed", "class=%s matcher-last-offset=%d capture-bytes=%d overflow=%t",
			reason, lastObserved, endpoint.bytes, endpoint.partial)
		trace.flowFail()
		t.Fatalf("%s: %s (%s)", stage, failure, reason)
		return
	}
	trace.record(matched, stage+" expect-matched", "matcher-last-offset=%d capture-bytes=%d", lastObserved, matched.bytes)
}

func (trace *nativeTerminalTrace) expectText(t nativeExpectationReporter, ctx context.Context, stage, text, failure string) {
	t.Helper()
	trace.expect(t, ctx, stage, failure, func(data []byte) bool {
		return bytes.Contains(data, []byte(text))
	})
}

func expectNativeHumanSSHEcho(t nativeExpectationReporter, trace *nativeTerminalTrace, ctx context.Context, credential string) {
	t.Helper()
	trace.expectText(t, ctx, "human-ssh-shell-echo", "ECHO:"+credential, "live human SSH shell did not echo deliberate input after the scope change")
}

func (trace *nativeTerminalTrace) wait(t *testing.T, ctx context.Context, failure string) {
	t.Helper()
	trace.recordCaptured("child-wait", "wait-attempt", "")
	err := trace.terminal.Wait(ctx)
	class := nativeWaitClass(err)
	if class == "clean-exit" || class == "nonzero-or-wait-error" {
		trace.childState = class
	}
	trace.recordCaptured("child-wait", "wait-result", "class=%s ", class)
	if err != nil {
		trace.report(t).Fatalf("%s (%s)", failure, class)
	}
}

func nativeWaitClass(err error) string {
	if err == nil {
		return "clean-exit"
	}
	return nativeResultClass(err, "nonzero-or-wait-error")
}

func (trace *nativeTerminalTrace) probeChildState() string {
	if trace.childState != "" {
		return trace.childState
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	return nativeWaitClass(trace.terminal.Wait(ctx))
}

func (trace *nativeTerminalTrace) probeChildBeforeClose() string {
	const notObserved = "not-observed-before-close"
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- trace.terminal.Wait(ctx) }()
	select {
	case err := <-result:
		class := nativeWaitClass(err)
		if class == "clean-exit" || class == "nonzero-or-wait-error" {
			return class
		}
	case <-ctx.Done():
	}
	return notObserved
}

func (trace *nativeTerminalTrace) cleanup(t *testing.T, closeFailure, joinFailure string) {
	t.Helper()
	state := trace.childState
	if state == "" {
		state = "not-observed-before-close"
		if t.Failed() {
			state = trace.probeChildBeforeClose()
			trace.recordCaptured("cleanup", "pre-close-probe", "class=%s ", state)
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	report := trace.report(t)
	trace.recordCaptured("cleanup", "close-attempt", "child-before-close=%s ", state)
	closeErr := trace.terminal.Close(ctx)
	closeClass := nativeResultClass(closeErr, "close-or-wait-error")
	trace.recordCaptured("cleanup", "close-result", "class=%s ", closeClass)
	if closeErr != nil && closeFailure != "" {
		report.Errorf("%s (%s)", closeFailure, closeClass)
	}
	trace.recordCaptured("cleanup", "drain-attempt", "")
	joinErr := trace.capture.Join(ctx)
	joinClass := nativeResultClass(joinErr, "drain-error")
	if errors.Is(joinErr, ownerterminal.ErrTerminal) {
		joinClass = "capture-overflow"
	}
	trace.capture.Inspect(func(data []byte, total int, overflow bool) {
		snapshot := nativeScreenSnapshot{time.Since(trace.started), "cleanup/drain-result", len(data), overflow || joinErr != nil}
		trace.record(snapshot, "cleanup drain-result", "class=%s retained=%d total=%d overflow=%t",
			joinClass, len(data), total, overflow)
	})
	trace.cleaned = true
	if joinErr != nil {
		report.Errorf("%s (%s)", joinFailure, joinClass)
	}
}

func (trace *nativeTerminalTrace) hiddenInputMatches(inputs ...[]byte) []bool {
	matches := make([]bool, len(inputs))
	trace.capture.Inspect(func(data []byte, _ int, _ bool) {
		stripped := []byte(ansi.Strip(string(data)))
		defer clear(stripped)
		for i, input := range inputs {
			matches[i] = len(input) != 0 && (bytes.Contains(data, input) || bytes.Contains(stripped, input))
		}
	})
	return matches
}

func (trace *nativeTerminalTrace) replayScreenSnapshots(prefix []byte) {
	screen := replayNativeCredentialScreenForDiagnostics(nil)
	var previousLabel, previousField string
	foundChange := false
	for i, snapshot := range trace.snapshots {
		screen.consume(prefix[:snapshot.bytes])
		label, field := nativeDiagnosticField(screen)
		rows := nativeDiagnosticRowShapes(screen)
		fmt.Fprintf(&trace.fieldTimeline, "+%s stage=%s capture-bytes=%d field=%s field-label=%s rows-digest=%s partial=%t\n",
			snapshot.elapsed, snapshot.stage, snapshot.bytes, field, label, flakediag.Short(rows), snapshot.partial)
		firstChange := !foundChange && i > 0 && (label != previousLabel || field != previousField)
		last := i == len(trace.snapshots)-1
		if last {
			trace.screenRows = string(rows)
			trace.screenNote = nativeScreenReplayNote(screen.ignored, snapshot.partial)
			if firstChange {
				trace.screenNote = "also the first field label change\n" + trace.screenNote
			}
		} else if firstChange {
			trace.firstFieldChange = fmt.Sprintf("first field label change screen (stage=%s):\n%s%s",
				snapshot.stage, nativeScreenReplayNote(screen.ignored, snapshot.partial), rows)
		}
		foundChange = foundChange || firstChange
		previousLabel, previousField = label, field
	}
}

func nativeDiagnosticField(screen *nativeCredentialScreen) (string, string) {
	label, field := "none", "other"
	selectedFocused := false
	for row := range nativeScreenRows {
		line := strings.TrimSpace(screen.rowText(row))
		line, focused := strings.CutPrefix(line, "> ")
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		state := "other"
		switch strings.TrimSpace(value) {
		case "<hidden; empty>":
			state = "empty"
		case "<hidden; entered>":
			state = "entered"
		}
		var candidate string
		switch name {
		case "Credential":
			return "credential", state
		case "Value":
			candidate = "value"
		case "Archive password":
			candidate = "archive-password"
		default:
			continue
		}
		if (focused || state != "other") && (label == "none" || focused && !selectedFocused) {
			label, field, selectedFocused = candidate, state, focused
		}
	}
	return label, field
}

// Only structural counts and fixed viewport labels leave the replay model.
// Literal and n-gram redaction alone cannot protect unknown or partial input.
func nativeDiagnosticRowShapes(screen *nativeCredentialScreen) []byte {
	var shapes bytes.Buffer
	for line := range strings.SplitSeq(screen.diagnosticRows(), "\n") {
		switch line {
		case "Final viewport:", "Last alternate viewport:":
			fmt.Fprintln(&shapes, line)
		default:
			index, row, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(index)
			if err != nil || n < 1 || n > nativeScreenRows {
				continue
			}
			width, occupied := 0, 0
			for _, r := range row {
				width++
				if r != ' ' {
					occupied++
				}
			}
			fmt.Fprintf(&shapes, "row=%d width=%d occupied=%d\n", n, width, occupied)
		}
	}
	return shapes.Bytes()
}

// screenDiagnostics exercises the legacy masking regression only. Shared
// failure evidence must use row shapes, not this textual representation.
func (trace *nativeTerminalTrace) screenDiagnostics(prefix []byte, partial bool, inputs ...[]byte) {
	screen := replayNativeCredentialScreenForDiagnostics(prefix)
	trace.screenRows = string(nativeMaskedDiagnosticRows(screen, inputs...))
	trace.screenNote = nativeScreenReplayNote(screen.ignored, partial)
}

func nativeMaskedDiagnosticRows(screen *nativeCredentialScreen, inputs ...[]byte) []byte {
	rows := []byte(screen.diagnosticRows())
	defer clear(rows)
	return renderNativeRedaction(rows, nativeRedactionMask(rows, inputs...))
}

func nativeScreenReplayNote(ignored int, partial bool) string {
	note := fmt.Sprintf("screen replay (ignored=%d):\n", ignored)
	if partial || ignored != 0 {
		note += "screen picture may be incomplete\n"
	}
	return note
}

func nativeRedactionMask(data []byte, inputs ...[]byte) []bool {
	mask := make([]bool, len(data))
	for _, input := range inputs {
		if len(input) == 0 {
			continue
		}
		// Every full input of length >= 4 is covered by its overlapping windows.
		width := min(4, len(input))
		for i := 0; i+width <= len(input); i++ {
			window := input[i : i+width]
			for start := 0; start+width <= len(data); {
				n := bytes.Index(data[start:], window)
				if n < 0 {
					break
				}
				start += n
				for j := range mask[start : start+width] {
					mask[start+j] = true
				}
				start++ // Do not skip overlapping occurrences of the same window.
			}
		}
	}
	return mask
}

func renderNativeRedaction(data []byte, mask []bool) []byte {
	var safe []byte
	for i, b := range data {
		if !mask[i] {
			safe = append(safe, b)
		} else if i == 0 || !mask[i-1] {
			safe = append(safe, "███"...)
		}
	}
	return safe
}

func TestNativeScreenDiagnosticsMasksEcho(t *testing.T) {
	const credential = "sensitive-value"
	const password = "Zq83wVkp"
	trace := &nativeTerminalTrace{}
	trace.screenDiagnostics([]byte("Credential: hidden\r\nEcho: sensitive-\x1b[31mvalue\x1b[0m\r\nUnlock: Zq83wVkp"), true, []byte(credential), []byte(password))
	if strings.Contains(trace.screenRows, credential) || strings.Contains(trace.screenRows, password) ||
		!strings.Contains(trace.screenRows, "Credential: <redacted>") ||
		!strings.Contains(trace.screenRows, "Echo: ███") || !strings.Contains(trace.screenRows, "Unlock: ███") {
		t.Error("screen diagnostics did not mask hidden input")
	}
	if !strings.Contains(trace.screenNote, "ignored=2") || !strings.Contains(trace.screenNote, "screen picture may be incomplete") {
		t.Error("partial screen diagnostics lost the replay status")
	}
}

func TestNativeScreenSnapshotsUseRecordedOffsets(t *testing.T) {
	const empty = "> Credential: <hidden; empty>"
	const entered = "\r\x1b[2K> Credential: <hidden; entered>"
	trace := &nativeTerminalTrace{snapshots: []nativeScreenSnapshot{
		{0, "first-tui-frame/expect-matched", len(empty), false},
		{time.Second, "finish", len(empty + entered), true},
	}}
	trace.replayScreenSnapshots([]byte(empty + entered))
	wantLine := func(elapsed time.Duration, stage, field, prefix string, partial bool) string {
		screen := replayNativeCredentialScreenForDiagnostics([]byte(prefix))
		return fmt.Sprintf("+%s stage=%s capture-bytes=%d field=%s field-label=credential rows-digest=%s partial=%t\n",
			elapsed, stage, len(prefix), field, flakediag.Short(nativeDiagnosticRowShapes(screen)), partial)
	}
	want := wantLine(0, "first-tui-frame/expect-matched", "empty", empty, false) +
		wantLine(time.Second, "finish", "entered", empty+entered, true)
	if trace.fieldTimeline.String() != want {
		t.Error("field timeline did not replay the exact recorded prefixes")
	}
	if trace.firstFieldChange != "" || trace.screenRows == "" ||
		!strings.Contains(trace.screenNote, "also the first field label change") {
		t.Error("final snapshot was not retained once as the first field label change")
	}
}

func TestNativeDiagnosticArchiveFields(t *testing.T) {
	for _, tc := range []struct{ row, label, field string }{
		{"  Value: <hidden; empty>", "value", "empty"},
		{"> Archive password: <hidden; entered>", "archive-password", "entered"},
		{"> Value: visible", "value", "other"},
		{"log: > Archive password: <hidden; entered>", "none", "other"},
		{"Value: <hidden; empty> trailing text", "none", "other"},
		{"Archive password: visible", "none", "other"},
	} {
		label, field := nativeDiagnosticField(replayNativeCredentialScreenForDiagnostics([]byte(tc.row)))
		if label != tc.label || field != tc.field {
			t.Errorf("got %s/%s, want %s/%s", label, field, tc.label, tc.field)
		}
	}
}

func TestNativeScreenSnapshotShapesDoNotRenderText(t *testing.T) {
	prefix := []byte("\x1b[?1049hunknown-fragment\r\nYWJjMTIz\x1b[?1049l\rfinal-value")
	trace := &nativeTerminalTrace{snapshots: []nativeScreenSnapshot{{stage: "finish", bytes: len(prefix)}}}
	trace.replayScreenSnapshots(prefix)
	const want = "Final viewport:\nrow=1 width=11 occupied=11\nLast alternate viewport:\n" +
		"row=1 width=16 occupied=16\nrow=2 width=8 occupied=8\n"
	if trace.screenRows != want {
		t.Error("shared screen evidence did not contain only fixed labels and row shapes")
	}
}

type nativeExpectationRecorder struct {
	fatalText string
}

func (*nativeExpectationRecorder) Helper() {}

func (r *nativeExpectationRecorder) Fatalf(format string, args ...any) {
	r.fatalText = fmt.Sprintf(format, args...)
}

func TestNativeExpectationFailureEvidenceDoesNotLeak(t *testing.T) {
	const secret = "fixture-only-hidden-fragment"
	const sentinel = "RAW-ONLY-SENTINEL-739"
	for _, tc := range []struct {
		stage, matcher string
		expect         func(nativeExpectationReporter, *nativeTerminalTrace, context.Context)
	}{
		{"human-ssh-shell-echo", "ECHO:" + secret, func(t nativeExpectationReporter, trace *nativeTerminalTrace, ctx context.Context) {
			expectNativeHumanSSHEcho(t, trace, ctx, secret)
		}},
		{"persistence-receipt", "receipt:" + secret, func(t nativeExpectationReporter, trace *nativeTerminalTrace, ctx context.Context) {
			trace.expectText(t, ctx, "persistence-receipt", "receipt:"+secret, "native owner command lacked a persistence receipt")
		}},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			ctx := context.Background()
			const unregistered nativeChildFailure = "not-registered"
			raw := "\x1b[31m" + secret + "\x1b[0m\r\n" + sentinel + "\r\n" +
				unregistered.marker() + "\r\n" + applyChildCLIError.marker() + "\r\n" +
				keeperStdoutBase64.marker() + "\r\n" + keeperStdoutOffset.marker()
			if strings.Contains(raw, tc.matcher) {
				t.Fatal("fixture unexpectedly contains the expected matcher")
			}
			trace := &nativeTerminalTrace{started: time.Now(), capture: ownerterminal.CaptureOutput(strings.NewReader(raw))}
			defer trace.capture.Clear()
			if trace.capture.Join(ctx) != nil {
				t.Fatal("fixture capture did not finish")
			}
			// These keeper classes are registered beyond the old 16-marker cap.
			trace.addKeeperHarnessFailureMarkers()
			trace.addOwnerCommandChildFailureMarkers()
			reporter := &nativeExpectationRecorder{}
			tc.expect(reporter, trace, ctx)
			// Render the same evidence a failing native flow would report.
			evidence := trace.failureEvidence("native expectation regression", true)
			for _, forbidden := range []string{
				tc.matcher, secret, raw, sentinel, string(unregistered), "[native-child-failure:",
			} {
				if strings.Contains(evidence, forbidden) || strings.Contains(reporter.fatalText, forbidden) {
					t.Error("expectation failure disclosed forbidden fixture text")
				}
			}
			for _, want := range []string{
				tc.stage + " expect-failed class=eof-or-read-error",
				"capture-class=" + string(applyChildCLIError) + "\n",
				"capture-class=" + string(keeperStdoutBase64) + "\n",
				"capture-class=" + string(keeperStdoutOffset) + "\n",
				fmt.Sprintf("capture retained=%d total=%d overflow=false retained-digest=%s\n", len(raw), len(raw), flakediag.Short([]byte(raw))),
			} {
				if !strings.Contains(evidence, want) {
					t.Error("failure evidence lost a required diagnostic")
				}
			}
			if strings.Count(evidence, "capture-class=") != 3 || strings.Contains(evidence, "expect-matched") {
				t.Error("failure evidence recorded an unexpected class or match")
			}
			if !strings.HasPrefix(reporter.fatalText, tc.stage+": ") || !strings.HasSuffix(reporter.fatalText, "(eof-or-read-error)") {
				t.Error("expectation did not report the expected fatal stage and class")
			}
		})
	}
}

func nativeUnlockInput(password []byte) []byte {
	input := make([]byte, len(password)+1)
	copy(input, password)
	input[len(password)] = '\n'
	if runtime.GOOS == "windows" {
		input[len(password)] = '\r'
	}
	return input
}

func nativeOwnerCommandAcceptance(t *testing.T, diagnostics *testing.T, ctx context.Context, path string, password []byte, server, account string, control *ownercontrol.Control) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := control.Backend().Metadata()
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, entry := range metadata.Servers {
		if entry.ID == server {
			name = entry.Name
		}
	}
	if name == "" {
		t.Fatal("native owner server selection is unavailable")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := control.Backend().Status().Database.Revision
	credentialText := "synthetic native helper credential"
	if account == "keeper-added" {
		credentialText = nativeGuardAddedCredential
	}
	credential := []byte(credentialText)
	defer clear(credential)
	var trace *nativeTerminalTrace
	for _, mode := range []string{"cancel", "apply"} {
		func() {
			lifetime, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			environment := make([]string, 0)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
					environment = append(environment, entry)
				}
			}
			cancelled := "0"
			if mode == "cancel" {
				cancelled = "1"
			}
			environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_CHILD=1", "SSJACK_OWNER_COMMAND_CHILD=1", "SSJACK_OWNER_COMMAND_CANCEL="+cancelled)
			trace = startNativeTerminal(t, diagnostics, lifetime, "native owner command "+mode, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Environment: environment,
				Args: []string{"-test.run=^TestOwnerNativeCommandChild$", "--", "--vault", path, "owner", "add-account", "--server", name, "--account", account, "--login", "native-user", "--auth", "password", "--usage", "agent"}})
			trace.addOwnerCommandChildFailureMarkers()
			defer func() {
				trace.cleanup(t, "", "native owner terminal output did not join")
				leaked := trace.hiddenInputMatches(password, credential)
				if leaked[0] {
					trace.report(t).Error("native owner terminal disclosed the vault password")
				}
				if leaked[1] {
					trace.report(t).Error("native owner terminal disclosed the account credential")
				}
			}()
			trace.expectText(t, lifetime, "vault-prompt", "Vault secret:", "native owner did not request its single vault unlock")
			trace.write(t, "unlock", nativeUnlockInput(password))
			screen := newNativeCredentialScreen()
			trace.expect(t, lifetime, "first-tui-frame", "native owner did not display its focused hidden-empty credential", func(data []byte) bool {
				return screen.matches(data, "> Credential: <hidden; empty>")
			})
			trace.write(t, "credential", bytes.Clone(credential))
			// A console write can arrive in batches; entered proves nonempty, not complete.
			trace.expect(t, lifetime, "credential-nonempty", "native owner did not display its focused hidden nonempty credential", func(data []byte) bool {
				return screen.matches(data, "> Credential: <hidden; entered>")
			})
			if mode == "cancel" {
				trace.write(t, "cancel", []byte{'\x1b'})
			} else {
				trace.write(t, "apply", []byte{'\t', '\r'})
			}
			trace.wait(t, lifetime, "native owner command did not finish its explicit decision")
			if mode == "apply" {
				trace.expectText(t, lifetime, "persistence-receipt", "Owner command completed; encrypted persistence confirmed.", "native owner command lacked a persistence receipt")
			}
		}()
		after, err := os.ReadFile(path)
		if err != nil {
			trace.report(t).Fatalf("native helper %s ciphertext could not be read", mode)
		}
		if mode == "cancel" && !bytes.Equal(before, after) {
			trace.report(t).Fatalf("cancelled native helper changed encrypted database bytes: before-size=%d after-size=%d", len(before), len(after))
		}
		if _, err := control.Backend().Metadata(); err != nil {
			trace.report(t).Fatal("native helper detach closed its parent coordinator")
		}
		if mode == "cancel" {
			trace.flow.Complete()
		}
	}
	report := trace.report(t)
	status := control.Backend().Status()
	if status.Database.Revision != revision+1 {
		report.Fatalf("native helper parent RAM revision mismatch: got=%d want=%d", status.Database.Revision, revision+1)
	}
	if status.Database.SavedRevision != status.Database.Revision {
		report.Fatalf("native helper saved revision mismatch: saved=%d current=%d", status.Database.SavedRevision, status.Database.Revision)
	}
	if status.Database.Err != nil {
		report.Fatal("native helper parent database reported an error")
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		report.Fatal("native helper persisted vault could not be loaded")
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, account)
	if err != nil {
		report.Fatal("native helper persisted account profile could not be resolved")
	}
	target := loaded.Targets[profile]
	if target.User != "native-user" {
		report.Fatal("native helper persisted the wrong account user")
	}
	if !bytes.Equal(target.Password, credential) {
		offset := 0
		for offset < len(target.Password) && offset < len(credential) && target.Password[offset] == credential[offset] {
			offset++
		}
		report.Fatalf("native helper persisted the wrong hidden credential: got-length=%d want-length=%d first-differing-offset=%d", len(target.Password), len(credential), offset)
	}
	trace.flow.Complete()
}

func TestNativeInteractiveProcessChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_NATIVE_TUI_CHILD") != "1" {
		t.Skip("actual native interactive child only")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		nativeChildFatal(t, interactiveChildStdinNotTTY, "interactive child stdin was not a terminal")
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		nativeChildFatal(t, interactiveChildStdoutNotTTY, "interactive child stdout was not a terminal")
	}
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		nativeChildFatal(t, interactiveChildRawSetup, "interactive child could not configure raw terminal mode")
	}
	defer term.Restore(int(os.Stdin.Fd()), state)
	ownerInteractivePTYChild(t)
}

func nativeInteractiveAcceptance(t *testing.T, diagnostics *testing.T, ctx context.Context, path string, password []byte, server string, observer *ownercontrol.Control) {
	flakediag.Begin(t)
	t.Helper()
	metadata, err := observer.Backend().Metadata()
	if err != nil {
		t.Fatal(err)
	}
	connections, index, oldAddress := 0, -1, ""
	for position, entry := range metadata.Servers {
		if entry.ID == server {
			index, oldAddress = position, entry.Address
		}
		for _, account := range entry.Accounts {
			if account.Usage == "" || account.Usage == "both" || account.Usage == "human" {
				connections++
			}
		}
	}
	if index < 0 {
		t.Fatal("interactive navigation server was not found")
	}
	if connections < 1 {
		t.Fatal("interactive navigation has no human connections")
	}
	if oldAddress == "" {
		t.Fatal("interactive navigation server has no address")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	revision := observer.Backend().Status().Database.Revision
	const replacement = "127.0.0.1:2"
	var applyTrace *nativeTerminalTrace
	for _, mode := range []string{"cancel", "apply"} {
		t.Run(mode, func(t *testing.T) {
			lifetime, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			environment := make([]string, 0)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
					environment = append(environment, entry)
				}
			}
			environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1")
			trace := startNativeTerminal(t, diagnostics, lifetime, "interactive helper "+mode, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
				Args: []string{"-test.run=^TestNativeInteractiveProcessChild$", "--", "--vault", path, "--interactive"}})
			if mode == "apply" {
				applyTrace = trace
			}
			trace.addInteractiveTerminalFailureMarkers()
			trace.addInteractiveCLIFailureMarkers()
			defer func() {
				trace.cleanup(t, "", "interactive terminal output did not join")
				if trace.hiddenInputMatches(password)[0] {
					trace.report(t).Error("interactive teardown: terminal disclosed the vault password")
				}
				if trace.capture.Contains([]byte("SSH connection failed")) {
					trace.report(t).Error("interactive teardown: unexpected SSH connection marker")
				}
			}()
			trace.expectText(t, lifetime, "vault-prompt", "Vault secret:", "actual interactive navigation did not reach: Vault secret:")
			trace.write(t, "unlock", nativeUnlockInput(password))
			trace.expectText(t, lifetime, "first-tui-frame", "Connect:", "actual interactive navigation did not reach: Connect:")
			trace.write(t, "open-server-list", []byte(strings.Repeat("\x1b[B", connections)+"\r"))
			trace.expectText(t, lifetime, "server-list", "[Add server]", "actual interactive navigation did not reach: [Add server]")
			trace.write(t, "select-server", []byte(strings.Repeat("\x1b[B", index+1)+"\r"))
			trace.expectText(t, lifetime, "server-actions", "[Edit server connection]", "actual interactive navigation did not reach: [Edit server connection]")
			trace.write(t, "open-connection-editor", []byte("\x1b[B\r"))
			trace.expectText(t, lifetime, "connection-editor", "Replacement host keys", "actual interactive navigation did not reach: Replacement host keys")
			trace.write(t, "replace-address", append(bytes.Repeat([]byte{127}, len(oldAddress)), []byte(replacement)...))
			if mode == "cancel" {
				trace.write(t, "cancel-and-close", []byte{3, 3})
			} else {
				trace.write(t, "apply", []byte{'\t', '\t', '\r'})
				trace.expectText(t, lifetime, "persistence-receipt", "Change applied. Check persistence status below.", "actual interactive navigation did not reach: Change applied. Check persistence status below.")
				trace.write(t, "close", []byte{3})
			}
			trace.wait(t, lifetime, "actual interactive helper did not finish its close/flush")
			if mode == "cancel" {
				after, err := os.ReadFile(path)
				if err != nil {
					trace.report(t).Fatal("interactive cancel-read: database ciphertext read failed")
				}
				if !bytes.Equal(before, after) {
					trace.report(t).Fatalf("interactive cancel-read: database ciphertext changed: before-size=%d after-size=%d", len(before), len(after))
				}
				trace.flow.Complete()
			}
		})
	}
	report := applyTrace.report(t)
	metadata, err = observer.Backend().Metadata()
	if err != nil {
		report.Fatal("interactive final-metadata: metadata read failed")
	}
	found := false
	for _, entry := range metadata.Servers {
		found = found || entry.ID == server && entry.Address == replacement
	}
	if !found {
		report.Fatal("interactive final-metadata: updated address not found")
	}
	status := observer.Backend().Status()
	if status.Database.Revision != revision+1 {
		report.Fatalf("interactive final-status: revision mismatch: got=%d want=%d", status.Database.Revision, revision+1)
	}
	if status.Database.SavedRevision != status.Database.Revision {
		report.Fatalf("interactive final-status: saved revision mismatch: saved=%d current=%d", status.Database.SavedRevision, status.Database.Revision)
	}
	if status.Database.Err != nil {
		report.Fatal("interactive final-status: parent database reported an error")
	}
	if applyTrace != nil {
		applyTrace.flow.Complete()
	}
}
