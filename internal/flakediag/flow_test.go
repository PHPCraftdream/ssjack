package flakediag

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFlowOutcomeLabels(t *testing.T) {
	for _, tc := range []struct {
		name    string
		run     func(*Flow)
		outcome string
	}{
		{"complete", func(f *Flow) { f.Complete() }, "completed-ok"},
		{"fail", func(f *Flow) { f.Fail() }, "failed"},
		{"untouched", func(*Flow) {}, "not-finished"},
		{"complete-then-fail", func(f *Flow) { f.Complete(); f.Fail() }, "failed"},
		{"fail-then-complete", func(f *Flow) { f.Fail(); f.Complete() }, "failed"},
	} {
		f := &Flow{label: tc.name}
		tc.run(f)
		if got := f.snapshot().String(); got != tc.outcome {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.outcome)
		}
	}
}

// fakeDump counts calls with a nil-safe counter.
func fakeDump(marker string, calls *int) func(int) string {
	return func(int) string {
		if calls != nil {
			*calls++
		}
		return "dump:" + marker
	}
}

func capturingLogf(sink *[]string) func(string, ...any) {
	return func(s string, args ...any) { *sink = append(*sink, fmt.Sprintf(s, args...)) }
}

func TestRenderFlowReportFullCompactAndSingleDump(t *testing.T) {
	failed := &Flow{label: "alpha"}
	failed.Fail()
	unfinished := &Flow{label: "beta"}
	done := &Flow{label: "gamma"}
	done.Complete()
	failedFull, doneFull := false, false
	doneRendered := false
	failed.render = func(full bool) string { failedFull = full; return "alpha evidence" }
	unfinished.render = func(full bool) string {
		if !full {
			t.Error("unfinished flow rendered compact")
		}
		return "beta evidence"
	}
	done.render = func(full bool) string { doneFull = full; doneRendered = true; return "gamma evidence" }
	var logged []string
	calls := 0
	renderFlowReport(true, capturingLogf(&logged),
		func() string { return "environment: test" },
		[]*Flow{failed, unfinished, done}, fakeDump("x", &calls))
	out := strings.Join(logged, "\n")
	for _, want := range []string{
		"flow: alpha outcome=failed", "flow: beta outcome=not-finished",
		"flow: gamma outcome=completed-ok", "goroutine dump:", "dump:x",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if calls != 1 {
		t.Errorf("dump called %d times, want 1", calls)
	}
	firstEvidence := strings.Index(out, "alpha evidence")
	if firstEvidence < 0 {
		firstEvidence = strings.Index(out, "beta evidence")
	}
	if firstEvidence < 0 {
		t.Fatalf("no evidence found in output:\n%s", out)
	}
	overview := out[:firstEvidence]
	for _, want := range []string{
		"flow outcomes:", "  alpha: failed", "  beta: not-finished", "  gamma: completed-ok",
	} {
		if !strings.Contains(overview, want) {
			t.Errorf("overview missing %q before first evidence:\n%s", want, overview)
		}
	}
	if strings.Contains(overview, "alpha evidence") || strings.Contains(overview, "beta evidence") ||
		strings.Contains(overview, "gamma evidence") || strings.Contains(overview, "goroutine dump:") {
		t.Errorf("evidence appears before all outcomes listed:\n%s", overview)
	}
	if !failedFull {
		t.Error("failed flow should render full evidence")
	}
	if doneFull {
		t.Error("completed flow should render compact evidence")
	}
	if !doneRendered {
		t.Error("completed flow renderer not called")
	}
	if !strings.Contains(out, "gamma evidence") || !strings.Contains(out, "beta evidence") {
		t.Errorf("rendered evidence missing from output:\n%s", out)
	}
}

func TestRenderFlowReportDumpPriorityFailedOverUnfinished(t *testing.T) {
	unfinished := &Flow{label: "late"}
	unfinished.render = func(bool) string { return "e" }
	failed := &Flow{label: "boom"}
	failed.Fail()
	failed.render = func(bool) string { return "e" }
	var logged []string
	calls := 0
	renderFlowReport(true, capturingLogf(&logged),
		func() string { return "env" }, []*Flow{unfinished, failed}, fakeDump("x", &calls))
	out := strings.Join(logged, "\n")
	if calls != 1 {
		t.Errorf("dump called %d times, want 1", calls)
	}
	if strings.Count(out, "goroutine dump:") != 1 {
		t.Errorf("want one explicit dump marker:\n%s", out)
	}
	if idxFailed := strings.Index(out, "outcome=failed"); idxFailed >= 0 &&
		strings.Index(out, "dump:x") < idxFailed {
		t.Errorf("dump should attach after the first failed flow:\n%s", out)
	}
}

func TestRenderFlowReportSingleDumpMultipleUnfinished(t *testing.T) {
	f1 := &Flow{label: "a"}
	f1.render = func(bool) string { return "e" }
	f2 := &Flow{label: "b"}
	f2.render = func(bool) string { return "e" }
	calls := 0
	renderFlowReport(true, func(string, ...any) {}, func() string { return "env" },
		[]*Flow{f1, f2}, fakeDump("x", &calls))
	if calls != 1 {
		t.Errorf("dump called %d times, want 1", calls)
	}
}

func TestRenderFlowReportStandaloneDumpWhenAllCompleted(t *testing.T) {
	done := &Flow{label: "done"}
	done.Complete()
	done.render = func(bool) string { return "e" }
	var logged []string
	calls := 0
	renderFlowReport(true, capturingLogf(&logged),
		func() string { return "env" }, []*Flow{done}, fakeDump("x", &calls))
	out := strings.Join(logged, "\n")
	if !strings.Contains(out, "all flows completed; test-level goroutine dump:") {
		t.Errorf("missing standalone dump marker:\n%s", out)
	}
	if calls != 1 {
		t.Errorf("dump called %d times, want 1", calls)
	}
}

func TestRenderFlowReportSilentOnPass(t *testing.T) {
	done := &Flow{label: "done"}
	done.Complete()
	probed := false
	done.render = func(bool) string { probed = true; return "e" }
	dumpCalls := 0
	dump := func(int) string {
		dumpCalls++
		t.Error("dump invoked even though report discarded")
		return "dump:x"
	}
	renderFlowReport(false, func(string, ...any) { t.Error("logged on pass") },
		func() string { probed = true; return "env" }, []*Flow{done}, dump)
	if probed {
		t.Error("probed environment or rendered on pass")
	}
	if dumpCalls != 0 {
		t.Errorf("dump called %d times, want 0", dumpCalls)
	}
}

func TestRenderFlowReportRenderPanicConstantMessage(t *testing.T) {
	failed := &Flow{label: "boom"}
	failed.Fail()
	secret := "hunter2-super-secret"
	failed.render = func(bool) string { panic("leaked: " + secret) }
	var logged []string
	renderFlowReport(true, capturingLogf(&logged),
		func() string { return "env" }, []*Flow{failed}, fakeDump("x", nil))
	out := strings.Join(logged, "\n")
	if strings.Contains(out, secret) {
		t.Errorf("panic text leaked into diagnostics:\n%s", out)
	}
	if !strings.Contains(out, "render panicked (details omitted)") {
		t.Errorf("missing constant panic message:\n%s", out)
	}
}

func TestRenderFlowReportReleaseAlwaysRuns(t *testing.T) {
	failed := &Flow{label: "boom"}
	failed.Fail()
	failed.render = func(bool) string { return "e" }
	passed := &Flow{label: "ok"}
	passed.Complete()
	passed.render = func(bool) string { return "e" }
	cases := []struct {
		failed bool
		panicR bool
	}{
		{false, false}, {true, false}, {true, true},
	}
	for i, tc := range cases {
		released := 0
		if tc.panicR {
			failed.render = func(bool) string { panic("x") }
		} else {
			failed.render = func(bool) string { return "e" }
		}
		failed.release = func() { released++ }
		passed.release = func() { released += 10 }
		renderFlowReport(tc.failed, func(string, ...any) {}, func() string { return "env" },
			[]*Flow{failed, passed}, fakeDump("x", nil))
		if released != 11 {
			t.Errorf("case %d: releases ran %d times, want 11", i, released)
		}
	}
}

func TestStartFlowSingleCleanupGroupAndDelete(t *testing.T) {
	var leaf *testing.T
	releaseOne, releaseTwo := 0, 0
	sentinelRan := false
	t.Run("group", func(t *testing.T) {
		leaf = t
		StartFlow(t, "one", func(bool) string { return "e" }, func() { releaseOne++ })
		t.Cleanup(func() {
			sentinelRan = true
			if releaseOne != 0 || releaseTwo != 0 {
				t.Errorf("releases ran before sentinel cleanup (one=%d two=%d)", releaseOne, releaseTwo)
			}
		})
		StartFlow(t, "two", func(bool) string { return "e" }, func() { releaseTwo++ })
	})
	if !sentinelRan {
		t.Error("sentinel cleanup never ran")
	}
	if releaseOne != 1 || releaseTwo != 1 {
		t.Errorf("releases after child cleanup: one=%d two=%d, want 1 and 1", releaseOne, releaseTwo)
	}
	if _, ok := groups.Load(leaf); ok {
		t.Error("group entry not deleted after cleanup")
	}
}

func TestStartFlowPassReleaseAndNoOutput(t *testing.T) {
	released := false
	var leaf *testing.T
	t.Run("leaf", func(t *testing.T) {
		leaf = t
		f := StartFlow(t, "x", func(bool) string { return "" }, func() { released = true })
		f.Complete()
	})
	if !released {
		t.Error("release not called on pass")
	}
	if _, ok := groups.Load(leaf); ok {
		t.Error("group entry not deleted after pass cleanup")
	}
}

func TestSafeGoroutineDumpStrips(t *testing.T) {
	raw := "goroutine 1 [running]:\n" +
		"github.com/org/repo/internal/pkg.Fn(0xc0001, {0x2}, \"C:\\\\secret path\\\\key\")\n" +
		"\tD:/dev/proj/main.go:42 +0x1f\n" +
		"github.com/org/repo/internal/pkg.(*Type).Method(0xc0009)\n" +
		"main.main(0x1, \"/unix/secret\")\n" +
		"\t/unix/path/main.go:9 +0x2\n" +
		"created by github.com/org/repo/internal/pkg.Start(0xfeed)\n" +
		"\tC:/go/src/x.go:1 +0x1"
	got := sanitizeDump(raw)
	if strings.Contains(got, "0xc0001") || strings.Contains(got, "0xc0009") ||
		strings.Contains(got, "secret") || strings.Contains(got, ".go:") || strings.Contains(got, "+0x") || strings.Contains(got, "0xfeed") {
		t.Errorf("raw args/paths leaked:\n%s", got)
	}
	for _, want := range []string{
		"goroutine 1 [running]:", "pkg.Fn(...)", "pkg.(*Type).Method(...)",
		"main.main(...)", "created by pkg.Start(...)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSanitizeDumpDropsTruncatedFrame(t *testing.T) {
	raw := "goroutine 1 [running]:\n" +
		"github.com/org/repo/internal/pkg.Fn(0xc0001, 0x2" // cut mid-arguments
	got := sanitizeDump(raw)
	if strings.Contains(got, "0xc0001") || strings.Contains(got, "Fn") {
		t.Errorf("partial frame with raw address leaked:\n%s", got)
	}
	if !strings.Contains(got, "goroutine 1 [running]:") {
		t.Errorf("header lost:\n%s", got)
	}
}

func TestDropTruncationSuffix(t *testing.T) {
	raw := "goroutine 1 [running]:\n" +
		"pkg.Fn(0x1)\n" +
		"\tx.go:1 +0x1\n" +
		"github.com/org/repo/internal/pkg.Fn2(0xc0001, 0x2\n...truncated (full 99999 bytes)"
	got := dropTruncationSuffix(raw)
	if strings.Contains(got, "truncated") || strings.Contains(got, "Fn2") || strings.Contains(got, "0xc0001") {
		t.Errorf("marker or partial frame kept:\n%s", got)
	}
	if !strings.Contains(got, "pkg.Fn(0x1)\n") {
		t.Errorf("complete frames lost:\n%s", got)
	}
}

func TestSafeGoroutineDumpProduction(t *testing.T) {
	got := SafeGoroutineDump(0)
	if got == "" {
		t.Error("empty production dump")
	}
	if strings.Contains(got, ".go:") {
		t.Error("source paths leaked in goroutine dump")
	}
	bounded := SafeGoroutineDump(64)
	if len(bounded) > 64 {
		t.Errorf("dump exceeds limit: %d > 64 bytes", len(bounded))
	}
}

// flakediagDedupChildGate is a synthetic, non-secret boolean selector: only
// the subprocess started by TestFlowDumpScopeDedupNestedSubprocess sets it,
// so the gated child test skips when the whole suite runs in-process. The
// child process environment is a fixed whitelist, never a full inheritance,
// so no ambient project credentials are forwarded.
const flakediagDedupChildGate = "FLAKEDIAG_DEDUP_CHILD_GATE"

// TestStartFlowScopeBoundPassStaysSilent: a bound scope must not be consumed
// when every flow completes and the report is discarded.
func TestStartFlowScopeBoundPassStaysSilent(t *testing.T) {
	var scope FlowDumpScope
	var leaf *testing.T
	t.Run("leaf", func(t *testing.T) {
		leaf = t
		scope.Bind(t)
		f := StartFlow(t, "ok", func(bool) string { return "" }, nil)
		f.Complete()
		if scope.claimed.Load() {
			t.Error("scope consumed while test still passing")
		}
	})
	if scope.claimed.Load() {
		t.Error("scope consumed on passing flow")
	}
	if _, ok := flowDumpScopes.Load(leaf); ok {
		t.Error("scope binding not removed after subtest finished")
	}
	if _, ok := groups.Load(leaf); ok {
		t.Error("flow group entry not removed after pass")
	}
}

func TestFlowDumpScopeDedupNestedChild(t *testing.T) {
	if os.Getenv(flakediagDedupChildGate) != "1" {
		t.Skip("subprocess-only helper; run via TestFlowDumpScopeDedupNestedSubprocess")
	}
	var scope FlowDumpScope
	scope.Bind(t)
	parent := StartFlow(t, "parent", func(full bool) string {
		if full {
			return "parent full evidence"
		}
		return "parent compact timeline"
	}, nil)
	parent.Complete()
	t.Run("keeper", func(t *testing.T) {
		scope.Bind(t)
		nested := StartFlow(t, "nested", func(bool) string { return "nested full evidence" }, nil)
		nested.Fail()
		t.Error("simulated nested failure")
	})
}

// TestFlowDumpScopeDedupNestedSubprocess runs the gated child in a real test
// binary so cleanup-integrated rendering is exercised. The child simulates a
// failing nested subtest plus a completed parent flow sharing one scope; the
// report must contain exactly one goroutine dump, the nested failure label,
// and the parent's completed-ok timeline entry.
func TestFlowDumpScopeDedupNestedSubprocess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate test binary")
	}
	// Fixed synthetic environment: only the gate variable is set; on Windows
	// os/exec supplies SYSTEMROOT itself, and no PATH/TMP forwarding or
	// ambient (possibly credential-bearing) variables are inherited.
	cmd := exec.CommandContext(t.Context(), executable,
		"-test.run=^TestFlowDumpScopeDedupNestedChild$", "-test.v", "-test.timeout=15s")
	cmd.Env = []string{flakediagDedupChildGate + "=1"}
	output, err := cmd.CombinedOutput()
	out := string(output)
	if err == nil {
		t.Fatal("child test binary exited zero; expected the simulated nested failure")
	}
	if code, ok := exitCode(err); !ok || code != 1 {
		t.Fatalf("child exit: want code 1, got code %d ok %v", code, ok)
	}
	if got := strings.Count(out, "goroutine dump:"); got != 1 {
		t.Fatalf("child output: want exactly one goroutine dump marker, got %d (%d bytes)", got, len(out))
	}
	if !strings.Contains(out, "flow: nested outcome=failed") {
		t.Fatal("child output: missing nested failure label")
	}
	if !strings.Contains(out, "nested: failed") {
		t.Fatal("child output: missing nested outcome in compact timeline")
	}
	if !strings.Contains(out, "flow: parent outcome=completed-ok") || !strings.Contains(out, "parent: completed-ok") {
		t.Fatal("child output: missing parent completed-ok trace")
	}
	if !strings.Contains(out, "parent compact timeline") {
		t.Fatal("child output: missing distinct parent compact evidence")
	}
	dumpIdx, nestedIdx, parentIdx := strings.Index(out, "goroutine dump:"), strings.Index(out, "nested full evidence"), strings.Index(out, "parent compact timeline")
	if nestedIdx < 0 || dumpIdx < nestedIdx || parentIdx < dumpIdx {
		t.Fatalf("child output ordering: want nested evidence < dump < parent compact evidence (nested at %d, dump at %d, parent at %d)", nestedIdx, dumpIdx, parentIdx)
	}
}

// exitCode extracts the process exit status from a run error when available.
func exitCode(err error) (int, bool) {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), true
	}
	return 0, false
}
