//go:build linux || darwin

package fixture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/fileops"
)

type fixedResultWriter struct {
	n   int
	err error
}

func (w fixedResultWriter) Write(p []byte) (int, error) { return w.n, w.err }

func TestDiagnosticWriterForwardsAndCountsAcceptedBytes(t *testing.T) {
	var s ExecServer
	var downstream bytes.Buffer
	var observed streamDiagnostic
	writer := &diagnosticWriter{downstream: &downstream, observe: s.observeStream(&observed)}
	payload := []byte("hello\x00\xff\r\n")
	n, err := writer.Write(payload)
	if err != nil {
		t.Fatal("Write returned an error")
	}
	if n != len(payload) {
		t.Error("Write returned the wrong count")
	}
	if !bytes.Equal(downstream.Bytes(), payload) {
		t.Error("Write changed the downstream payload")
	}
	if observed.bytes != int64(len(payload)) {
		t.Error("Write recorded the wrong count")
	}
	if observed.issue != "" {
		t.Error("Write recorded an unexpected issue")
	}
}

func TestDiagnosticWriterPropagatesShortWriteAndError(t *testing.T) {
	var s ExecServer
	wantErr := errors.New("write failed")
	for _, tc := range []struct {
		err   error
		class string
	}{{wantErr, "error"}, {nil, "short-write"}} {
		var observed streamDiagnostic
		writer := &diagnosticWriter{downstream: fixedResultWriter{n: 2, err: tc.err}, observe: s.observeStream(&observed)}
		n, err := writer.Write([]byte("data"))
		if n != 2 {
			t.Errorf("%s: Write returned the wrong count", tc.class)
		}
		if err != tc.err {
			t.Errorf("%s: Write returned the wrong error", tc.class)
		}
		if observed.bytes != 2 {
			t.Errorf("%s: Write recorded the wrong count", tc.class)
		}
		if observed.issue != tc.class {
			t.Errorf("%s: Write recorded the wrong issue class", tc.class)
		}
	}
}

func TestExecDiagnosticsOnlyRenderMetadata(t *testing.T) {
	s := &ExecServer{startedAt: time.Now()}
	script := "secret-script\n\xff"
	input := "secret-input\r\x00"
	output := "secret-output\né"
	rawError := "secret-error\n/path"
	missingShell := filepath.Join(t.TempDir(), "secret-shell")
	d := s.recordExec("set -eu\npath=\"$path\"\ncat > \"$path\" || exit 24\n" + script)
	r := &diagnosticReader{upstream: strings.NewReader(input), observe: s.observeStream(&d.stdin)}
	gotInput, err := io.ReadAll(r)
	if err != nil {
		t.Fatal("ReadAll returned an error")
	}
	if string(gotInput) != input {
		t.Fatal("ReadAll changed the input payload")
	}
	w := &diagnosticWriter{downstream: &bytes.Buffer{}, observe: s.observeStream(&d.stdout)}
	_, _ = w.Write([]byte(output))
	w = &diagnosticWriter{downstream: fixedResultWriter{n: 2, err: errors.New(rawError)}, observe: s.observeStream(&d.stderr)}
	_, _ = w.Write([]byte(output))
	if status := s.runCommand(exec.Command(missingShell, "-c", script), d); status != 111 {
		t.Fatal("startup failure returned the wrong wire status")
	}
	got := s.renderDiagnostics()
	for _, secret := range []string{script, input, output, rawError, missingShell} {
		quoted := strconv.QuoteToASCII(secret)
		if strings.Contains(got, secret) {
			t.Error("diagnostics contain an unescaped secret")
		}
		if strings.Contains(got, quoted[1:len(quoted)-1]) {
			t.Error("diagnostics contain an escaped secret")
		}
	}
	for _, forbidden := range []string{"secret-", "script=", "exit=", "signal="} {
		if strings.Contains(got, forbidden) {
			t.Errorf("startup diagnostics contain forbidden marker %q", forbidden)
		}
	}
	for _, field := range []struct{ name, text string }{
		{"exec summary", "remote exec 1: op=write-file pid=0 process=none io=not-started stdin=14 stdout=16 stderr=2 stderr-error=error"},
		{"acceptance step", "exec=1 step=accepted"},
		{"start attempt step", "step=start-attempted"},
		{"start failure step", "step=start-failed/not-found"},
	} {
		if !strings.Contains(got, field.text) {
			t.Errorf("startup diagnostics missing %s", field.name)
		}
	}
}

func TestDiagnosticOperationLabels(t *testing.T) {
	publish := func(template string, mvT bool) string {
		return fmt.Sprintf(core.PublicationTemplate(template, core.Caps{MvT: mvT}), `'/stage/file name'`, `'/dest/file name'`)
	}
	for i, tc := range []struct{ command, want string }{
		{`assembled.$rnd`, "assemble"},
		{`set -eu
asm="$stage/assembled.$rnd.tmp"`, "assemble"},
		{"set -eu\nstat -c '%s %Y' \"$path\"", "stat-source"},
		{"set -eu\nstat -f '%z %m' \"$path\"", "stat-source"},
		{"set -eu\nwc -c < \"$path\"", "stat-file"},
		{`set -eu
src="$stage/x"
dst="$path"
if perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$src" "$dst"; then`, "publish"},
		{`set -eu
src="$stage/x"
dst="$path"
if perl -e 'exit(link($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$src" "$dst"; then`, "publish"},
		{publish(fileops.PublishFileOverwriteTemplate, true), "publish"},
		{publish(fileops.PublishFileOverwriteTemplate, false), "publish"},
		{publish(fileops.PublishFileTemplate, true), "publish"},
		{publish(fileops.PublishFileTemplate, false), "publish"},
		{core.PublicationTemplate(`set -eu
if ! (umask 077 && cat > "$tmp"); then
	exit 24
fi
if ! mv -T -f "$tmp" "$final"; then
	exit 24
fi
`, core.Caps{}), "upload-part"},
		{`arbitrary`, "other"},
	} {
		if got := commandOperation(tc.command); got != tc.want {
			t.Errorf("case %d: operation label = %q, want %q", i, got, tc.want)
		}
	}
}

func TestFormatTimelineMergesExecAndFixtureEvents(t *testing.T) {
	records := []execDiagnostic{
		{id: 1, steps: [execStepLimit]diagnosticStep{{at: 5 * time.Second, state: "accepted"}, {at: 15 * time.Second, state: "started"}}, nsteps: 2},
		{id: 2, steps: [execStepLimit]diagnosticStep{{at: 10 * time.Second, state: "accepted"}}, nsteps: 1},
	}
	events := []fixtureEvent{{at: 7 * time.Second, kind: "kill-fired", op: "read-file", id: 1, direction: "stdout", threshold: 4, seen: 4}}
	got := formatTimeline(records, events)
	ordered := []string{"+5s exec=1 step=accepted", "+7s:kill-fired", "+10s exec=2 step=accepted", "+15s exec=1 step=started"}
	last := -1
	for _, item := range ordered {
		at := strings.Index(got, item)
		if at <= last {
			t.Fatalf("timeline ordering assertion failed")
		}
		last = at
	}
}

func TestDiagnosticRingKeepsLatestRecordsInOrder(t *testing.T) {
	var records [execDiagnosticLimit]*execDiagnostic
	for i := uint64(1); i <= execDiagnosticLimit+1; i++ {
		records[(i-1)%execDiagnosticLimit] = &execDiagnostic{id: i}
	}
	ordered := orderedExecRecords(records, execDiagnosticLimit+1)
	if len(ordered) != execDiagnosticLimit {
		t.Fatal("diagnostic ring retained the wrong number of records")
	}
	if ordered[0].id != 2 {
		t.Error("diagnostic ring starts at the wrong record")
	}
	if ordered[len(ordered)-1].id != execDiagnosticLimit+1 {
		t.Error("diagnostic ring ends at the wrong record")
	}
}

// TestRenderDiagnosticsGoroutineDumpIsSanitized preserves the fixture-level
// regression coverage of the old local sanitizer: the goroutines section of
// rendered diagnostics must carry neither frame arguments nor source paths.
// The argument/path stripping itself is covered by the shared
// flakediag.SafeGoroutineDump unit tests.
func TestRenderDiagnosticsGoroutineDumpIsSanitized(t *testing.T) {
	s := &ExecServer{startedAt: time.Now()}
	rendered := s.renderDiagnostics()
	i := strings.Index(rendered, "goroutines:\n")
	if i < 0 {
		t.Fatal("rendered diagnostics omit the goroutines section")
	}
	dump := rendered[i+len("goroutines:\n"):]
	for _, leak := range []string{"0x", "\t", "/"} {
		if strings.Contains(dump, leak) {
			t.Errorf("rendered goroutine dump retained %q", leak)
		}
	}
	if !strings.Contains(dump, "goroutine ") {
		t.Error("rendered goroutine dump lost its goroutine headers")
	}
}

func TestExecDiagnosticsDistinguishExitAndSignal(t *testing.T) {
	s := &ExecServer{startedAt: time.Now()}
	for _, tc := range []struct {
		script string
		wire   int
		kind   string
		signal int
	}{
		{"exit 111", 111, "exited", 0},
		{"kill -TERM $$", -1, "signaled", int(syscall.SIGTERM)},
	} {
		d := s.recordExec(tc.script)
		if wire := s.runCommand(exec.Command("sh", "-c", tc.script), d); wire != tc.wire {
			t.Fatalf("%s: wrong wire status", tc.kind)
		}
		if d.pid <= 0 {
			t.Errorf("%s: missing child PID", tc.kind)
		}
		if d.process.kind != tc.kind {
			t.Errorf("%s: wrong process outcome", tc.kind)
		}
		if d.process.signal != tc.signal {
			t.Errorf("%s: wrong recorded signal", tc.kind)
		}
		if tc.kind == "exited" && d.process.code != tc.wire {
			t.Error("wrong recorded exit code")
		}
		got := formatExecDiagnostic(*d)
		want := "exit=111"
		if tc.kind == "signaled" {
			want = "signal=" + strconv.Itoa(tc.signal)
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s: diagnostics missing process outcome detail", tc.kind)
		}
		if strings.Contains(got, "exit=-1") {
			t.Errorf("%s: diagnostics contain a sentinel exit code", tc.kind)
		}
		timeline := formatTimeline([]execDiagnostic{*d}, nil)
		if !strings.Contains(timeline, "step=process-wait-completed/process-exit") {
			t.Errorf("%s: timeline missing process-wait completion", tc.kind)
		}
		if !strings.Contains(timeline, "step=io-join-completed/ok") {
			t.Errorf("%s: timeline missing successful I/O join", tc.kind)
		}
		if d.ioState != "joined" {
			t.Errorf("%s: I/O state is not joined", tc.kind)
		}
	}
}

type blockedDiagnosticWriter struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (w blockedDiagnosticWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.release
	return 0, io.ErrClosedPipe
}

func TestExecDiagnosticsObserveExitBeforeIOJoin(t *testing.T) {
	for _, tc := range []struct {
		script     string
		exit, wire int
		waitClass  string
	}{
		{"printf x; exit 23", 23, 23, "process-exit"},
		{"printf x; exit 0", 0, 111, "ok"},
	} {
		t.Run(tc.waitClass, func(t *testing.T) {
			s := &ExecServer{startedAt: time.Now()}
			d := s.recordExec(tc.script)
			cmd := exec.Command("sh", "-c", tc.script)
			release := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			entered := make(chan struct{})
			cmd.Stdout = blockedDiagnosticWriter{entered: entered, release: release}
			status := make(chan int, 1)
			go func() { status <- s.runCommand(cmd, d) }()

			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			select {
			case <-entered:
			case <-deadline.C:
				t.Fatal("stdout pump did not reach writer")
			}
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				s.mu.Lock()
				snapshot := *d
				s.mu.Unlock()
				if snapshot.process.kind == "exited" {
					if snapshot.pid <= 0 {
						t.Error("pre-join diagnostics missing child PID")
					}
					if snapshot.process.code != tc.exit {
						t.Error("pre-join diagnostics recorded the wrong exit code")
					}
					if snapshot.ioState != "pending" {
						t.Error("pre-join I/O state is not pending")
					}
					if snapshot.nsteps == 0 || snapshot.steps[snapshot.nsteps-1].state != "process-wait-completed/"+tc.waitClass {
						t.Error("pre-join timeline does not end with the expected wait outcome")
					}
					break
				}
				select {
				case <-tick.C:
				case <-deadline.C:
					t.Fatal("child exit not observed before I/O join")
				}
			}

			close(release)
			select {
			case wire := <-status:
				if wire != tc.wire {
					t.Error("runCommand returned the wrong wire status after pump release")
				}
			case <-deadline.C:
				t.Fatal("I/O did not join after release")
			}
			if d.ioState != "joined" {
				t.Error("post-join I/O state is not joined")
			}
			if d.process.code != tc.exit {
				t.Error("post-join diagnostics recorded the wrong exit code")
			}
			if d.nsteps == 0 || d.steps[d.nsteps-1].state != "io-join-completed/closed" {
				t.Error("post-join timeline does not end with the closed pump outcome")
			}
		})
	}
}
