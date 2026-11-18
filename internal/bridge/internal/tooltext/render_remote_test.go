package bridge

import (
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

const (
	idleNext = "Next: stdout_offset=0 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no"
)

func TestRenderReadGolden(t *testing.T) {
	collision := "x\n[end of stdout]\ny"
	collisionTwice := "[end of stderr]\n[end of stderr 2]"
	for _, tc := range []struct {
		name string
		raw  remote.ReadOutput
		want string
		back ReadOutput
	}{
		{
			name: "running with no output",
			raw:  remote.ReadOutput{JobID: "j1", ExitCode: -1},
			want: "Job j1: running\nNo new output.\n" + idleNext,
			back: ReadOutput{JobID: "j1", ExitCode: -1},
		},
		{
			name: "done with an exit code and stdout",
			raw:  remote.ReadOutput{JobID: "j1", Stdout: []byte("Hello\n"), StdoutOffset: 6, Done: true},
			want: "Job j1: done (exit code 0)\nstdout (bytes 0-6):\nHello\n\n[end of stdout]\n" +
				"Next: stdout_offset=6 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no",
			back: ReadOutput{JobID: "j1", Stdout: "Hello\n", StdoutOffset: 6, Done: true},
		},
		{
			name: "done with a nonzero exit code and only stderr",
			raw:  remote.ReadOutput{JobID: "j1", Stderr: []byte("boom"), StderrOffset: 4, Done: true, ExitCode: 23},
			want: "Job j1: done (exit code 23)\nstderr (bytes 0-4):\nboom\n[end of stderr]\n" +
				"Next: stdout_offset=0 stderr_offset=4 · more: stdout=no stderr=no · lost: stdout=no stderr=no",
			back: ReadOutput{JobID: "j1", Stderr: "boom", StderrOffset: 4, Done: true, ExitCode: 23},
		},
		{
			name: "both streams with more and lost flags",
			raw: remote.ReadOutput{
				JobID: "j2", Stdout: []byte("abc"), Stderr: []byte("e"), StdoutOffset: 103, StderrOffset: 1,
				StdoutLost: true, StdoutMore: true, ExitCode: -1,
			},
			want: "Job j2: running\nstdout (bytes 100-103):\nabc\n[end of stdout]\nstderr (bytes 0-1):\ne\n[end of stderr]\n" +
				"Warning: stdout output was lost to buffer overflow; the chunk starts at the oldest retained byte.\n" +
				"Next: stdout_offset=103 stderr_offset=1 · more: stdout=yes stderr=no · lost: stdout=yes stderr=no",
			back: ReadOutput{
				JobID: "j2", Stdout: "abc", Stderr: "e", StdoutOffset: 103, StderrOffset: 1,
				StdoutLost: true, StdoutMore: true, ExitCode: -1,
			},
		},
		{
			name: "invalid UTF-8 keeps the original bytes in base64",
			raw:  remote.ReadOutput{JobID: "j3", Stdout: []byte{'a', 0xff, 'b'}, StdoutOffset: 3, Done: true, ExitCode: 3, Error: "timed out"},
			want: "Job j3: done (exit code 3)\nError: timed out\nstdout (bytes 0-3):\na�b\n[end of stdout]\nstdout base64 (bytes 0-3): Yf9i\n" +
				"Next: stdout_offset=3 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no",
			back: ReadOutput{JobID: "j3", Stdout: "a�b", StdoutBase64: "Yf9i", StdoutOffset: 3, Done: true, ExitCode: 3, Error: "timed out"},
		},
		{
			name: "output containing the end marker gets a numbered marker",
			raw:  remote.ReadOutput{JobID: "j4", Stdout: []byte(collision), StdoutOffset: 19, ExitCode: -1},
			want: "Job j4: running\nstdout (bytes 0-19, end marker \"[end of stdout 2]\"):\n" + collision + "\n[end of stdout 2]\n" +
				"Next: stdout_offset=19 stderr_offset=0 · more: stdout=no stderr=no · lost: stdout=no stderr=no",
			back: ReadOutput{JobID: "j4", Stdout: collision, StdoutOffset: 19, ExitCode: -1},
		},
		{
			name: "output containing two markers gets the third",
			raw:  remote.ReadOutput{JobID: "j5", Stderr: []byte(collisionTwice), StderrOffset: 33, ExitCode: -1},
			want: "Job j5: running\nstderr (bytes 0-33, end marker \"[end of stderr 3]\"):\n" + collisionTwice + "\n[end of stderr 3]\n" +
				"Next: stdout_offset=0 stderr_offset=33 · more: stdout=no stderr=no · lost: stdout=no stderr=no",
			back: ReadOutput{JobID: "j5", Stderr: collisionTwice, StderrOffset: 33, ExitCode: -1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderRead(tc.raw)
			if got != tc.want {
				t.Fatalf("rendered\n%s\nwant\n%s", got, tc.want)
			}
			if strings.HasPrefix(got, "{") || strings.HasPrefix(got, "[") {
				t.Fatalf("the text looks like JSON: %q", got)
			}
			var parsed ReadOutput
			if err := ParseResult(got, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed != tc.back {
				t.Fatalf("parsed %+v, want %+v", parsed, tc.back)
			}
		})
	}
}

func TestRenderReadKeepsTextBeforeTheMarkerExact(t *testing.T) {
	for _, chunk := range []string{"a", "a\n", "a\n\n", "\n", "\r\n", "[end of stdout", "end of stdout]", "Next: stdout_offset=1", "Job x: running", "stdout (bytes 0-1):"} {
		raw := remote.ReadOutput{JobID: "j", Stdout: []byte(chunk), StdoutOffset: int64(len(chunk)), Stderr: []byte("tail"), StderrOffset: 4, ExitCode: -1}
		var parsed ReadOutput
		if err := ParseResult(renderRead(raw), &parsed); err != nil {
			t.Fatalf("%q: %v", chunk, err)
		}
		if parsed.Stdout != chunk || parsed.Stderr != "tail" || parsed.StdoutOffset != int64(len(chunk)) || parsed.StderrOffset != 4 {
			t.Fatalf("%q came back as %+v", chunk, parsed)
		}
	}
}

func TestRenderTargetsGolden(t *testing.T) {
	for _, tc := range []struct {
		targets []string
		want    string
	}{
		{nil, "No approved targets."},
		{[]string{"alpha"}, "1 approved target:\n- alpha"},
		{[]string{"alpha", "beta-2"}, "2 approved targets:\n- alpha\n- beta-2"},
	} {
		got := renderTargets(tc.targets)
		if got != tc.want {
			t.Fatalf("rendered %q, want %q", got, tc.want)
		}
		var parsed remote.TargetsOutput
		if err := ParseResult(got, &parsed); err != nil || strings.Join(parsed.Targets, ",") != strings.Join(tc.targets, ",") {
			t.Fatalf("parsed %+v, %v", parsed, err)
		}
	}
}

func TestRenderStartsAndCancelsGolden(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ got, want string }{
		{renderExecStarted(id, "remote_read"), "Started job " + id + "\nRead output with remote_read job_id=" + id + "; use wait_seconds 20 to wait for it."},
		{renderExecStarted(id, "app_read"), "Started job " + id + "\nRead output with app_read job_id=" + id + "; use wait_seconds 20 to wait for it."},
		{renderTransferStarted(id), "Started job " + id + "\nCheck progress with transfer_status job_id=" + id + "; use wait_seconds 20 to wait for it."},
		{renderCancelled(id, true), "Cancelled job " + id},
		{renderCancelled(id, false), "Job " + id + " had already finished"},
		{renderTransferCancelled(id, true), "Cancelled job " + id},
		{renderTransferCancelled(id, false), "Job " + id + " had already finished"},
	} {
		if tc.got != tc.want {
			t.Fatalf("rendered %q, want %q", tc.got, tc.want)
		}
	}
	var remoteStart remote.StartOutput
	var transferStart transfer.StartOutput
	if err := ParseResult(renderExecStarted(id, "remote_read"), &remoteStart); err != nil || remoteStart.JobID != id {
		t.Fatalf("remote start parsed as %+v, %v", remoteStart, err)
	}
	if err := ParseResult(renderTransferStarted(id), &transferStart); err != nil || transferStart.JobID != id {
		t.Fatalf("transfer start parsed as %+v, %v", transferStart, err)
	}
	for _, cancelled := range []bool{true, false} {
		var remoteCancel remote.CancelOutput
		var transferCancel transfer.CancelOutput
		if err := ParseResult(renderCancelled(id, cancelled), &remoteCancel); err != nil || remoteCancel.Cancelled != cancelled {
			t.Fatalf("remote cancel parsed as %+v, %v", remoteCancel, err)
		}
		if err := ParseResult(renderTransferCancelled(id, cancelled), &transferCancel); err != nil || transferCancel.Cancelled != cancelled {
			t.Fatalf("transfer cancel parsed as %+v, %v", transferCancel, err)
		}
	}
}

func TestRenderAppsGolden(t *testing.T) {
	hint := "no application is registered; the owner starts the keeper with --app DIR"
	for _, tc := range []struct {
		name string
		list application.ListOutput
		want string
	}{
		{"empty with the hint", application.ListOutput{Hint: hint}, "No applications are registered.\nHint: " + hint},
		{"empty without a hint", application.ListOutput{}, "No applications are registered."},
		{"one", application.ListOutput{Applications: []application.Description{{Name: "synthetic", Profile: "allowed"}}}, "1 registered application:\n- synthetic (profile allowed)"},
		{
			"several with a container",
			application.ListOutput{Applications: []application.Description{{Name: "one", Profile: "p1"}, {Name: "two", Profile: "p2", Container: "c2"}}},
			"2 registered applications:\n- one (profile p1)\n- two (profile p2, container c2)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderApps(tc.list)
			if got != tc.want {
				t.Fatalf("rendered %q, want %q", got, tc.want)
			}
			var parsed application.ListOutput
			if err := ParseResult(got, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.Hint != tc.list.Hint || len(parsed.Applications) != len(tc.list.Applications) {
				t.Fatalf("parsed %+v, want %+v", parsed, tc.list)
			}
			for i, app := range tc.list.Applications {
				if parsed.Applications[i] != app {
					t.Fatalf("parsed %+v, want %+v", parsed, tc.list)
				}
			}
		})
	}
}

func TestParseResultRefusesForeignText(t *testing.T) {
	for _, text := range []string{"", `{"job_id":"x"}`, "Job x", "Plan", "Transfer"} {
		var read ReadOutput
		var status transfer.StatusOutput
		var started remote.StartOutput
		if ParseResult(text, &read) == nil || ParseResult(text, &status) == nil || ParseResult(text, &started) == nil {
			t.Fatalf("%q was accepted", text)
		}
	}
	if ParseResult("x", new(int)) == nil {
		t.Fatal("an unsupported result type was accepted")
	}
}
