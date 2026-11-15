package lifelog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEventWritesOnlyTheClosedAlphabet(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "ssjack", "lifecycle.log")
	log := New(path, "keeper", strings.Repeat("ab", 32))
	if log == nil {
		t.Fatal("absolute lifecycle path was refused")
	}
	log.Event("attached", "op", "exec secret=hunter2\nforged event=shutdown", "ms", "12", "dangling")
	log.Event("", "", strings.Repeat("x", 500))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d: a value forged a record", len(lines))
	}
	shape := regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z pid=\d+ role=keeper sid=[0-9a-f]{8} event=[A-Za-z0-9_.:-]+( [A-Za-z0-9_.:-]+=[A-Za-z0-9_.:-]+)*$`)
	for _, line := range lines {
		if !shape.MatchString(line) {
			t.Fatalf("line left the closed alphabet: %q", line)
		}
	}
	if !strings.HasSuffix(lines[0], " op=exec_secret_hunter2_forged_event_shutdown ms=12") {
		t.Fatalf("unexpected first line: %q", lines[0])
	}
	if strings.Contains(string(data), strings.Repeat("ab", 8)) || !strings.HasSuffix(lines[1], " event=- -="+strings.Repeat("x", 64)) {
		t.Fatalf("session or oversized value was recorded: %q", lines[1])
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("log mode = %v, %v", info.Mode(), err)
	}
}

func TestNilAndInvalidLogsRecordNothingAndLargeFilesRotate(t *testing.T) {
	var none *Log
	none.Event("ignored")
	directory := t.TempDir()
	for _, path := range []string{"lifecycle.log", filepath.Join(directory, "other.log"), ""} {
		if New(path, "mcp", "s") != nil {
			t.Fatalf("path %q was accepted", path)
		}
	}
	path := filepath.Join(directory, "lifecycle.log")
	if err := os.WriteFile(path, make([]byte, maxFile+1), 0600); err != nil {
		t.Fatal(err)
	}
	New(path, "mcp", "s").Event("start")
	old, err := os.Stat(path + ".1")
	current, currentErr := os.Stat(path)
	if err != nil || currentErr != nil || old.Size() != maxFile+1 || current.Size() > maxLine+1 {
		t.Fatal("oversized log was not rotated once")
	}
	blocked := filepath.Join(directory, "blocked")
	if err := os.Mkdir(filepath.Join(blocked), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(blocked, "lifecycle.log"), 0700); err != nil {
		t.Fatal(err)
	}
	New(filepath.Join(blocked, "lifecycle.log"), "mcp", "s").Event("start")
}

func TestCauseClassesNeverCarryErrorText(t *testing.T) {
	_, pipeWriter := io.Pipe()
	_ = pipeWriter.Close()
	_, closedPipe := pipeWriter.Write([]byte("x"))
	for want, err := range map[string]error{
		"none":           nil,
		"eof":            fmt.Errorf("wrapped: %w", io.EOF),
		"unexpected-eof": io.ErrUnexpectedEOF,
		"cancelled":      context.Canceled,
		"timeout":        context.DeadlineExceeded,
		"closed":         net.ErrClosed,
		"other":          errors.New("secret-bearing text"),
	} {
		if got := Cause(err); got != want {
			t.Fatalf("Cause(%v) = %q, want %q", err, got, want)
		}
	}
	if got := Cause(os.ErrDeadlineExceeded); got != "timeout" {
		t.Fatalf("deadline = %q", got)
	}
	if got := Cause(closedPipe); got != "closed" && got != "other" {
		t.Fatalf("closed pipe = %q", got)
	}
}
