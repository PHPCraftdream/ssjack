package bridge

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/remote"
)

// Text contract of the remote and application tools (see docs/REMOTE-MCP.md).
//
// A command or application output chunk is shown verbatim between a label line
// and an end marker line:
//
//	stdout (bytes 0-237):
//	<the chunk text, line breaks included>
//	[end of stdout]
//
// The range is half open: it starts at the offset the chunk begins at and ends
// at the offset after it, which is also the next offset to pass. The marker is
// [end of stdout] (or [end of stderr]). When the chunk text itself contains
// that string, the marker gets a number, [end of stdout 2], [end of stdout 3]
// and so on, the first one the chunk does not contain, and the label names it:
//
//	stdout (bytes 0-12, end marker "[end of stdout 2]"):
//
// The text shown is the chunk with invalid UTF-8 replaced; a chunk that is not
// valid UTF-8 is followed by a line
//
//	stdout base64 (bytes 0-12): <the original bytes, standard base64>
//
// A chunk is always followed by a line break and then the marker, so the chunk
// text is everything between the label line and the line break before the
// marker.

const unreadable = "�"

// stream is one output stream of a read.
type stream struct {
	name string
	data []byte
	next int64
	more bool
	lost bool
}

// renderTargets lists the approved targets, one per line.
func renderTargets(targets []string) string {
	if len(targets) == 0 {
		return "No approved targets."
	}
	lines := make([]string, 0, len(targets)+1)
	if len(targets) == 1 {
		lines = append(lines, "1 approved target:")
	} else {
		lines = append(lines, fmt.Sprintf("%d approved targets:", len(targets)))
	}
	for _, target := range targets {
		lines = append(lines, "- "+target)
	}
	return strings.Join(lines, "\n")
}

// renderExecStarted is the result of a started command or application job;
// readTool names the tool that reads its output.
func renderExecStarted(jobID, readTool string) string {
	return fmt.Sprintf("Started job %s\nRead output with %s job_id=%s; use wait_seconds 20 to wait for it.", jobID, readTool, jobID)
}

// renderCancelled is the result of a cancel call.
func renderCancelled(jobID string, cancelled bool) string {
	if cancelled {
		return "Cancelled job " + jobID
	}
	return "Job " + jobID + " had already finished"
}

// renderRead is the result of one output read.
func renderRead(raw remote.ReadOutput) string {
	state := "running"
	if raw.Done {
		state = fmt.Sprintf("done (exit code %d)", raw.ExitCode)
	}
	lines := []string{fmt.Sprintf("Job %s: %s", raw.JobID, state)}
	if raw.Error != "" {
		lines = append(lines, "Error: "+oneLine(raw.Error))
	}
	streams := []stream{
		{"stdout", raw.Stdout, raw.StdoutOffset, raw.StdoutMore, raw.StdoutLost},
		{"stderr", raw.Stderr, raw.StderrOffset, raw.StderrMore, raw.StderrLost},
	}
	for _, s := range streams {
		lines = append(lines, streamBlock(s)...)
	}
	if len(raw.Stdout) == 0 && len(raw.Stderr) == 0 {
		lines = append(lines, "No new output.")
	}
	for _, s := range streams {
		if s.lost {
			lines = append(lines, fmt.Sprintf("Warning: %s output was lost to buffer overflow; the chunk starts at the oldest retained byte.", s.name))
		}
	}
	lines = append(lines, fmt.Sprintf("Next: stdout_offset=%d stderr_offset=%d%smore: stdout=%s stderr=%s%slost: stdout=%s stderr=%s",
		raw.StdoutOffset, raw.StderrOffset, fieldSep,
		yesNo(raw.StdoutMore), yesNo(raw.StderrMore), fieldSep,
		yesNo(raw.StdoutLost), yesNo(raw.StderrLost)))
	return strings.Join(lines, "\n")
}

// streamBlock is the label, text, marker and optional base64 lines of one
// non-empty chunk.
func streamBlock(s stream) []string {
	if len(s.data) == 0 {
		return nil
	}
	text := strings.ToValidUTF8(string(s.data), unreadable)
	marker := endMarker(s.name, text)
	start := max(s.next-int64(len(s.data)), 0)
	label := fmt.Sprintf("%s (bytes %d-%d):", s.name, start, s.next)
	if marker != defaultMarker(s.name) {
		label = fmt.Sprintf("%s (bytes %d-%d, end marker %q):", s.name, start, s.next, marker)
	}
	lines := []string{label, text, marker}
	if !utf8.Valid(s.data) {
		lines = append(lines, fmt.Sprintf("%s base64 (bytes %d-%d): %s", s.name, start, s.next, base64.StdEncoding.EncodeToString(s.data)))
	}
	return lines
}

func defaultMarker(name string) string {
	return "[end of " + name + "]"
}

// endMarker is the first marker of the stream the text does not contain.
func endMarker(name, text string) string {
	marker := defaultMarker(name)
	for n := 2; strings.Contains(text, marker); n++ {
		marker = fmt.Sprintf("[end of %s %d]", name, n)
	}
	return marker
}
