package bridge

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

// renderApps lists the registered applications, one per line. An empty list
// says so and repeats the keeper's hint.
func renderApps(list application.ListOutput) string {
	var lines []string
	switch len(list.Applications) {
	case 0:
		lines = append(lines, "No applications are registered.")
	case 1:
		lines = append(lines, "1 registered application:")
	default:
		lines = append(lines, fmt.Sprintf("%d registered applications:", len(list.Applications)))
	}
	for _, app := range list.Applications {
		detail := "profile " + app.Profile
		if app.Container != "" {
			detail += ", container " + app.Container
		}
		lines = append(lines, fmt.Sprintf("- %s (%s)", app.Name, detail))
	}
	if list.Hint != "" {
		lines = append(lines, "Hint: "+oneLine(list.Hint))
	}
	return strings.Join(lines, "\n")
}

// Text contract of the declarative tools (see docs/declarative/protocol.md).
// Both results are flat, so no nesting is rendered. A plan is:
//
//	Plan <plan_id> created
//	Digest: <digest> · Expires: <expires_at>
//	Precondition: <revision>        (none when absent)
//	Effects: <n>                    (none when empty)
//	- <class>: <summary_id> [(destructive)]
//	Next: apply it with plan_apply plan_id=<plan_id> and a new request_id.
//
// An apply is:
//
//	Operation <operation_id>: <state>
//	Delivery: <delivery>            (only when the keeper reports one)

const noPrecondition = "none"

// renderPlan is the result of resource_plan.
func renderPlan(plan declarativeslice.PlanResult) string {
	precondition := noPrecondition
	if plan.Precondition != nil {
		precondition = oneLine(*plan.Precondition)
	}
	lines := []string{
		fmt.Sprintf("Plan %s created", plan.PlanID),
		fmt.Sprintf("Digest: %s%sExpires: %s", plan.Digest, fieldSep, plan.ExpiresAt),
		"Precondition: " + precondition,
	}
	if len(plan.Effects) == 0 {
		lines = append(lines, "Effects: none")
	} else {
		lines = append(lines, fmt.Sprintf("Effects: %d", len(plan.Effects)))
		for _, effect := range plan.Effects {
			line := fmt.Sprintf("- %s: %s", effect.Class, effect.SummaryID)
			if effect.Destructive {
				line += " (destructive)"
			}
			lines = append(lines, line)
		}
	}
	lines = append(lines, fmt.Sprintf("Next: apply it with plan_apply plan_id=%s and a new request_id.", plan.PlanID))
	return strings.Join(lines, "\n")
}

// renderApply is the result of plan_apply.
func renderApply(result declarativeslice.ApplyResult) string {
	headline := "Operation: " + result.State
	if result.OperationID != "" {
		headline = fmt.Sprintf("Operation %s: %s", result.OperationID, result.State)
	}
	lines := []string{headline}
	if result.Delivery != "" {
		lines = append(lines, "Delivery: "+result.Delivery)
	}
	return strings.Join(lines, "\n")
}

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

// Text contract of the transfer tools (see docs/FILE-TRANSFER.md). A status
// is:
//
//	Transfer <job_id>: <direction> <kind>, <state>
//	Phase: <phase> · Mode: <mode> · Chunks: <done>/<total> · Chunk size: <n> bytes · Attempts: <n>
//	Bytes: <n> · Files: <n> · Dirs: <n> · Speed: <rate>
//	SHA-256: <hex>
//	Manifest SHA-256: <hex>
//	Failed: <error_class> — <message>
//
// A field that is absent is left out together with its label, and so is a line
// without any field. Failed becomes Cancelled for a cancelled job. A running
// job adds a hint to wait with transfer_status; a link_unstable failure adds
// how to resume.

// renderTransferStarted is the result of a started upload or download.
func renderTransferStarted(jobID string) string {
	return fmt.Sprintf("Started job %s\nCheck progress with transfer_status job_id=%s; use wait_seconds 20 to wait for it.", jobID, jobID)
}

// renderTransferCancelled is the result of cancelling a transfer job.
func renderTransferCancelled(jobID string, cancelled bool) string {
	return renderCancelled(jobID, cancelled)
}

// renderTransferStatus is the result of a status call.
func renderTransferStatus(s transfer.StatusOutput) string {
	subject := strings.TrimSpace(s.Direction + " " + s.Kind)
	headline := fmt.Sprintf("Transfer %s: ", s.JobID)
	if subject != "" {
		headline += subject + ", "
	}
	headline += s.State
	lines := []string{headline}

	var chunks string
	switch {
	case s.ChunksTotal > 0:
		chunks = fmt.Sprintf("Chunks: %d/%d", s.ChunksDone, s.ChunksTotal)
	case s.ChunksDone > 0:
		chunks = fmt.Sprintf("Chunks: %d", s.ChunksDone)
	}
	if line := joinFields(
		labelled("Phase", s.Phase),
		labelled("Mode", s.Mode),
		chunks,
		positive("Chunk size", s.ChunkBytes, " bytes"),
		positive("Attempts", int64(s.Attempts), ""),
	); line != "" {
		lines = append(lines, line)
	}

	speed := ""
	if s.BytesPerSecond > 0 {
		speed = "Speed: " + formatRate(s.BytesPerSecond)
	}
	lines = append(lines, joinFields(
		"Bytes: "+groupInt(s.Bytes),
		fmt.Sprintf("Files: %d", s.Files),
		fmt.Sprintf("Dirs: %d", s.Dirs),
		speed,
	))
	if s.SHA256 != "" {
		lines = append(lines, "SHA-256: "+s.SHA256)
	}
	if s.ManifestSHA256 != "" {
		lines = append(lines, "Manifest SHA-256: "+s.ManifestSHA256)
	}
	if s.ErrorClass != "" || s.Message != "" {
		lines = append(lines, failureLine(s))
	}
	switch {
	case s.State == "running":
		lines = append(lines, fmt.Sprintf("Still running; check again with transfer_status job_id=%s and wait_seconds 20.", s.JobID))
	case s.ErrorClass == "link_unstable":
		lines = append(lines, fmt.Sprintf("Resume: call %s again with the same arguments to continue from the staged parts; transfer_cancel removes them instead.", resumeTool(s.Direction)))
	}
	return strings.Join(lines, "\n")
}

// failureLine is the Failed (or Cancelled) line of a status.
func failureLine(s transfer.StatusOutput) string {
	label := "Failed"
	if s.State == "cancelled" {
		label = "Cancelled"
	}
	switch {
	case s.ErrorClass == "":
		return label + ": " + oneLine(s.Message)
	case s.Message == "":
		return label + ": " + s.ErrorClass
	}
	return label + ": " + s.ErrorClass + " — " + oneLine(s.Message)
}

func resumeTool(direction string) string {
	if direction == "download" {
		return "remote_download"
	}
	return "remote_upload"
}

// labelled is "Label: value", empty for an empty value.
func labelled(label, value string) string {
	if value == "" {
		return ""
	}
	return label + ": " + value
}

// positive is "Label: n<unit>" with thousands separators, empty unless n is
// above zero.
func positive(label string, n int64, unit string) string {
	if n <= 0 {
		return ""
	}
	return label + ": " + groupInt(n) + unit
}

// formatRate spells a throughput in decimal units with one decimal.
func formatRate(bytesPerSecond int64) string {
	value := float64(bytesPerSecond)
	switch {
	case bytesPerSecond >= 1_000_000_000:
		return fmt.Sprintf("%.1f GB/s", value/1e9)
	case bytesPerSecond >= 1_000_000:
		return fmt.Sprintf("%.1f MB/s", value/1e6)
	case bytesPerSecond >= 1_000:
		return fmt.Sprintf("%.1f kB/s", value/1e3)
	}
	return fmt.Sprintf("%d B/s", bytesPerSecond)
}
