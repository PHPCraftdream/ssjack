package bridge

import (
	"fmt"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

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
