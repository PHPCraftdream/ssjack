package bridge

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
)

// ParseResult is the reference reader of the text contract: it fills out from
// the text of a tool result. out is a pointer to the keeper result type of the
// tool (remote.TargetsOutput, remote.StartOutput, remote.CancelOutput,
// ReadOutput, application.ListOutput, transfer.StartOutput,
// transfer.StatusOutput, transfer.CancelOutput, declarativeslice.PlanResult or
// declarativeslice.ApplyResult). Conformance tests use it so that they check
// the same text a model sees. The speed of a transfer is read back rounded.
func ParseResult(text string, out any) error {
	switch target := out.(type) {
	case *remote.TargetsOutput:
		targets, err := parseTargets(text)
		target.Targets = targets
		return err
	case *remote.StartOutput:
		id, err := parseStarted(text)
		target.JobID = id
		return err
	case *transfer.StartOutput:
		id, err := parseStarted(text)
		target.JobID = id
		return err
	case *remote.CancelOutput:
		cancelled, err := parseCancelled(text)
		target.Cancelled = cancelled
		return err
	case *transfer.CancelOutput:
		cancelled, err := parseCancelled(text)
		target.Cancelled = cancelled
		return err
	case *ReadOutput:
		return parseRead(text, target)
	case *application.ListOutput:
		return parseApps(text, target)
	case *transfer.StatusOutput:
		return parseTransferStatus(text, target)
	case *declarativeslice.PlanResult:
		return parsePlan(text, target)
	case *declarativeslice.ApplyResult:
		return parseApply(text, target)
	}
	return fmt.Errorf("unsupported result type %s", normalizeImplementationPaths(fmt.Sprintf("%T", out)))
}

// implementationOwnerPath renames implementation package paths back to the
// public owner paths: diagnostics built from %T spell generic type arguments
// with full implementation paths (Go 1.26 instantiated type names use
// targ.LinkString), but the historical owner names are the documented ones.
var implementationOwnerPath = map[string]string{
	"github.com/PHPCraftdream/ssjack/internal/remote/internal/jobs":          "github.com/PHPCraftdream/ssjack/internal/remote",
	"github.com/PHPCraftdream/ssjack/internal/remote/internal/transport":     "github.com/PHPCraftdream/ssjack/internal/remote",
	"github.com/PHPCraftdream/ssjack/internal/apptransport/internal/server":  "github.com/PHPCraftdream/ssjack/internal/apptransport",
	"github.com/PHPCraftdream/ssjack/internal/bridge/internal/tooltext":      "github.com/PHPCraftdream/ssjack/internal/bridge",
	"github.com/PHPCraftdream/ssjack/internal/mcpbridge/internal/supervisor": "github.com/PHPCraftdream/ssjack/internal/mcpbridge",
	"github.com/PHPCraftdream/ssjack/internal/broker/internal/brokercore":    "github.com/PHPCraftdream/ssjack/internal/broker",
	"github.com/PHPCraftdream/ssjack/internal/keyfile/internal/core":         "github.com/PHPCraftdream/ssjack/internal/keyfile",
}

var quotedStringOrPathToken = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|[\p{L}\p{N}_.~/+\-%]+`)

func normalizeImplementationPaths(name string) string {
	if !strings.Contains(name, "github.com/PHPCraftdream/ssjack/") {
		return name
	}
	return quotedStringOrPathToken.ReplaceAllStringFunc(name, func(token string) string {
		if token[0] == '"' {
			return token
		}
		last := strings.LastIndex(token, ".")
		if last < 0 {
			return token
		}
		if owner, ok := implementationOwnerPath[token[:last]]; ok {
			return owner + token[last:]
		}
		return token
	})
}

func errFormat(what string) error {
	return errors.New("malformed " + what + " result text")
}

// firstLine splits off the first line of a text.
func firstLine(text string) (line, rest string) {
	line, rest, _ = strings.Cut(text, "\n")
	return line, rest
}

var (
	startedLine   = regexp.MustCompile(`^Started job (\S+)$`)
	cancelledLine = regexp.MustCompile(`^Cancelled job (\S+)$`)
	finishedLine  = regexp.MustCompile(`^Job (\S+) had already finished$`)
	countLine     = regexp.MustCompile(`^\d+ approved targets?:$`)
	appCountLine  = regexp.MustCompile(`^\d+ registered applications?:$`)
	appLine       = regexp.MustCompile(`^- (\S+) \(profile ([^,)]+)(?:, container ([^)]+))?\)$`)
)

func parseStarted(text string) (string, error) {
	line, _ := firstLine(text)
	match := startedLine.FindStringSubmatch(line)
	if match == nil {
		return "", errFormat("start")
	}
	return match[1], nil
}

func parseCancelled(text string) (bool, error) {
	line, _ := firstLine(text)
	if cancelledLine.MatchString(line) {
		return true, nil
	}
	if finishedLine.MatchString(line) {
		return false, nil
	}
	return false, errFormat("cancel")
}

func parseTargets(text string) ([]string, error) {
	if text == "No approved targets." {
		return nil, nil
	}
	head, rest := firstLine(text)
	if !countLine.MatchString(head) {
		return nil, errFormat("targets")
	}
	var targets []string
	for _, line := range strings.Split(rest, "\n") {
		name, ok := strings.CutPrefix(line, "- ")
		if !ok || name == "" {
			return nil, errFormat("targets")
		}
		targets = append(targets, name)
	}
	return targets, nil
}

func parseApps(text string, out *application.ListOutput) error {
	*out = application.ListOutput{}
	head, rest := firstLine(text)
	empty := head == "No applications are registered."
	if !empty && !appCountLine.MatchString(head) {
		return errFormat("application list")
	}
	for _, line := range strings.Split(rest, "\n") {
		if line == "" {
			continue
		}
		if hint, ok := strings.CutPrefix(line, "Hint: "); ok {
			out.Hint = hint
			continue
		}
		match := appLine.FindStringSubmatch(line)
		if match == nil {
			return errFormat("application list")
		}
		out.Applications = append(out.Applications, application.Description{Name: match[1], Profile: match[2], Container: match[3]})
	}
	if empty != (len(out.Applications) == 0) {
		return errFormat("application list")
	}
	return nil
}

var (
	readHeader = regexp.MustCompile(`^Job (\S+): (running|done \(exit code (-?\d+)\))$`)
	blockLabel = regexp.MustCompile(`^(stdout|stderr) \(bytes \d+-\d+(?:, end marker "([^"]+)")?\):$`)
	base64Line = regexp.MustCompile(`^(stdout|stderr) base64 \(bytes \d+-\d+\): (\S+)$`)
	nextLine   = regexp.MustCompile(`^Next: stdout_offset=(-?\d+) stderr_offset=(-?\d+) · more: stdout=(yes|no) stderr=(yes|no) · lost: stdout=(yes|no) stderr=(yes|no)$`)
)

func parseRead(text string, out *ReadOutput) error {
	*out = ReadOutput{}
	head, rest := firstLine(text)
	match := readHeader.FindStringSubmatch(head)
	if match == nil {
		return errFormat("read")
	}
	out.JobID = match[1]
	out.ExitCode = -1
	if match[3] != "" {
		code, err := strconv.Atoi(match[3])
		if err != nil {
			return errFormat("read")
		}
		out.Done, out.ExitCode = true, code
	}
	seenNext := false
	for len(rest) > 0 {
		var line string
		line, rest = firstLine(rest)
		if message, ok := strings.CutPrefix(line, "Error: "); ok {
			out.Error = message
			continue
		}
		if label := blockLabel.FindStringSubmatch(line); label != nil {
			name, marker := label[1], label[2]
			if marker == "" {
				marker = defaultMarker(name)
			}
			end := strings.Index(rest, "\n"+marker)
			if end < 0 {
				return errFormat("read")
			}
			chunk := rest[:end]
			rest = rest[end+1+len(marker):]
			if rest != "" {
				after, ok := strings.CutPrefix(rest, "\n")
				if !ok {
					return errFormat("read")
				}
				rest = after
			}
			if name == "stdout" {
				out.Stdout = chunk
			} else {
				out.Stderr = chunk
			}
			continue
		}
		if encoded := base64Line.FindStringSubmatch(line); encoded != nil {
			if encoded[1] == "stdout" {
				out.StdoutBase64 = encoded[2]
			} else {
				out.StderrBase64 = encoded[2]
			}
			continue
		}
		if next := nextLine.FindStringSubmatch(line); next != nil {
			var err error
			if out.StdoutOffset, err = strconv.ParseInt(next[1], 10, 64); err != nil {
				return errFormat("read")
			}
			if out.StderrOffset, err = strconv.ParseInt(next[2], 10, 64); err != nil {
				return errFormat("read")
			}
			out.StdoutMore, out.StderrMore = next[3] == "yes", next[4] == "yes"
			out.StdoutLost, out.StderrLost = next[5] == "yes", next[6] == "yes"
			seenNext = true
		}
	}
	if !seenNext {
		return errFormat("read")
	}
	return nil
}

var statusHeader = regexp.MustCompile(`^Transfer (\S+): (?:([^\s,]+)(?: ([^\s,]+))?, )?([^\s,]+)$`)

func parseTransferStatus(text string, out *transfer.StatusOutput) error {
	*out = transfer.StatusOutput{}
	head, rest := firstLine(text)
	match := statusHeader.FindStringSubmatch(head)
	if match == nil {
		return errFormat("transfer status")
	}
	out.JobID, out.Direction, out.Kind, out.State = match[1], match[2], match[3], match[4]
	for _, line := range strings.Split(rest, "\n") {
		if err := parseStatusLine(line, out); err != nil {
			return err
		}
	}
	return nil
}

func parseStatusLine(line string, out *transfer.StatusOutput) error {
	for _, label := range []string{"Failed: ", "Cancelled: "} {
		if failure, ok := strings.CutPrefix(line, label); ok {
			if class, message, found := strings.Cut(failure, " — "); found {
				out.ErrorClass, out.Message = class, message
			} else if strings.ContainsAny(failure, " \t") {
				out.Message = failure
			} else {
				out.ErrorClass = failure
			}
			return nil
		}
	}
	if sum, ok := strings.CutPrefix(line, "Manifest SHA-256: "); ok {
		out.ManifestSHA256 = sum
		return nil
	}
	if sum, ok := strings.CutPrefix(line, "SHA-256: "); ok {
		out.SHA256 = sum
		return nil
	}
	for _, field := range strings.Split(line, fieldSep) {
		key, value, ok := strings.Cut(field, ": ")
		if !ok {
			return nil
		}
		if err := setStatusField(out, key, value); err != nil {
			return err
		}
	}
	return nil
}

func setStatusField(out *transfer.StatusOutput, key, value string) error {
	var err error
	switch key {
	case "Phase":
		out.Phase = value
	case "Mode":
		out.Mode = value
	case "Chunks":
		done, total, found := strings.Cut(value, "/")
		if out.ChunksDone, err = strconv.Atoi(done); err == nil && found {
			out.ChunksTotal, err = strconv.Atoi(total)
		}
	case "Chunk size":
		out.ChunkBytes, err = parseGrouped(strings.TrimSuffix(value, " bytes"))
	case "Attempts":
		out.Attempts, err = strconv.Atoi(value)
	case "Bytes":
		out.Bytes, err = parseGrouped(value)
	case "Files":
		out.Files, err = strconv.Atoi(value)
	case "Dirs":
		out.Dirs, err = strconv.Atoi(value)
	case "Speed":
		out.BytesPerSecond, err = parseRate(value)
	}
	if err != nil {
		return errFormat("transfer status")
	}
	return nil
}

// parseRate reads a rate written by formatRate, rounded to its precision.
func parseRate(text string) (int64, error) {
	number, unit, found := strings.Cut(text, " ")
	if !found {
		return 0, errFormat("transfer status")
	}
	factor := map[string]float64{"B/s": 1, "kB/s": 1e3, "MB/s": 1e6, "GB/s": 1e9}[unit]
	value, err := strconv.ParseFloat(number, 64)
	if err != nil || factor == 0 {
		return 0, errFormat("transfer status")
	}
	return int64(math.Round(value * factor)), nil
}

var (
	planHeader  = regexp.MustCompile(`^Plan (\S+) created$`)
	effectLine  = regexp.MustCompile(`^- ([^:]+): (.*?)( \(destructive\))?$`)
	applyHeader = regexp.MustCompile(`^Operation(?: ([^\s:]+))?: (\S+)$`)
)

func parsePlan(text string, out *declarativeslice.PlanResult) error {
	*out = declarativeslice.PlanResult{}
	head, rest := firstLine(text)
	match := planHeader.FindStringSubmatch(head)
	if match == nil {
		return errFormat("plan")
	}
	out.PlanID = match[1]
	for _, line := range strings.Split(rest, "\n") {
		switch {
		case strings.HasPrefix(line, "Digest: "):
			for _, field := range strings.Split(line, fieldSep) {
				key, value, _ := strings.Cut(field, ": ")
				switch key {
				case "Digest":
					out.Digest = value
				case "Expires":
					out.ExpiresAt = value
				}
			}
		case strings.HasPrefix(line, "Precondition: "):
			if value := strings.TrimPrefix(line, "Precondition: "); value != noPrecondition {
				out.Precondition = &value
			}
		case strings.HasPrefix(line, "- "):
			effect := effectLine.FindStringSubmatch(line)
			if effect == nil {
				return errFormat("plan")
			}
			out.Effects = append(out.Effects, declarativeslice.Effect{Class: effect[1], SummaryID: effect[2], Destructive: effect[3] != ""})
		}
	}
	if out.PlanID == "" {
		return errFormat("plan")
	}
	return nil
}

func parseApply(text string, out *declarativeslice.ApplyResult) error {
	*out = declarativeslice.ApplyResult{}
	head, rest := firstLine(text)
	match := applyHeader.FindStringSubmatch(head)
	if match == nil {
		return errFormat("apply")
	}
	out.OperationID, out.State = match[1], match[2]
	if delivery, ok := strings.CutPrefix(rest, "Delivery: "); ok {
		out.Delivery = delivery
	}
	return nil
}
