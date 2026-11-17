package transfer

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type StartInput struct {
	Target    string `json:"target" jsonschema:"Name of a preconfigured SSH target approved by remote_targets"`
	Root      string `json:"root,omitempty" jsonschema:"Owner-registered transfer root name; omit when exactly one root is registered"`
	Local     string `json:"local" jsonschema:"Path relative to the transfer root; never an absolute path"`
	Remote    string `json:"remote" jsonschema:"Absolute POSIX path on the target"`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"Replace an existing destination; requires confirm=true"`
	Confirm   bool   `json:"confirm,omitempty" jsonschema:"Acknowledge a potentially mutating operation; harness authorization still applies"`
}

type StartOutput struct {
	JobID string `json:"job_id" jsonschema:"Transfer job identifier for transfer_status and transfer_cancel"`
}

type StatusInput struct {
	JobID       string `json:"job_id" jsonschema:"Transfer job identifier"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"Optional wait, integer 0 to 25, default 0 (return at once); a larger value counts as 25. A positive value blocks until the job is done, failed or cancelled, or the wait expires, then returns the current status. Prefer one call with 20 over repeated immediate polling"`
}

type StatusOutput struct {
	JobID          string `json:"job_id"`
	State          string `json:"state"`
	Direction      string `json:"direction"`
	Phase          string `json:"phase,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Files          int    `json:"files"`
	Dirs           int    `json:"dirs"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	ErrorClass     string `json:"error_class,omitempty"`
	Message        string `json:"message,omitempty"`

	// The chunked-mode fields are content-free: a mode name and plain
	// integers. They describe single-file transfers only and are omitted while
	// absent (a directory never carries them; an omitted count is zero).
	Mode           string `json:"mode,omitempty" jsonschema:"How a single-file transfer moves its bytes: stream (one whole-file stream) or chunked (resumable parts); omitted for directories"`
	ChunkBytes     int64  `json:"chunk_bytes,omitempty" jsonschema:"Current chunk size in bytes while chunked; omitted otherwise"`
	ChunksDone     int    `json:"chunks_done,omitempty" jsonschema:"Parts verified at the destination so far, including parts found from an earlier call; omitted while zero"`
	ChunksTotal    int    `json:"chunks_total,omitempty" jsonschema:"chunks_done plus an estimate of the parts still needed at the current chunk size; omitted while zero"`
	Attempts       int    `json:"attempts,omitempty" jsonschema:"Number of attempts so far: each stream and each chunk session counts"`
	BytesPerSecond int64  `json:"bytes_per_second,omitempty" jsonschema:"Rounded link throughput estimate in bytes per second; omitted while unknown"`
}

type CancelInput struct {
	JobID string `json:"job_id" jsonschema:"Transfer job identifier"`
}

type CancelOutput struct {
	Cancelled bool `json:"cancelled"`
}

// Handle routes keeper transfer requests; unhandled requests return false.
func (m *Manager) Handle(ctx context.Context, request wire.Request) (wire.Reply, bool) {
	m.bind.Do(func() { context.AfterFunc(ctx, m.cancel) })
	switch request.Operation {
	case "transfer_upload":
		if !m.hasRootsGate() {
			return broker.Result(nil, errNoRoots), true
		}
		var input StartInput
		if wire.Decode(request.Data, &input) != nil {
			return broker.Result(nil, errors.New("invalid transfer arguments")), true
		}
		out, err := m.start(input, false)
		return broker.Result(out, err), true
	case "transfer_download":
		if !m.hasRootsGate() {
			return broker.Result(nil, errNoRoots), true
		}
		var input StartInput
		if wire.Decode(request.Data, &input) != nil {
			return broker.Result(nil, errors.New("invalid transfer arguments")), true
		}
		out, err := m.start(input, true)
		return broker.Result(out, err), true
	case "transfer_status":
		if !m.hasRootsGate() {
			return broker.Result(nil, errNoRoots), true
		}
		var input StatusInput
		if wire.Decode(request.Data, &input) != nil {
			return broker.Result(nil, errors.New("invalid transfer arguments")), true
		}
		wait, err := jobwait.Duration(input.WaitSeconds)
		if err != nil {
			return broker.Result(nil, err), true
		}
		out, err := m.statusWait(ctx, input.JobID, wait)
		return broker.Result(out, err), true
	case "transfer_cancel":
		if !m.hasRootsGate() {
			return broker.Result(nil, errNoRoots), true
		}
		var input CancelInput
		if wire.Decode(request.Data, &input) != nil {
			return broker.Result(nil, errors.New("invalid transfer arguments")), true
		}
		out, err := m.cancelJob(input.JobID)
		return broker.Result(out, err), true
	default:
		return wire.Reply{}, false
	}
}

// hasRootsGate refuses every operation when no root is registered.
func (m *Manager) hasRootsGate() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hasRoots
}
