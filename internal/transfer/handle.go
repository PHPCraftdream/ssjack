package transfer

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/broker"
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
	JobID string `json:"job_id" jsonschema:"Transfer job identifier"`
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
		out, err := m.status(input.JobID)
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
