// Package transferengine is the public root facade of the transfer engine.
// The implementation lives in internal/transferengine/internal/engine
// (package engine) and the stall watchdog in
// internal/transferengine/internal/watchdog; this file
// re-exports their public surface so existing importers of this package keep
// working unchanged.
package transferengine

import (
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/engine"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/watchdog"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// Engine is the transfer engine over one approved remote target.
type Engine = engine.Engine

// Progress reports the phase and bytes transferred so far.
type Progress = engine.Progress

// Result is the bounded, content-free outcome of one transfer.
type Result = engine.Result

// Kind is the transfer kind, detected from the source.
type Kind = engine.Kind

// Options configure NewWithOptions.
type Options = engine.Options

// Transfer kinds.
const (
	KindFile = engine.KindFile
	KindDir  = engine.KindDir
)

// Transfer modes reported in Progress.Mode and Result.Mode.
const (
	ModeStream  = engine.ModeStream
	ModeChunked = engine.ModeChunked
)

// StallClock and StallTimer are the watchdog's timer interfaces.
type (
	StallClock = watchdog.StallClock
	StallTimer = watchdog.StallTimer
)

// DefaultStallLimit is how long a byte-moving session may deliver no byte
// before the stall watchdog aborts it.
const DefaultStallLimit = watchdog.DefaultStallLimit

// New validates the limits and returns an Engine over remote with default
// options.
func New(remote transferremote.Remote, limits transfercore.Limits) (*Engine, error) {
	return engine.New(remote, limits)
}

// NewWithOptions is New with the target name, an injectable link profile and
// an injectable clock.
func NewWithOptions(remote transferremote.Remote, limits transfercore.Limits, opts Options) (*Engine, error) {
	return engine.NewWithOptions(remote, limits, opts)
}
