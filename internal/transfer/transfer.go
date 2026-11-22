// Package transfer runs owner-registered file transfers as bounded,
// content-free jobs between approved local roots and approved SSH targets
// (docs/FILE-TRANSFER.md). Status records never contain file content,
// absolute local paths, remote stderr or raw lower-layer error text.
//
// This file is a thin facade over internal/transfer/internal/manager,
// which holds the implementation and the in-package tests.
package transfer

import (
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer/internal/manager"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// Exported API aliases preserve the public surface of this import path.
type (
	Engine       = manager.Engine
	Manager      = manager.Manager
	StartInput   = manager.StartInput
	StartOutput  = manager.StartOutput
	StatusInput  = manager.StatusInput
	StatusOutput = manager.StatusOutput
	CancelInput  = manager.CancelInput
	CancelOutput = manager.CancelOutput
)

// NewEngine builds the real engine for one approved target.
func NewEngine(runner remote.StreamRunner, target string, limits transfercore.Limits) (Engine, error) {
	return manager.NewEngine(runner, target, limits)
}

// NewManager roots transfers in the owner-registered roots and approved
// targets; build returns the engine for one target name.
func NewManager(roots []*transferlocal.Root, targets []string, limits transfercore.Limits, build func(string) (Engine, error)) (*Manager, error) {
	return manager.NewManager(roots, targets, limits, build)
}

// ErrUnknownJob is the keeper's word for a job it no longer retains.
var ErrUnknownJob = manager.ErrUnknownJob

// IsUnknownJob reports whether err carries the keeper's unknown-job reply,
// whether it is the keeper's own error or the broker client's re-created one.
func IsUnknownJob(err error) bool {
	return err != nil && err.Error() == manager.ErrUnknownJob.Error()
}
