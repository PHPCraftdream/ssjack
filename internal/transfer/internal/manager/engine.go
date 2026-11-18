// Package manager runs owner-registered file transfers as bounded,
// content-free jobs between approved local roots and approved SSH targets
// (docs/FILE-TRANSFER.md). Status records never contain file content,
// absolute local paths, remote stderr or raw lower-layer error text.
package manager

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// Engine performs transfers against one approved target;
// *transferengine.Engine satisfies it exactly.
type Engine interface {
	Upload(ctx context.Context, root *transferlocal.Root, local, remote string, overwrite bool, progress func(transferengine.Progress)) (transferengine.Result, error)
	Download(ctx context.Context, root *transferlocal.Root, remote, local string, overwrite bool, progress func(transferengine.Progress)) (transferengine.Result, error)
}

// NewEngine builds the real engine for one approved target.
func NewEngine(runner remote.StreamRunner, target string, limits transfercore.Limits) (Engine, error) {
	return transferengine.NewWithOptions(transferremote.NewChunk(runner, target, limits), limits, transferengine.Options{Target: target})
}
