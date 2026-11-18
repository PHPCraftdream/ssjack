// Package transferremote implements the remote half of the ssjack
// file-transfer protocol: capability probing, staging, file transfer, tree
// listing and verification, tar streaming and atomic publication over
// remote.StreamRunner using fixed command templates.
//
// The implementation is split by responsibility: core (runner, error
// classes, shell quoting, capabilities), probe, fileops, tree and chunk. This
// package composes them behind Remote and ChunkRemote.
package transferremote

import (
	"context"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/chunk"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/fileops"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/probe"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/tree"
)

// Remote is the set of remote primitives the transfer engines are built on.
// Later engines compose these primitives; fakes can implement it on any OS.
type Remote interface {
	Probe(ctx context.Context) error
	CreateStaging(ctx context.Context, parent string) (string, error)
	CleanupStaging(ctx context.Context, parent, name string) error
	WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error)
	StatFile(ctx context.Context, path string) (int64, [32]byte, error)
	ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error)
	PreflightTree(ctx context.Context, root string) (transfercore.Manifest, error)
	TarOut(ctx context.Context, root string, dst io.Writer) error
	TarIn(ctx context.Context, root string, src io.Reader) error
	VerifyTree(ctx context.Context, root string, manifest transfercore.Manifest) error
	PublishFile(ctx context.Context, staging, dest string, overwrite bool) error
	PublishDir(ctx context.Context, staging, dest string, overwrite bool) error
}

// remoteRunner is the composition of the operation sets over one core.Runner.
type remoteRunner struct {
	*core.Runner
	*probe.Prober
	*fileops.FileOps
	*tree.TreeOps
	*chunk.ChunkOps
}

var (
	_ Remote      = (*remoteRunner)(nil)
	_ ChunkRemote = (*remoteRunner)(nil)
)

func newRunner(run remote.StreamRunner, target string, limits transfercore.Limits) *remoteRunner {
	r := core.NewRunner(run, target, limits)
	return &remoteRunner{
		Runner: r, Prober: probe.New(r), FileOps: fileops.New(r), TreeOps: tree.New(r), ChunkOps: chunk.New(r),
	}
}

// New returns a Remote that runs fixed templates against target via run.
func New(run remote.StreamRunner, target string, limits transfercore.Limits) Remote {
	return newRunner(run, target, limits)
}

// NewChunk returns the Remote of New as a ChunkRemote.
func NewChunk(run remote.StreamRunner, target string, limits transfercore.Limits) ChunkRemote {
	return newRunner(run, target, limits)
}
