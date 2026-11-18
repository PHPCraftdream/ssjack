// Package transfercmd implements the production transfer command surface:
// repeatable --transfer-root flag collection, validation of transfer limits
// and root specifications against the vault path, and construction of the
// transfer manager over the approved targets.
package transfercmd

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// RootFlags collects repeatable --transfer-root specifications.
type RootFlags []string

func (l *RootFlags) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, " ")
}

func (l *RootFlags) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// Options holds parsed transfer roots and validated limits.
type Options struct {
	Roots  []*transferlocal.Root
	Limits transfercore.Limits
}

// Prepare validates the limits and parses every [NAME=]DIR root against the
// vault path before the vault is unlocked.
func Prepare(vaultPath string, specs []string, maxBytes int64, maxEntries int) (*Options, error) {
	limits := transfercore.DefaultLimits()
	limits.MaxBytes, limits.MaxEntries = maxBytes, maxEntries
	if limits.Validate() != nil {
		return nil, errors.New("transfer limits are invalid")
	}
	vault, err := filepath.Abs(vaultPath)
	if err != nil {
		return nil, errors.New("vault path could not be resolved for transfer roots")
	}
	byName := transferlocal.NewRoots()
	roots := make([]*transferlocal.Root, 0, len(specs))
	for _, spec := range specs {
		root, err := transferlocal.ParseRoot(spec, vault)
		if err != nil {
			return nil, err
		}
		if err := byName.Add(root); err != nil {
			return nil, err
		}
		roots = append(roots, root)
	}
	return &Options{Roots: roots, Limits: limits}, nil
}

// NewManager builds the transfer manager over the parsed roots and approved
// targets, creating one engine per target.
func NewManager(options *Options, targets []string, runner remote.StreamRunner) (*transfer.Manager, error) {
	return transfer.NewManager(options.Roots, targets, options.Limits, func(target string) (transfer.Engine, error) {
		return transfer.NewEngine(runner, target, options.Limits)
	})
}
