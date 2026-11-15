package main

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// transferRootFlags collects repeatable --transfer-root specifications.
type transferRootFlags []string

func (l *transferRootFlags) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, " ")
}

func (l *transferRootFlags) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// transferOptions holds parsed transfer roots and validated limits.
type transferOptions struct {
	roots  []*transferlocal.Root
	limits transfercore.Limits
}

// prepareTransfer validates the limits and parses every [NAME=]DIR root
// against the vault path before the vault is unlocked.
func prepareTransfer(vaultPath string, specs []string, maxBytes int64, maxEntries int) (*transferOptions, error) {
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
	return &transferOptions{roots: roots, limits: limits}, nil
}

// newTransferManager builds the transfer manager over the parsed roots and
// approved targets, creating one engine per target.
func newTransferManager(options *transferOptions, targets []string, runner remote.StreamRunner) (*transfer.Manager, error) {
	return transfer.NewManager(options.roots, targets, options.limits, func(target string) (transfer.Engine, error) {
		return transfer.NewEngine(runner, target, options.limits)
	})
}
