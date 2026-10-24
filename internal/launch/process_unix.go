//go:build !windows

package launch

import (
	"context"
	"os/exec"
)

func harnessCommand(ctx context.Context, args []string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, args[0], args[1:]...), nil
}
