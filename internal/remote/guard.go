package remote

import (
	"context"
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

var ErrJob = errors.New("remote operation failed")

// GuardProvider captures a private immutable capability before each model job.
type GuardProvider func(context.Context) (*outputguard.Snapshot, error)

// NewGuardedManager masks model output before capture. Read offsets count filtered
// bytes. Human shells and private StreamRunner protocols do not use this path.
func NewGuardedManager(parent context.Context, targets []string, runner Runner, provider GuardProvider) *Manager {
	return NewManager(parent, targets, func(ctx context.Context, target, command string, stdout, stderr io.Writer) (int, error) {
		if runner == nil || provider == nil || ctx.Err() != nil {
			return -1, outputguard.ErrGuard
		}
		snapshot, err := provider(ctx)
		if err != nil || ctx.Err() != nil {
			return -1, outputguard.ErrGuard
		}
		out, err := outputguard.NewWriter(snapshot, stdout)
		if err != nil {
			return -1, outputguard.ErrGuard
		}
		errOut, err := outputguard.NewWriter(snapshot, stderr)
		if err != nil {
			_ = out.Close()
			return -1, outputguard.ErrGuard
		}
		exit, runErr := runner(ctx, target, command, out, errOut)
		outErr, stderrErr := out.Close(), errOut.Close()
		if outErr != nil || stderrErr != nil {
			return exit, outputguard.ErrGuard
		}
		if runErr != nil {
			if err := ctx.Err(); err == context.Canceled || err == context.DeadlineExceeded {
				return exit, err
			}
			return exit, ErrJob
		}
		return exit, nil
	})
}
