package remote

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

var ErrJob = errors.New("remote operation failed")
var ErrAdmission = errors.New("remote operation capability unavailable")

// GuardProvider captures a private immutable capability before each model job.
type GuardProvider func(context.Context) (*outputguard.Snapshot, error)
type AdmissionProvider func(context.Context, string, string) (AdmittedOperation, error)

type AdmittedOperation struct {
	Runner Runner
	Guard  *outputguard.Snapshot
	// Issued records validated admission before its worker starts.
	Issued func()
}

func NewAdmittedManager(parent context.Context, targets []string, provider AdmissionProvider) *Manager {
	manager := NewManager(parent, targets, nil)
	manager.admit = provider
	return manager
}

func prepareAdmitted(admitted AdmittedOperation) (Runner, error) {
	if admitted.Runner == nil || admitted.Guard == nil {
		return nil, ErrAdmission
	}
	validator, err := outputguard.NewWriter(admitted.Guard, io.Discard)
	if err != nil {
		return nil, ErrAdmission
	}
	if err := validator.Close(); err != nil {
		return nil, ErrAdmission
	}
	runner, guard := admitted.Runner, admitted.Guard
	return func(ctx context.Context, target, command string, stdout, stderr io.Writer) (int, error) {
		return guardedRun(ctx, runner, guard, target, command, stdout, stderr)
	}, nil
}

func closeGuarded(out, errOut io.Closer, exit int, runErr error, ctx context.Context) (int, error) {
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
}

func guardedRun(ctx context.Context, runner Runner, snapshot *outputguard.Snapshot, target, command string, stdout, stderr io.Writer) (int, error) {
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
	return closeGuarded(out, errOut, exit, runErr, ctx)
}

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
		return guardedRun(ctx, runner, snapshot, target, command, stdout, stderr)
	})
}

type capture struct {
	mu    sync.Mutex
	data  []byte
	total int64
}

func (b *capture) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(data)
	b.total += int64(n)
	if n >= outputLimit {
		b.data = append(b.data[:0], data[n-outputLimit:]...)
	} else {
		if excess := len(b.data) + n - outputLimit; excess > 0 {
			copy(b.data, b.data[excess:])
			b.data = b.data[:len(b.data)-excess]
		}
		b.data = append(b.data, data...)
	}
	return n, nil
}

func (b *capture) read(offset int64) ([]byte, int64, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if offset < 0 || offset > b.total {
		return nil, offset, false, errors.New("invalid output offset")
	}
	start := b.total - int64(len(b.data))
	lost := offset < start
	if lost {
		offset = start
	}
	index := int(offset - start)
	end := min(index+chunkLimit, len(b.data))
	return append([]byte{}, b.data[index:end]...), offset + int64(end-index), lost, nil
}

func (b *capture) more(offset int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return offset < b.total
}

type job struct {
	stdout capture
	stderr capture
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	exit   int
	err    string
}
