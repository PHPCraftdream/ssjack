// Package immutableexec provides an isolated, bounded immutable executable binder.
// It is not integrated into production launch paths.
package immutableexec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

var ErrUnsupported = errors.New("immutable executable binding unsupported")
var ErrInvalidEnvironment = errors.New("invalid or unsafe environment")

// Environment is intentionally restricted to reviewed, non-secret locale and terminal settings.
var safeEnvironment = map[string]bool{"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true, "TERM": true}

func validateObserveRequest(ctx context.Context, env []string, data []byte) (driverprotocol.StructuralRequest, error) {
	if ctx == nil {
		return driverprotocol.StructuralRequest{}, errors.New("explicit deadline context required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return driverprotocol.StructuralRequest{}, errors.New("explicit deadline required")
	}
	request, err := driverprotocol.ValidateStructuralRequest(data)
	if err != nil || request.Action() != "observe" {
		return driverprotocol.StructuralRequest{}, driverprotocol.ErrInvalid
	}
	if err := validateEnvironment(env); err != nil {
		return driverprotocol.StructuralRequest{}, err
	}
	return request, nil
}

const maxObserveStdout = 65540
const maxObserveStderr = 65536

type observeWriters struct {
	mu                 sync.Mutex
	cmd                *exec.Cmd
	started            bool
	killRequested      bool
	stdout             *bytes.Buffer
	outBytes, errBytes int
	overflow           bool
}
type observeStream struct {
	owner  *observeWriters
	stderr bool
}

// publishStarted synchronizes cmd.Process publication with early output writers.
func (o *observeWriters) publishStarted() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.started = true
	if o.killRequested && o.cmd.Process != nil {
		_ = o.cmd.Process.Kill()
	}
}

func (s observeStream) Write(p []byte) (int, error) {
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	used, limit := &o.outBytes, maxObserveStdout
	if s.stderr {
		used, limit = &o.errBytes, maxObserveStderr
	}
	if len(p) > limit-*used {
		o.overflow = true
		if o.started && o.cmd.Process != nil {
			_ = o.cmd.Process.Kill()
		} else {
			o.killRequested = true
		}
		return 0, errors.New("child output limit exceeded")
	}
	*used += len(p)
	if !s.stderr {
		return o.stdout.Write(p)
	}
	return len(p), nil
}

func validateEnvironment(env []string) error {
	if env == nil {
		return ErrInvalidEnvironment
	}
	seen := make(map[string]bool, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, 0) || !safeEnvironment[key] || seen[key] {
			return ErrInvalidEnvironment
		}
		seen[key] = true
	}
	return nil
}
