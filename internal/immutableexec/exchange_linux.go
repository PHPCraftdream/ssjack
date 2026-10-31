//go:build linux

package immutableexec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func (r *Runner) Exchange(ctx context.Context, env []string, dir string, requestBytes []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("explicit deadline context required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("explicit deadline required")
	}
	request, err := driverprotocol.ValidateStructuralRequest(requestBytes)
	if err != nil || request.Action() != "observe" && request.Action() != "apply" && request.Action() != "reconcile" {
		return nil, driverprotocol.ErrInvalid
	}
	if err := validateEnvironment(env); err != nil {
		return nil, err
	}
	if r == nil || !r.mu.TryLock() {
		return nil, errors.New("closed binding or runner busy")
	}
	defer r.mu.Unlock()
	if r.file == nil {
		return nil, errors.New("closed binding")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", r.args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.ExtraFiles = []*os.File{r.file}
	cmd.Env, cmd.Dir = append([]string{}, env...), dir
	var stdin bytes.Buffer
	if err := driverframe.Write(&stdin, requestBytes); err != nil {
		return nil, driverprotocol.ErrInvalid
	}
	cmd.Stdin = bytes.NewReader(stdin.Bytes())
	var stdout bytes.Buffer
	writers := &observeWriters{cmd: cmd, stdout: &stdout}
	cmd.Stdout, cmd.Stderr = observeStream{writers, false}, observeStream{writers, true}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("driver exchange failed")
	}
	writers.publishStarted()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if writers.overflow || waitErr != nil {
		return nil, errors.New("driver exchange failed")
	}
	reader := bytes.NewReader(stdout.Bytes())
	payload, err := driverframe.Read(reader)
	if err != nil || driverframe.RequireEOF(reader) != nil {
		return nil, errors.New("invalid driver frame")
	}
	if _, err := driverprotocol.ValidateStructuralResponse(request, payload); err != nil {
		return nil, errors.New("invalid driver response")
	}
	return payload, nil
}
