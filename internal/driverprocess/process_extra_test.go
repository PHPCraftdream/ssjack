package driverprocess

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
)

func TestOverflowKillsAndReapsOwnedChild(t *testing.T) {
	cap := &commandCapability{cmd: testCommandEnvironment(exec.Command(os.Args[0], "-test.run=TestProcessHelper", "--", "fixed-test-token", "overflow-block"))}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := execute(ctx, cap, []byte(requestJSON))
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("overflow result=%+v err=%v", got, err)
	}
	if ctx.Err() != nil {
		t.Fatalf("overflow termination relied on deadline: %v", ctx.Err())
	}
	if cap.cmd.Process == nil || cap.cmd.ProcessState == nil || cap.cmd.ProcessState.Pid() != cap.cmd.Process.Pid {
		t.Fatalf("owned child not independently waited/reaped: process=%v state=%+v", cap.cmd.Process, cap.cmd.ProcessState)
	}
}

func TestReadyFailureJoinsAndReapsOwnedChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cap := newReadyCapability()
	ready, done := startReadyExecution(ctx, cap)
	joined := false
	t.Cleanup(func() { joinReadyExecution(t, cancel, done, &joined) })
	pid, err := awaitReady(ready)
	if err != nil {
		t.Fatal(err)
	}
	// Force the readiness failure path using an already-closed channel.
	failedReadiness := make(chan int)
	close(failedReadiness)
	if _, err := awaitReady(failedReadiness); err == nil {
		t.Fatal("closed readiness channel unexpectedly succeeded")
	}
	joinReadyExecution(t, cancel, done, &joined)
	if !joined {
		t.Fatal("cleanup did not join execution")
	}
	assertReapedPID(t, cap, pid)
}
func TestFramingFailureCauses(t *testing.T) {
	cases := []struct {
		mode string
		want error
	}{{"zero-length", driverframe.ErrLength}, {"trailing-byte", driverframe.ErrTrailing}, {"invalid-json", driverprotocol.ErrInvalid}, {"wrong-correlation", driverprotocol.ErrInvalid}}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			got, err := launch(ctx, tc.mode, []byte(requestJSON))
			if !errors.Is(err, ErrSemantic) || !errors.Is(got.SemanticErr, tc.want) {
				t.Fatalf("error=%v semantic=%v, want %v", err, got.SemanticErr, tc.want)
			}
		})
	}
}

func TestProcessExitCodeSeven(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := launch(ctx, "fail", []byte(requestJSON))
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || got.ExitErr == nil {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestOverflowRetainsExactPrefix(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		response bool
	}{{"overflow", true}, {"stderr", false}} {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			got, err := launch(ctx, tc.mode, []byte(requestJSON))
			if !errors.Is(err, ErrOutputLimit) {
				t.Fatal(err)
			}
			b := got.Stderr
			if tc.response {
				b = got.Response
			}
			if len(b) != MaxOutput || !bytes.Equal(b, make([]byte, MaxOutput)) {
				t.Fatalf("retained %d bytes", len(b))
			}
		})
	}
}

func TestMaximumValidResponseFrame(t *testing.T) {
	request := bytes.Replace([]byte(requestJSON), []byte(`"max_response_bytes":1024`), []byte(`"max_response_bytes":65536`), 1)
	payload := []byte(responseJSON)
	payload = append(payload, bytes.Repeat([]byte(" "), driverframe.MaxPayload-len(payload))...)
	if len(payload) != driverframe.MaxPayload {
		t.Fatal(len(payload))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := launch(ctx, "maximum", request)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Response) != driverframe.MaxPayload+4 {
		t.Fatalf("frame length %d", len(got.Response))
	}
}

func TestDeadlineKillsReadyChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	cap := newReadyCapability()
	ready, done := startReadyExecution(ctx, cap)
	joined := false
	t.Cleanup(func() { joinReadyExecution(t, cancel, done, &joined) })
	pid, err := awaitReady(ready)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("deadline result: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("execute did not finish after deadline")
	}
	assertReapedPID(t, cap, pid)
}

func TestCancellationKillsOwnedChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cap := newReadyCapability()
	ready, done := startReadyExecution(ctx, cap)
	joined := false
	t.Cleanup(func() { joinReadyExecution(t, cancel, done, &joined) })
	pid, err := awaitReady(ready)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("execute did not finish after cancellation")
	}
	assertReapedPID(t, cap, pid)
}

func startReadyExecution(ctx context.Context, cap *readyCapability) (<-chan int, chan error) {
	done := make(chan error, 1)
	go func() { _, err := execute(ctx, cap, []byte(requestJSON)); done <- err }()
	return cap.ready, done
}

func awaitReady(ready <-chan int) (int, error) {
	select {
	case pid, ok := <-ready:
		if !ok {
			return 0, errors.New("readiness channel closed")
		}
		return pid, nil
	case <-time.After(4 * time.Second):
		return 0, errors.New("child did not become ready")
	}
}

func joinReadyExecution(t *testing.T, cancel context.CancelFunc, done <-chan error, joined *bool) {
	t.Helper()
	cancel()
	if *joined {
		return
	}
	select {
	case <-done:
		*joined = true
	case <-time.After(4 * time.Second):
		t.Error("execute lifecycle did not join after cancellation; child state unavailable")
	}
}

type readyCapability struct {
	cmd   *exec.Cmd
	ready chan int
	line  []byte
}

func newReadyCapability() *readyCapability {
	cap := &readyCapability{ready: make(chan int, 1)}
	cap.cmd = testCommandEnvironment(exec.Command(os.Args[0], "-test.run=TestProcessHelper", "--", "fixed-test-token", "ready"))
	return cap
}

func (c *readyCapability) command(context.Context) *exec.Cmd { return c.cmd }

func (c *readyCapability) observeStderr(p []byte) {
	for _, b := range p {
		if b == '\n' {
			pid, err := strconv.Atoi(strings.TrimSpace(string(c.line)))
			if err == nil {
				select {
				case c.ready <- pid:
				default:
				}
			}
			c.line = c.line[:0]
		} else if len(c.line) < 32 {
			c.line = append(c.line, b)
		}
	}
}

func assertReapedPID(t *testing.T, cap *readyCapability, pid int) {
	t.Helper()
	if cap.cmd.Process == nil || cap.cmd.Process.Pid != pid || cap.cmd.ProcessState == nil || cap.cmd.ProcessState.Pid() != pid {
		t.Fatalf("child was not waited: ready pid=%d process=%v state=%+v", pid, cap.cmd.Process, cap.cmd.ProcessState)
	}
}

type commandCapability struct{ cmd *exec.Cmd }

func (c commandCapability) command(context.Context) *exec.Cmd { return c.cmd }
