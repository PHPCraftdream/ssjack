package remote

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSSHSetupErrorsPreserveContextCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sshStageError(ctx, "server refused the SSH shell"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled setup lost its cause: %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	if err := sshStageError(expired, "SSH authentication failed"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired setup lost its cause: %v", err)
	}
	const message = "server refused the interactive SSH terminal"
	if err := sshStageError(context.Background(), message); err == nil || err.Error() != message {
		t.Fatalf("non-cancelled setup changed its diagnostic: %v", err)
	}
}
