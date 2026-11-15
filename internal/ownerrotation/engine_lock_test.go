package ownerrotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// gatedRemote parks inside Add so a test can observe a held operation lock.
type gatedRemote struct {
	*memoryRemote
	entered chan struct{}
	release chan struct{}
}

func (g *gatedRemote) Add(ctx context.Context, target vault.Target, oldPublic, newPublic []byte) error {
	close(g.entered)
	<-g.release
	return g.memoryRemote.Add(ctx, target, oldPublic, newPublic)
}

func TestWaitingOperationHonorsItsContextWhileAddIsInFlight(t *testing.T) {
	// Failure-only evidence: where the Install/Inspect goroutines are parked.
	flakediag.OnFailure(t, func() string {
		return "goroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
	engine, keeper, remote := testEngine(t, nil)
	gate := &gatedRemote{memoryRemote: remote, entered: make(chan struct{}), release: make(chan struct{})}
	engine.remote = gate
	installed := make(chan error, 1)
	go func() { installed <- engine.Install(context.Background(), 8, 4, true) }()
	<-gate.entered
	revision := keeper.revision

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	waited := make(chan error, 1)
	go func() {
		_, err := engine.Inspect(ctx, revision, 4)
		waited <- err
	}()
	select {
	case err := <-waited:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("waiting Inspect error = %v, want deadline exceeded", err)
		}
	case <-time.After(5 * time.Second):
		close(gate.release)
		t.Fatal("waiting Inspect ignored its context while Add held the operation lock")
	}

	close(gate.release)
	if err := <-installed; err != nil {
		t.Fatalf("Install after a waiter gave up: %v", err)
	}
	if keeper.info.Phase != vault.RotationAdded {
		t.Fatalf("phase = %s, want %s", keeper.info.Phase, vault.RotationAdded)
	}
}

func TestZeroValueEngineIsUnavailableInsteadOfBlocking(t *testing.T) {
	if _, err := (&Engine{}).Inspect(context.Background(), 1, 1); err == nil {
		t.Fatal("zero-value engine accepted work")
	}
}
