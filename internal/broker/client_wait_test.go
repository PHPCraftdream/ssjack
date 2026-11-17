package broker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/jobwait"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type waitEcho struct {
	Value string `json:"value"`
}

// waitFixture is a keeper whose "slow" operation blocks until released.
type waitFixture struct {
	keeper  *Server
	client  *Client
	entered chan struct{}
	release func()
}

func newWaitFixture(t *testing.T, ctx context.Context) *waitFixture {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("3", 64), Token: strings.Repeat("4", 64)}
	entered := make(chan struct{}, 4)
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
		switch req.Operation {
		case "slow":
			entered <- struct{}{}
			<-gate
		case "fail":
			return wire.Reply{Error: "refused by the keeper"}
		}
		return wire.Reply{OK: true, Data: req.Data}
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		keeper.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		release()
		client.Close()
		keeper.Close()
	})
	return &waitFixture{keeper: keeper, client: client, entered: entered, release: release}
}

func (f *waitFixture) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the keeper did not receive the request")
	}
}

func TestWaitCallBudgetCoversTheLongestWait(t *testing.T) {
	if waitCallBudget < (jobwait.MaxSeconds+5)*time.Second {
		t.Fatalf("waitCallBudget %v leaves less than 5 s past the longest wait", waitCallBudget)
	}
}

func TestCallWaitRoundTripAndKeeperError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newWaitFixture(t, ctx)
	f.release()
	var out waitEcho
	if err := f.client.CallWait(ctx, "slow", waitEcho{Value: "a"}, &out); err != nil || out.Value != "a" {
		t.Fatalf("CallWait = %+v, %v", out, err)
	}
	err := f.client.CallWait(ctx, "fail", waitEcho{Value: "b"}, &out)
	if err == nil || err.Error() != "refused by the keeper" {
		t.Fatalf("keeper error = %v", err)
	}
	// A keeper error does not end the session.
	if err := f.client.Call(ctx, "echo", waitEcho{Value: "c"}, &out); err != nil || out.Value != "c" {
		t.Fatalf("Call after CallWait = %+v, %v", out, err)
	}
}

func TestCallWaitCancelledContextSendsNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newWaitFixture(t, ctx)
	done, stop := context.WithCancel(ctx)
	stop()
	if err := f.client.CallWait(done, "slow", waitEcho{Value: "a"}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("CallWait with an ended context = %v", err)
	}
	select {
	case <-f.entered:
		t.Fatal("a call with an ended context reached the keeper")
	default:
	}
	var out waitEcho
	if err := f.client.Call(ctx, "echo", waitEcho{Value: "c"}, &out); err != nil || out.Value != "c" {
		t.Fatalf("Call after the refused CallWait = %+v, %v", out, err)
	}
}

func TestCallWaitContextEndKeepsTheSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newWaitFixture(t, ctx)
	callCtx, endCall := context.WithCancel(ctx)
	defer endCall()
	result := make(chan error, 1)
	go func() { result <- f.client.CallWait(callCtx, "slow", waitEcho{Value: "a"}, nil) }()
	f.awaitEntered(t)
	endCall()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("abandoned CallWait = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an abandoned CallWait did not return while the keeper still waited")
	}
	// The next call queues behind the reply still owed, then succeeds.
	next := make(chan error, 1)
	var out waitEcho
	go func() { next <- f.client.Call(ctx, "echo", waitEcho{Value: "b"}, &out) }()
	f.release()
	select {
	case err := <-next:
		if err != nil || out.Value != "b" {
			t.Fatalf("Call after an abandoned CallWait = %+v, %v", out, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not recover after an abandoned CallWait")
	}
	select {
	case <-f.keeper.Done():
		t.Fatal("an abandoned CallWait ended the keeper session")
	default:
	}
}
