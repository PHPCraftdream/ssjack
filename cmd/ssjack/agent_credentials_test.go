package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

func assertGuardMasks(t *testing.T, snapshot *outputguard.Snapshot, value []byte) {
	t.Helper()
	var result bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range value {
		if _, err := writer.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || result.String() != outputguard.Marker {
		t.Fatal("startup guard did not retain the captured credential")
	}
}

func TestFixedGuardRefusesMissingSeedAndCancelledAdmission(t *testing.T) {
	if snapshot, err := fixedOutputGuard(nil)(context.Background()); snapshot != nil || err != outputguard.ErrGuard {
		t.Fatal("missing startup seed granted an unguarded capability")
	}
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic captured credential")})
	if err != nil {
		t.Fatal(err)
	}
	provider := fixedOutputGuard(snapshot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if result, err := provider(ctx); result != nil || err != outputguard.ErrGuard {
			t.Fatal("invalid context obtained a captured capability")
		}
	}
	captured, err := provider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertGuardMasks(t, captured, []byte("synthetic captured credential"))
}

type ownerCloseFunc func(context.Context) error

func (f ownerCloseFunc) Close(ctx context.Context) error { return f(ctx) }

type serviceCloseProbe struct {
	close func(context.Context) error
	done  chan struct{}
}

func (p *serviceCloseProbe) Close(ctx context.Context) error { return p.close(ctx) }
func (p *serviceCloseProbe) Done() <-chan struct{}           { return p.done }

func TestKeeperJoinsServiceBeforeClosingParentKeyAndRole(t *testing.T) {
	for _, mode := range []string{"joined", "service-error", "unjoined", "partial-service"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			private := errors.New("synthetic-private-service-diagnostic")
			service := &serviceCloseProbe{done: make(chan struct{})}
			service.close = func(ctx context.Context) error {
				events = append(events, "service-close")
				if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
					t.Fatal("service cleanup omitted independent bound")
				}
				if mode != "unjoined" {
					close(service.done)
				}
				if mode == "service-error" || mode == "unjoined" {
					return private
				}
				return nil
			}
			credentials := &agentCredentials{service: service, owner: ownerCloseFunc(func(context.Context) error {
				events = append(events, "owner-close")
				return nil
			})}
			if mode == "partial-service" {
				credentials.owner = nil
			}
			code := 0
			var result error
			finishAgentCredentials(credentials, &code, &result)
			want := []string{"service-close", "owner-close"}
			if mode == "unjoined" || mode == "partial-service" {
				want = want[:1]
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatal("parent closed before service join or partial service leaked")
			}
			if mode == "service-error" || mode == "unjoined" {
				if code != 1 || !errors.Is(result, errOwnerShutdown) || strings.Contains(result.Error(), private.Error()) {
					t.Fatal("unsafe service shutdown reported success or raw diagnostics")
				}
			} else if code != 0 || result != nil {
				t.Fatal("joined service changed a saved outcome")
			}
		})
	}
}

func TestKeeperClosesRetainedOwnerAfterHarnessAndReportsFailure(t *testing.T) {
	for _, mode := range []string{"success", "harness-error", "owner-error", "both-errors", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
			t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
			var events []string
			private := errors.New("synthetic-private-owner-diagnostic")
			harnessError := errors.New("synthetic harness failure")
			owner := ownerCloseFunc(func(closeContext context.Context) error {
				events = append(events, "owner-close")
				deadline, bounded := closeContext.Deadline()
				if closeContext.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > time.Minute {
					t.Fatal("keeper shutdown reused a cancelled context or omitted its bound")
				}
				if mode == "owner-error" || mode == "both-errors" {
					return private
				}
				return nil
			})
			cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
				events = append(events, "load")
				return &agentCredentials{owner: owner}, nil
			}
			cliLaunchRun = func(context.Context, launch.Options) (int, error) {
				events = append(events, "harness-return")
				if mode == "cancelled" {
					cancel()
					return 1, context.Canceled
				}
				if mode == "harness-error" || mode == "both-errors" {
					return 7, harnessError
				}
				return 0, nil
			}
			code, err := run(ctx, []string{"run", "synthetic-harness"})
			if !reflect.DeepEqual(events, []string{"load", "harness-return", "owner-close"}) {
				t.Fatal("keeper dropped owner lifetime before the harness stopped or failed to close it")
			}
			switch mode {
			case "owner-error", "both-errors":
				if code != 1 || !errors.Is(err, errOwnerShutdown) || strings.Contains(err.Error(), private.Error()) {
					t.Fatal("owner shutdown failure was ignored or exposed raw diagnostics")
				}
			case "harness-error":
				if code != 7 || !errors.Is(err, harnessError) {
					t.Fatal("successful owner shutdown changed the harness outcome")
				}
			case "cancelled":
				if code != 1 || !errors.Is(err, context.Canceled) {
					t.Fatal("shutdown lost the original cancellation outcome")
				}
			default:
				if code != 0 || err != nil {
					t.Fatal("saved owner shutdown changed a successful harness outcome")
				}
			}
		})
	}
}

func TestKeeperClosesAnOwnedPartialStartupButRefusesMissingCredentials(t *testing.T) {
	oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
	t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
	launched, closed := false, false
	failure := errors.New("synthetic startup refusal")
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		return &agentCredentials{owner: ownerCloseFunc(func(context.Context) error { closed = true; return nil })}, failure
	}
	cliLaunchRun = func(context.Context, launch.Options) (int, error) { launched = true; return 0, nil }
	if code, err := run(context.Background(), []string{"run", "fixture"}); code != 1 || !errors.Is(err, failure) || !closed || launched {
		t.Fatal("partially initialized owner was leaked or launched after startup failure")
	}
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) { return nil, nil }
	if code, err := run(context.Background(), []string{"run", "fixture"}); code != 1 || err == nil || launched {
		t.Fatal("missing credential session reached the harness")
	}
}
