package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
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

func ordinarySSHLiveAcceptance(t *testing.T, parent context.Context) {
	t.Helper()
	f := newOrdinaryLiveFixture(t, parent)
	human, session, reader, stdin := liveHumanShell(t, f.ctx, f.helper, f.selected)
	defer human.Close()
	defer session.Close()
	old, err := f.jobs.Start(remote.StartInput{Target: f.credentials.targets[0], Command: "synthetic-live-hold", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal("initial live SSH job was not admitted")
	}
	if identity, err := f.server.waitSyntheticHold(f.ctx); err != nil || identity != "old" {
		t.Fatal("held job did not authenticate as the original identity")
	}
	if err := liveEditAccount(f.ctx, f.helper, f.selected.ServerID, f.selected.Revision, []byte("synthetic ordinary live rejected password")); err != nil {
		t.Fatal("owner helper could not save the rejected replacement")
	}
	badRevision := f.helper.Backend().Status().Database.Revision
	probe, err := f.jobs.Start(remote.StartInput{Target: f.credentials.targets[0], Command: "synthetic-live-once", TimeoutSeconds: 30})
	if err != nil {
		t.Fatal("rejected replacement authentication probe was not admitted")
	}
	failed := liveReadJob(t, f.ctx, f.jobs, probe.JobID)
	if !failed.Done || failed.Error == "" {
		t.Fatal("fixture accepted the deliberately rejected credential")
	}
	if status := f.credentials.ssh.Status(); !status.AdoptedKnown || status.AdoptedRevision >= badRevision {
		t.Fatal("failed authentication was reported as adopted or prior authentication was not recorded")
	}
	if err := liveEditAccount(f.ctx, f.helper, f.selected.ServerID, badRevision, []byte(ordinaryLiveNewPassword)); err != nil {
		t.Fatal("owner helper could not save the valid replacement")
	}
	current := f.helper.Backend().Status().Database.Revision
	connections := f.server.acceptedConnections()
	if err := liveEditAccount(f.ctx, f.helper, f.selected.ServerID, f.selected.Revision, []byte("synthetic stale credential")); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatal("stale owner revision was not refused")
	}
	if f.server.acceptedConnections() != connections || f.helper.Backend().Status().Database.Revision != current {
		t.Fatal("stale edit changed owner state or opened an SSH connection")
	}
	fresh, err := f.jobs.Start(remote.StartInput{Target: f.credentials.targets[0], Command: "synthetic-live-once", TimeoutSeconds: 30})
	if err != nil {
		t.Fatal("new live SSH job was not admitted")
	}
	result := liveReadJob(t, f.ctx, f.jobs, fresh.JobID)
	if !result.Done || result.Error != "" || !strings.Contains(string(result.Stdout), "SYNTHETIC-LIVE:new") {
		t.Fatal("new job did not use the confirmed replacement identity")
	}
	status := f.helper.Backend().Status().Database.SSH
	if status == nil || !status.DesiredKnown || status.DesiredRevision != current || !status.DeliveredKnown || status.DeliveredRevision != current || !status.AdoptedKnown || status.AdoptedRevision != current {
		t.Fatal("authenticated owner did not report the replacement as desired, delivered, and adopted")
	}
	stillHeld, err := f.jobs.Read(remote.ReadInput{JobID: old.JobID})
	if err != nil || stillHeld.Done || !strings.Contains(string(stillHeld.Stdout), "SYNTHETIC-LIVE:old") {
		t.Fatal("pre-edit job did not retain its original live connection")
	}
	if _, err := io.WriteString(stdin, "human-after-edit\r"); err != nil {
		t.Fatal("human shell closed during credential replacement")
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "ECHO:human-after-edit") {
		t.Fatal("captured human shell did not survive the credential replacement")
	}
	f.server.releaseSyntheticHolds()
	oldResult := liveReadJob(t, f.ctx, f.jobs, old.JobID)
	if !oldResult.Done || oldResult.Error != "" || !strings.Contains(string(oldResult.Stdout), "SYNTHETIC-LIVE:old") {
		t.Fatal("held original job did not complete on its original identity")
	}
	if !f.server.hasIdentityLabel("second|old") || !f.server.hasIdentityLabel("second|new") {
		t.Fatal("fixture did not observe both original and replacement identities")
	}
}
