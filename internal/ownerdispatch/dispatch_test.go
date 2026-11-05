package ownerdispatch

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type recorder struct {
	*ownerdb.Manager
	snapshot ownerdb.Snapshot
	action   string
	revision uint64
	plan     uint64
	failure  error
	releases int
	reads    int
	change   vault.OwnerChange
	path     string
	value    []byte
	export   ownerdb.ExportRequest
}

func (r *recorder) Snapshot() (ownerdb.Snapshot, error) { r.reads++; return r.snapshot, nil }
func (r *recorder) record(action string, revision, plan uint64) error {
	r.action, r.revision, r.plan = action, revision, plan
	return r.failure
}
func (r *recorder) EditAt(revision uint64, _ func(*vault.Vault) error) error {
	return r.record("directory", revision, 0)
}
func (r *recorder) SubmitAt(revision uint64, change vault.OwnerChange) error {
	r.change = change
	return r.record("secret", revision, 0)
}
func (r *recorder) LinkAt(revision uint64, path string, value []byte) error {
	r.path, r.value = path, append([]byte(nil), value...)
	return r.record("link", revision, 0)
}
func (r *recorder) ExportAt(revision uint64, request ownerdb.ExportRequest) error {
	r.export = request
	return r.record("export", revision, 0)
}
func (r *recorder) InspectImportAt(revision uint64, path string, value []byte) error {
	r.path, r.value = path, append([]byte(nil), value...)
	if r.failure == nil {
		r.snapshot.Import = ownerdb.ImportStatus{Phase: ownerdb.ImportStaged, PlanID: 17}
	}
	return r.record("inspect-import", revision, 0)
}
func (r *recorder) ConfirmImportPlanAt(revision, plan uint64) error {
	return r.record("confirm-import", revision, plan)
}
func (r *recorder) ResumeImportPlanAt(revision, plan uint64) error {
	if r.failure == nil {
		r.snapshot.Import.Phase = ownerdb.ImportComplete
	}
	return r.record("resume-import", revision, plan)
}
func (r *recorder) AbortImportPlanAt(revision, plan uint64) error {
	return r.record("abort-import", revision, plan)
}
func (r *recorder) RetryDatabaseAt(revision uint64) error { return r.record("retry-db", revision, 0) }
func (r *recorder) ReconcileAt(revision uint64) error     { return r.record("reconcile", revision, 0) }
func (r *recorder) ResumeDraftAt(revision uint64) error   { return r.record("resume-draft", revision, 0) }
func (r *recorder) CancelDraftAt(revision uint64) error   { return r.record("cancel-draft", revision, 0) }
func (r *recorder) Flush(context.Context) error           { return r.record("flush", 0, 0) }
func (r *recorder) ReleaseImportPlan(plan uint64) error {
	r.releases++
	if r.snapshot.Import.PlanID != plan || r.snapshot.Import.DirectoryApplied {
		return ownerdb.ErrPending
	}
	r.snapshot.Import = ownerdb.ImportStatus{}
	return nil
}

func fixture(t *testing.T) (*Dispatcher, *recorder, *Peer, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	r := &recorder{snapshot: ownerdb.Snapshot{Status: ownerdb.Status{Database: vault.SessionStatus{Revision: 42, SavedRevision: 42}}, CipherDigest: [32]byte{1}}}
	d := &Dispatcher{manager: r, gate: make(chan struct{}, 1)}
	p, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return d, r, p, ctx
}

func TestClosedDispatcherUsesEveryPinnedManagerAPI(t *testing.T) {
	revision := uint64(42)
	commands := []ownerpacket.Command{
		{Operation: "directory", Directory: &ownerpacket.DirectoryChange{Action: "rename-server", ServerID: strings.Repeat("01", 16), Fields: [][]byte{[]byte("changed")}}},
		{Operation: "secret", Secret: &ownerpacket.SecretChange{Action: "add", Name: "token", Value: []byte("synthetic private value")}},
		{Operation: "link", Link: &ownerpacket.Link{Directory: "synthetic", Master: []byte("synthetic-master")}},
		{Operation: "export", Export: &ownerpacket.Export{Global: true, Destination: "synthetic.zip"}},
		{Operation: "inspect-import", Inspect: &ownerpacket.Inspect{Path: "synthetic.zip"}},
		{Operation: "confirm-import", Plan: 17},
		{Operation: "flush"},
	}
	for _, action := range []string{"retry-db", "reconcile", "resume-draft", "cancel-draft", "resume-import", "abort-import"} {
		c := ownerpacket.Command{Operation: "recovery", Recovery: action}
		if action == "resume-import" || action == "abort-import" {
			c.Plan = 17
		}
		commands = append(commands, c)
	}
	for _, command := range commands {
		_, r, p, ctx := fixture(t)
		r.failure = vault.ErrOwnerRevision
		wantRevision, wantAction := revision, command.Operation
		if command.Operation == "flush" {
			wantRevision = 0
		} else {
			command.Revision = &revision
		}
		if command.Operation == "recovery" {
			wantAction = command.Recovery
		}
		reply := p.Dispatch(ctx, &command)
		if command.Secret != nil && !reflect.DeepEqual(r.change, vault.OwnerChange(*command.Secret)) {
			t.Fatal("dispatch changed private secret input")
		}
		if command.Link != nil && (r.path != command.Link.Directory || string(r.value) != string(command.Link.Master)) {
			t.Fatal("dispatch changed the selected installation or private master")
		}
		if command.Inspect != nil && (r.path != command.Inspect.Path || string(r.value) != string(command.Inspect.Password)) {
			t.Fatal("dispatch changed the archive or private password")
		}
		if command.Export != nil && (!reflect.DeepEqual(r.export.Selection.Servers, command.Export.Servers) || r.export.Selection.GlobalSecrets != command.Export.Global || r.export.Destination != command.Export.Destination || r.export.PlaintextConfirmation != command.Export.Confirmation) {
			t.Fatal("dispatch changed explicit export scope or confirmation")
		}
		if reply.ErrorCode != "stale" || r.action != wantAction || r.revision != wantRevision || r.plan != command.Plan || reply.Status.Revision != 42 || reply.Status.CipherDigest != ([32]byte{1}) {
			t.Fatalf("closed dispatch lost operation, revision, plan, error or receipt for %s", wantAction)
		}
	}
}

func TestLiveHelperOwnsItsPlanAndDisconnectDropsOnlyNoEffectRAM(t *testing.T) {
	d, r, a, ctx := fixture(t)
	b, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	revision := uint64(42)
	if reply := a.Dispatch(ctx, &ownerpacket.Command{Operation: "inspect-import", Revision: &revision, Inspect: &ownerpacket.Inspect{Path: "synthetic.zip"}}); reply.ErrorCode != "" {
		t.Fatal("owner inspection failed")
	}
	b.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	before := r.snapshot
	r.action = ""
	if reply := b.Dispatch(ctx, &ownerpacket.Command{Operation: "recovery", Revision: &revision, Plan: 17, Recovery: "abort-import"}); reply.ErrorCode != "pending" || r.action != "" || !reflect.DeepEqual(r.snapshot, before) {
		t.Fatal("another helper used metadata as authority over an active plan")
	}
	if err := a.EndLease(ctx); err != nil || r.releases != 1 || r.snapshot.Import.PlanID != 0 {
		t.Fatal("departing helper leaked its no-effect RAM plan")
	}
	if err := a.EndLease(ctx); err != nil || r.releases != 1 {
		t.Fatal("lease cleanup replayed plan release")
	}
	if reply := a.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"}); reply.ErrorCode != "authentication" {
		t.Fatal("closed helper retained dispatcher access")
	}
}

func TestPartialPlanNeedsFreshSnapshotAndExplicitRecoveryAfterDisconnect(t *testing.T) {
	d, r, a, ctx := fixture(t)
	revision := uint64(42)
	a.Dispatch(ctx, &ownerpacket.Command{Operation: "inspect-import", Revision: &revision, Inspect: &ownerpacket.Inspect{Path: "synthetic.zip"}})
	r.snapshot.Import.Phase, r.snapshot.Import.DirectoryApplied = ownerdb.ImportPartial, true
	before := r.snapshot
	if err := a.EndLease(ctx); !errors.Is(err, ownerdb.ErrPending) || !reflect.DeepEqual(r.snapshot, before) {
		t.Fatal("disconnect silently discarded a partial-effect plan")
	}
	b, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	r.action = ""
	resume := ownerpacket.Command{Operation: "recovery", Revision: &revision, Plan: 17, Recovery: "resume-import"}
	if reply := b.Dispatch(ctx, &resume); reply.ErrorCode != "pending" || r.action != "" {
		t.Fatal("new helper auto-adopted a partial plan without seeing it")
	}
	b.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := b.Dispatch(ctx, &resume); reply.ErrorCode != "" || r.action != "resume-import" || r.plan != 17 {
		t.Fatal("fresh explicit recovery did not target the retained exact plan")
	}
}

func TestInvalidExpiredOrUnboundedPeerCannotReachManager(t *testing.T) {
	_, r, p, ctx := fixture(t)
	if reply := p.Dispatch(ctx, &ownerpacket.Command{Operation: "get-secret"}); reply.ErrorCode != "invalid" || r.reads != 0 {
		t.Fatal("open-ended secret getter reached the manager")
	}
	if reply := p.Dispatch(context.Background(), &ownerpacket.Command{Operation: "snapshot"}); reply.ErrorCode != "invalid" || r.reads != 0 {
		t.Fatal("unbounded dispatcher reached the manager")
	}
	p.deadline = time.Now().Add(-time.Second)
	if reply := p.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"}); reply.ErrorCode != "authentication" || r.reads != 0 {
		t.Fatal("expired lease reached the manager")
	}
}
