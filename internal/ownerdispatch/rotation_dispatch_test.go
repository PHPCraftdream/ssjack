package ownerdispatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type rotationRecorder struct {
	*recorder
	rotationCalls []string
	archives      int
	prepares      int
}
type rotationlessManager struct{ manager }

func (r *rotationRecorder) PrepareRotation(_ context.Context, revision uint64, serverID, account string) (ownerrotation.Plan, error) {
	if revision != r.snapshot.Status.Database.Revision {
		return ownerrotation.Plan{}, vault.ErrOwnerRevision
	}
	r.prepares++
	info := vault.RotationInfo{ID: fmt.Sprintf("%032x", r.prepares), PlanID: uint64(4 + r.prepares), BaseRevision: revision, Phase: vault.RotationPrepared, ServerID: serverID, Account: account, Profile: "profile", Address: "host.invalid:22", User: "deploy", Usage: "human", OldPublic: []byte("old-public"), NewPublic: []byte("new-public")}
	r.snapshot.Rotation = &info
	r.snapshot.Status.Database.Revision++
	r.snapshot.Status.Database.SavedRevision = r.snapshot.Status.Database.Revision
	r.rotationCalls = append(r.rotationCalls, "prepare")
	return ownerrotation.Plan{Info: info, Revision: r.snapshot.Status.Database.Revision, Digest: [32]byte{1}}, nil
}

func (r *rotationRecorder) DecideRotation(_ context.Context, revision, planID uint64, id, action string) (ownerrotation.Plan, error) {
	info := r.snapshot.Rotation
	if revision != r.snapshot.Status.Database.Revision || info == nil || info.PlanID != planID || info.ID != id {
		return ownerrotation.Plan{}, vault.ErrOwnerRevision
	}
	if action == "recover" {
		r.rotationCalls = append(r.rotationCalls, action)
		return ownerrotation.Plan{Info: *info, Revision: revision, Digest: [32]byte{1}}, nil
	}
	r.rotationCalls = append(r.rotationCalls, action)
	switch action {
	case "install":
		if info.Phase != vault.RotationPrepared {
			return ownerrotation.Plan{}, errors.New("replay refused")
		}
		info.Phase = vault.RotationUnknown
	case "verify":
		if info.Phase != vault.RotationUnknown && info.Phase != vault.RotationAdded && info.Phase != vault.RotationAttempting {
			return ownerrotation.Plan{}, errors.New("verify refused")
		}
		info.Phase = vault.RotationVerified
	case "commit":
		if info.Phase != vault.RotationVerified {
			return ownerrotation.Plan{}, errors.New("commit refused")
		}
		info.Phase, info.CommitDigest = vault.RotationComplete, strings.Repeat("a", 64)
	case "cancel":
		if info.Phase != vault.RotationPrepared {
			return ownerrotation.Plan{}, errors.New("cancel refused")
		}
		info.Phase, info.OldPublic, info.NewPublic = vault.RotationCancelled, nil, nil
	case "archive":
		if info.Phase != vault.RotationComplete {
			return ownerrotation.Plan{}, errors.New("archive refused")
		}
		info.Phase, info.RecoveryPath, info.RecoveryDigest = vault.RotationArchived, "rotation-backup.ktav", strings.Repeat("b", 64)
		info.Address, info.User, info.Usage = "", "", ""
		info.OldPublic, info.NewPublic, info.HostKeys = nil, nil, nil
		r.archives++
	default:
		return ownerrotation.Plan{}, ownerpacket.ErrProtocol
	}
	r.snapshot.Status.Database.Revision++
	r.snapshot.Status.Database.SavedRevision = r.snapshot.Status.Database.Revision
	return ownerrotation.Plan{Info: *info, Revision: r.snapshot.Status.Database.Revision, Digest: [32]byte{1}}, nil
}

func rotationFixture(t *testing.T) (*Dispatcher, *rotationRecorder, *Peer, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	base := &recorder{snapshot: ownerdb.Snapshot{Status: ownerdb.Status{Database: vault.SessionStatus{Revision: 42, SavedRevision: 42}}, CipherDigest: [32]byte{1}}}
	manager := &rotationRecorder{recorder: base}
	d := &Dispatcher{manager: manager, gate: make(chan struct{}, 1)}
	peer, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return d, manager, peer, ctx
}

func rotationCommand(revision uint64, action, id string, plan uint64) *ownerpacket.Command {
	return &ownerpacket.Command{Operation: "rotation", Revision: &revision, Rotation: &ownerpacket.Rotation{Action: action, ID: id, PlanID: plan}}
}

func TestRotationAdmissionIdentityNoReplayAndRecovery(t *testing.T) {
	d, r, first, ctx := rotationFixture(t)
	prepare := ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(42), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat("02", 16), Account: "deploy"}}
	if reply := first.Dispatch(ctx, &prepare); reply.ErrorCode != "" || reply.Rotation == nil || reply.Rotation.Phase != vault.RotationPrepared {
		t.Fatal("prepare receipt missing")
	}
	id, plan := r.snapshot.Rotation.ID, r.snapshot.Rotation.PlanID
	if reply := first.Dispatch(ctx, rotationCommand(42, "install", id, plan)); reply.ErrorCode != "stale" || len(r.rotationCalls) != 1 {
		t.Fatal("stale revision reached rotation manager")
	}
	if reply := first.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "install", strings.Repeat("03", 16), plan)); reply.ErrorCode != "stale" || len(r.rotationCalls) != 1 {
		t.Fatal("conflicting journal ID reached manager")
	}
	if reply := first.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "install", id, plan)); reply.ErrorCode != "" {
		t.Fatal("owner could not install prepared plan")
	}
	count := len(r.rotationCalls)
	if reply := first.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "install", id, plan)); reply.ErrorCode == "" || len(r.rotationCalls) != count {
		t.Fatal("effectful install replayed")
	}
	if err := first.EndLease(ctx); err != nil {
		t.Fatal(err)
	}
	second, _ := d.NewPeer(time.Now().Add(time.Minute))
	if reply := second.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"}); reply.Rotation == nil || reply.Rotation.ID != id {
		t.Fatal("orphan metadata unavailable")
	}
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "recover", id, plan)); reply.ErrorCode != "" {
		t.Fatal("explicit recovery failed")
	}
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "verify", id, plan)); reply.ErrorCode != "" {
		t.Fatal("verify recovery failed")
	}
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "commit", id, plan)); reply.ErrorCode != "" {
		t.Fatal("verified commit failed")
	}
}

func TestPreparedOrphanCanCancelButCannotInstall(t *testing.T) {
	d, r, first, ctx := rotationFixture(t)
	prepare := ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(42), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat("02", 16), Account: "deploy"}}
	first.Dispatch(ctx, &prepare)
	id, plan := r.snapshot.Rotation.ID, r.snapshot.Rotation.PlanID
	second, _ := d.NewPeer(time.Now().Add(time.Minute))
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "install", id, plan)); reply.ErrorCode != "pending" {
		t.Fatal("different live peer took over")
	}
	if err := first.EndLease(ctx); err != nil {
		t.Fatal(err)
	}
	second, _ = d.NewPeer(time.Now().Add(time.Minute))
	second.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "recover", id, plan)); reply.ErrorCode != "" {
		t.Fatal("prepared orphan inspection failed")
	}
	count := len(r.rotationCalls)
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "install", id, plan)); reply.ErrorCode != "pending" || len(r.rotationCalls) != count {
		t.Fatal("orphan prepared plan installed")
	}
	if reply := second.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "cancel", id, plan)); reply.ErrorCode != "" || reply.Rotation == nil || reply.Rotation.Phase != vault.RotationCancelled {
		t.Fatal("orphan cancellation receipt missing")
	}
}

func TestMissingRotationCapabilityFailsClosed(t *testing.T) {
	_, r, peer, ctx := rotationFixture(t)
	r.snapshot.Rotation = &vault.RotationInfo{ID: strings.Repeat("01", 16), PlanID: 5, Phase: vault.RotationComplete, ServerID: strings.Repeat("02", 16), Account: "deploy", Profile: "profile", CommitDigest: strings.Repeat("a", 64), OldPublic: []byte("old"), NewPublic: []byte("new")}
	r.rotationCalls = append(r.rotationCalls, "fixture")
	peer.dispatcher.manager = &rotationlessManager{manager: r}
	peer.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	command := rotationCommand(42, "archive", r.snapshot.Rotation.ID, r.snapshot.Rotation.PlanID)
	if reply := peer.Dispatch(ctx, command); reply.ErrorCode != "invalid" || len(r.rotationCalls) != 1 {
		t.Fatal("missing archive capability failed open")
	}
}

func TestImportAndRotationOwnershipExcludeBothDirections(t *testing.T) {
	d, r, owner, ctx := rotationFixture(t)
	peer, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	r.snapshot.Import = ownerdb.ImportStatus{PlanID: 17, Phase: ownerdb.ImportStaged}
	d.observe(r.snapshot)
	prepare := &ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(42), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat("02", 16), Account: "deploy"}}
	if reply := owner.Dispatch(ctx, prepare); reply.ErrorCode != "pending" || len(r.rotationCalls) != 0 {
		t.Fatal("rotation reached manager with staged import active")
	}
	if reply := peer.Dispatch(ctx, &ownerpacket.Command{Operation: "confirm-import", Revision: revisionPtr(42), Plan: 17}); reply.ErrorCode != "pending" || r.action != "" {
		t.Fatal("non-owner confirmed another peer's staged import")
	}
	d.owner, d.plan = nil, 0
	if reply := owner.Dispatch(ctx, prepare); reply.ErrorCode != "pending" || len(r.rotationCalls) != 0 {
		t.Fatal("fresh peer used staged import metadata to authorize rotation")
	}

	r.snapshot.Import = ownerdb.ImportStatus{}
	d.observe(r.snapshot)
	if reply := owner.Dispatch(ctx, prepare); reply.ErrorCode != "" || len(r.rotationCalls) != 1 {
		t.Fatal("rotation setup failed after import ownership ended")
	}
	id, plan := r.snapshot.Rotation.ID, r.snapshot.Rotation.PlanID
	beforeCalls := len(r.rotationCalls)
	if reply := peer.Dispatch(ctx, &ownerpacket.Command{Operation: "inspect-import", Revision: revisionPtr(r.snapshot.Status.Database.Revision), Inspect: &ownerpacket.Inspect{Path: "archive.zip"}}); reply.ErrorCode != "pending" || len(r.rotationCalls) != beforeCalls {
		t.Fatal("import inspection crossed a live rotation")
	}
	if reply := owner.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "install", id, plan)); reply.ErrorCode != "" {
		t.Fatal("rotation owner could not continue its active plan")
	}
	calls := len(r.rotationCalls)
	if reply := owner.Dispatch(ctx, &ownerpacket.Command{Operation: "flush"}); reply.ErrorCode != "" || r.action != "flush" || len(r.rotationCalls) != calls {
		t.Fatal("flush was not kept as persistence-only authority")
	}
}
func TestOrphanRotationRequiresSnapshotAndRetryDoesNotGrantWrites(t *testing.T) {
	d, r, first, ctx := rotationFixture(t)
	prepare := &ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(42), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat("02", 16), Account: "deploy"}}
	if reply := first.Dispatch(ctx, prepare); reply.ErrorCode != "" {
		t.Fatal("rotation prepare failed")
	}
	id, plan := r.snapshot.Rotation.ID, r.snapshot.Rotation.PlanID
	if err := first.EndLease(ctx); err != nil {
		t.Fatal(err)
	}
	fresh, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	revision := r.snapshot.Status.Database.Revision
	if reply := fresh.Dispatch(ctx, rotationCommand(revision, "recover", id, plan)); reply.ErrorCode != "pending" || len(r.rotationCalls) != 1 {
		t.Fatal("orphan rotation recovered without fresh snapshot")
	}
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "inspect-import", Revision: revisionPtr(revision), Inspect: &ownerpacket.Inspect{Path: "archive.zip"}}); reply.ErrorCode != "pending" || len(r.rotationCalls) != 1 {
		t.Fatal("snapshot metadata granted a new import mutation")
	}
	if reply := fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "recovery", Revision: revisionPtr(revision), Recovery: "retry-db"}); reply.ErrorCode != "" || r.action != "retry-db" {
		t.Fatal("explicit local database retry was blocked during rotation")
	}
	if reply := fresh.Dispatch(ctx, rotationCommand(revision, "recover", id, plan)); reply.ErrorCode != "" || len(r.rotationCalls) != 2 {
		t.Fatal("fresh explicit recovery failed after local persistence retry")
	}
}
func TestCompletedRotationArchiveRequiresFreshExactSnapshot(t *testing.T) {
	d, r, owner, ctx := rotationFixture(t)
	prepare := &ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(42), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat("02", 16), Account: "deploy"}}
	if reply := owner.Dispatch(ctx, prepare); reply.ErrorCode != "" {
		t.Fatal("rotation prepare failed")
	}
	info := r.snapshot.Rotation
	id, plan := info.ID, info.PlanID
	fresh, err := d.NewPeer(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "pending" || r.archives != 0 {
		t.Fatal("archive used another peer's snapshot")
	}
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan+1)); reply.ErrorCode != "stale" || r.archives != 0 {
		t.Fatal("archive accepted a wrong plan identity")
	}
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision-1, "archive", id, plan)); reply.ErrorCode != "stale" || r.archives != 0 {
		t.Fatal("archive accepted a stale plan revision")
	}
	info.Phase = vault.RotationUnknown
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "pending" || r.archives != 0 {
		t.Fatal("archive accepted an unknown plan")
	}
	info.Phase = vault.RotationPrepared
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "pending" || r.archives != 0 {
		t.Fatal("archive accepted an uncompleted plan")
	}
	info.Phase, info.CommitDigest = vault.RotationComplete, strings.Repeat("a", 64)
	r.snapshot.Status.Database.Revision++
	r.snapshot.Status.Database.SavedRevision = r.snapshot.Status.Database.Revision
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "pending" || r.archives != 0 {
		t.Fatal("archive accepted a completion absent from its fresh snapshot")
	}
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	r.snapshot.Import = ownerdb.ImportStatus{PlanID: 17, Phase: ownerdb.ImportStaged}
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "pending" || r.archives != 0 {
		t.Fatal("archive crossed an active staged import")
	}
	r.snapshot.Import = ownerdb.ImportStatus{}
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "" || reply.Rotation == nil || reply.Rotation.Phase != vault.RotationArchived || reply.Rotation.ID != id || reply.Rotation.ServerID != info.ServerID || reply.Rotation.Account != info.Account || reply.Rotation.Profile != info.Profile || reply.Rotation.RecoveryPath == "" || reply.Rotation.RecoveryDigest == "" || reply.Rotation.Address != "" || reply.Rotation.User != "" || reply.Rotation.Usage != "" || len(reply.Rotation.OldPublic)+len(reply.Rotation.NewPublic)+len(reply.Rotation.HostKeys) != 0 || r.archives != 1 {
		t.Fatal("exact completed rotation archive receipt missing")
	}
	if reply := fresh.Dispatch(ctx, rotationCommand(r.snapshot.Status.Database.Revision, "archive", id, plan)); reply.ErrorCode != "stale" || r.archives != 1 {
		t.Fatal("duplicate archive was not rejected as stale")
	}
	if reply := fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(r.snapshot.Status.Database.Revision), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat("03", 16), Account: "deploy"}}); reply.ErrorCode != "" || r.snapshot.Rotation.ID == id || r.snapshot.Rotation.PlanID <= plan {
		t.Fatal("archived journal did not admit a distinct monotonic plan")
	}
}
