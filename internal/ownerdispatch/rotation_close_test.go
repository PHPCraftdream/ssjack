package ownerdispatch

import (
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func prepareCommand(revision uint64, server string) *ownerpacket.Command {
	return &ownerpacket.Command{Operation: "rotation", Revision: revisionPtr(revision), Rotation: &ownerpacket.Rotation{Action: "prepare", ServerID: strings.Repeat(server, 16), Account: "deploy"}}
}

func TestAbandonRequiresAnAttemptedAddAndAnExplicitClaim(t *testing.T) {
	d, r, first, ctx := rotationFixture(t)
	if reply := first.Dispatch(ctx, prepareCommand(42, "02")); reply.ErrorCode != "" {
		t.Fatal("rotation prepare failed")
	}
	id, plan := r.snapshot.Rotation.ID, r.snapshot.Rotation.PlanID
	revision := func() uint64 { return r.snapshot.Status.Database.Revision }
	count := len(r.rotationCalls)
	if reply := first.Dispatch(ctx, rotationCommand(revision(), "abandon", id, plan)); reply.ErrorCode != "pending" || len(r.rotationCalls) != count {
		t.Fatal("prepared no-effect plan was abandoned; it must be cancelled")
	}
	if reply := first.Dispatch(ctx, rotationCommand(revision(), "install", id, plan)); reply.ErrorCode != "" || r.snapshot.Rotation.Phase != vault.RotationUnknown {
		t.Fatal("install did not reach the unknown outcome")
	}
	count = len(r.rotationCalls)
	second, _ := d.NewPeer(time.Now().Add(time.Minute))
	second.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := second.Dispatch(ctx, rotationCommand(revision(), "abandon", id, plan)); reply.ErrorCode != "pending" || len(r.rotationCalls) != count {
		t.Fatal("another peer abandoned a rotation whose owner is alive")
	}
	if err := first.EndLease(ctx); err != nil {
		t.Fatal(err)
	}
	third, _ := d.NewPeer(time.Now().Add(time.Minute))
	third.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := third.Dispatch(ctx, rotationCommand(revision(), "abandon", id, plan)); reply.ErrorCode != "pending" || len(r.rotationCalls) != count {
		t.Fatal("orphan rotation was abandoned without an explicit recovery claim")
	}
	if reply := third.Dispatch(ctx, rotationCommand(revision(), "recover", id, plan)); reply.ErrorCode != "" {
		t.Fatal("explicit recovery claim failed")
	}
	if reply := third.Dispatch(ctx, rotationCommand(revision(), "abandon", id, plan+1)); reply.ErrorCode != "stale" {
		t.Fatal("abandon accepted a wrong plan identity")
	}
	if reply := third.Dispatch(ctx, rotationCommand(revision(), "abandon", id, plan)); reply.ErrorCode != "" || reply.Rotation == nil || reply.Rotation.Phase != vault.RotationCancelled {
		t.Fatal("claimed stuck rotation could not be abandoned")
	}
	if reply := third.Dispatch(ctx, rotationCommand(revision(), "verify", id, plan)); reply.ErrorCode == "" {
		t.Fatal("abandoned rotation admitted verification")
	}
	if reply := third.Dispatch(ctx, prepareCommand(revision(), "03")); reply.ErrorCode != "" || r.snapshot.Rotation.ID == id || r.snapshot.Rotation.PlanID <= plan {
		t.Fatal("abandoned journal did not admit a distinct later plan")
	}
}

func TestRetireRequiresTheExactCompletedRotationAndKeepsTheRevision(t *testing.T) {
	d, r, owner, ctx := rotationFixture(t)
	if reply := owner.Dispatch(ctx, prepareCommand(42, "02")); reply.ErrorCode != "" {
		t.Fatal("rotation prepare failed")
	}
	info := r.snapshot.Rotation
	id, plan := info.ID, info.PlanID
	revision := func() uint64 { return r.snapshot.Status.Database.Revision }
	fresh, _ := d.NewPeer(time.Now().Add(time.Minute))
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	for _, phase := range []string{vault.RotationPrepared, vault.RotationUnknown, vault.RotationAdded, vault.RotationVerified} {
		info.Phase = phase
		if reply := fresh.Dispatch(ctx, rotationCommand(revision(), "retire", id, plan)); reply.ErrorCode != "pending" || r.retires != 0 {
			t.Fatalf("retire accepted an uncompleted %s rotation", phase)
		}
	}
	info.Phase, info.CommitDigest = vault.RotationComplete, strings.Repeat("a", 64)
	r.snapshot.Status.Database.Revision++
	r.snapshot.Status.Database.SavedRevision = revision()
	if reply := fresh.Dispatch(ctx, rotationCommand(revision(), "retire", id, plan)); reply.ErrorCode != "pending" || r.retires != 0 {
		t.Fatal("retire accepted a completion absent from its fresh snapshot")
	}
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, rotationCommand(revision(), "retire", id, plan+1)); reply.ErrorCode != "stale" || r.retires != 0 {
		t.Fatal("retire accepted a wrong plan identity")
	}
	if reply := fresh.Dispatch(ctx, rotationCommand(revision()-1, "retire", id, plan)); reply.ErrorCode != "stale" || r.retires != 0 {
		t.Fatal("retire accepted a stale revision")
	}
	before := revision()
	for attempt := 1; attempt <= 2; attempt++ {
		reply := fresh.Dispatch(ctx, rotationCommand(revision(), "retire", id, plan))
		if reply.ErrorCode != "" || reply.Rotation == nil || reply.Rotation.Phase != vault.RotationComplete || reply.Rotation.ID != id || r.retires != attempt {
			t.Fatalf("retire attempt %d was not admitted for the exact completed rotation", attempt)
		}
		if revision() != before {
			t.Fatal("retire changed the saved revision")
		}
	}
	if reply := fresh.Dispatch(ctx, rotationCommand(revision(), "archive", id, plan)); reply.ErrorCode != "" || r.archives != 1 {
		t.Fatal("retirement prevented the later archive")
	}
	fresh.Dispatch(ctx, &ownerpacket.Command{Operation: "snapshot"})
	if reply := fresh.Dispatch(ctx, rotationCommand(revision(), "retire", id, plan)); reply.ErrorCode != "pending" || r.retires != 2 {
		t.Fatal("retire accepted an archived rotation")
	}
}
