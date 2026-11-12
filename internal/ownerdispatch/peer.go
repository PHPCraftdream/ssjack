package ownerdispatch

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Peer is private server-side state for one authenticated packet connection.
// Creating it is not authentication; only ServePeer may expose its dispatcher.
type Peer struct {
	dispatcher           *Dispatcher
	deadline             time.Time
	closed               atomic.Bool
	seenPlan             uint64
	seenRotation         string
	seenRotationPlan     uint64
	seenRotationRevision uint64
}

func (d *Dispatcher) NewPeer(deadline time.Time) (*Peer, error) {
	now := time.Now()
	if !now.Before(deadline) || deadline.After(now.Add(ownerpacket.Lease)) {
		return nil, ownerpacket.ErrExpired
	}
	return &Peer{dispatcher: d, deadline: deadline}, nil
}

func (d *Dispatcher) lock(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ownerpacket.ErrProtocol
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ownerpacket.ErrProtocol
	}
	select {
	case d.gate <- struct{}{}:
		if ctx.Err() == nil {
			return nil
		}
		<-d.gate
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func active(s ownerdb.ImportStatus) bool {
	return s.PlanID != 0 && (s.Phase == ownerdb.ImportInspecting || s.Phase == ownerdb.ImportStaged || s.Phase == ownerdb.ImportApplying || s.Phase == ownerdb.ImportPartial)
}

func (d *Dispatcher) observe(s ownerdb.Snapshot) {
	if !active(s.Import) {
		d.owner, d.plan = nil, 0
	} else {
		if d.plan != s.Import.PlanID {
			d.owner = nil
		}
		d.plan = s.Import.PlanID
	}
}

func (p *Peer) Dispatch(ctx context.Context, command *ownerpacket.Command) ownerpacket.Reply {
	if p == nil || p.dispatcher == nil || p.closed.Load() {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, ownerpacket.ErrAuthentication)
	}
	if ctx == nil || command == nil || !command.Valid() {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, ownerpacket.ErrProtocol)
	}
	if !time.Now().Before(p.deadline) {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, ownerpacket.ErrExpired)
	}
	// Refuse unbounded callers before deriving the peer-lifetime context.
	if _, bounded := ctx.Deadline(); !bounded {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, ownerpacket.ErrProtocol)
	}
	bounded, cancel := context.WithDeadline(ctx, p.deadline)
	defer cancel()
	d := p.dispatcher
	if err := d.lock(bounded); err != nil {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, err)
	}
	defer func() { <-d.gate }()
	if p.closed.Load() {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, ownerpacket.ErrAuthentication)
	}
	before, err := d.manager.Snapshot()
	if err != nil {
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, err)
	}
	d.observe(before)
	d.observeRotation(before)
	if command.Operation == "snapshot" {
		p.seenPlan = before.Import.PlanID
		if before.Rotation != nil {
			p.seenRotation, p.seenRotationPlan, p.seenRotationRevision = before.Rotation.ID, before.Rotation.PlanID, before.Status.Database.Revision
		} else {
			p.seenRotation, p.seenRotationPlan, p.seenRotationRevision = "", 0, 0
		}
		return ownerrpc.SnapshotReply(before, nil)
	}
	rotationOrphan := activeRotation(before.Rotation) && (d.rotationOwner == nil || d.rotationOwner.closed.Load())
	if command.Operation == "rotation" {
		if active(before.Import) {
			return ownerrpc.SnapshotReply(before, ownerdb.ErrPending)
		}
		if bounded.Err() != nil {
			return ownerrpc.SnapshotReply(before, bounded.Err())
		}
		err = d.routeRotation(bounded, p, *command.Revision, command.Rotation, before, rotationOrphan)
		return d.rotationReply(err)
	}
	if activeRotation(before.Rotation) && !rotationSaveAllowed(command) {
		return ownerrpc.SnapshotReply(before, ownerdb.ErrPending)
	}
	orphan := active(before.Import) && (d.owner == nil || d.owner.closed.Load())
	if command.Operation != "flush" {
		if d.owner != nil && d.owner != p && !d.owner.closed.Load() {
			return ownerrpc.SnapshotReply(before, ownerdb.ErrPending)
		}
		if orphan && (p.seenPlan != before.Import.PlanID || (command.Operation != "confirm-import" && command.Operation != "recovery")) {
			return ownerrpc.SnapshotReply(before, ownerdb.ErrPending)
		}
	}
	if bounded.Err() != nil {
		return ownerrpc.SnapshotReply(before, bounded.Err())
	}
	err = d.route(bounded, command)
	if err == nil && (command.Operation == "inspect-import" || (orphan && command.Operation != "flush")) {
		d.owner, d.plan = p, before.Import.PlanID
	}
	after, snapshotError := d.manager.Snapshot()
	if snapshotError != nil {
		if err == nil {
			err = ownerpacket.ErrUncertain
		}
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, err)
	}
	if command.Operation == "inspect-import" && err == nil {
		d.plan = after.Import.PlanID
	}
	d.observe(after)
	return ownerrpc.SnapshotReply(after, err)
}

func (d *Dispatcher) rotationReply(err error) ownerpacket.Reply {
	snapshot, snapshotErr := d.manager.Snapshot()
	if snapshotErr != nil {
		if err == nil {
			err = ownerpacket.ErrUncertain
		}
		return ownerrpc.SnapshotReply(ownerdb.Snapshot{}, err)
	}
	d.observeRotation(snapshot)
	if d.rotationOwner != nil && d.rotationOwner.closed.Load() && snapshot.Rotation != nil && snapshot.Rotation.ID == d.rotationID && snapshot.Rotation.Phase == vault.RotationPrepared {
		d.orphanPrepared = true
	}
	return ownerrpc.SnapshotReply(snapshot, err)
}

// EndLease never drops partial-effect plans or closes the coordinator.
func (p *Peer) EndLease(ctx context.Context) error {
	if p == nil || p.dispatcher == nil {
		return ownerpacket.ErrProtocol
	}
	p.closed.Store(true)
	d := p.dispatcher
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	snapshot, err := d.manager.Snapshot()
	if err != nil {
		return err
	}
	d.observe(snapshot)
	d.observeRotation(snapshot)
	if d.rotationOwner == p {
		d.rotationOwner = nil
		if snapshot.Rotation != nil && snapshot.Rotation.ID == d.rotationID && snapshot.Rotation.Phase == vault.RotationPrepared {
			d.orphanPrepared = true
		}
	}
	if d.owner != p {
		return nil
	}
	d.owner = nil
	return d.manager.ReleaseImportPlan(d.plan)
}
