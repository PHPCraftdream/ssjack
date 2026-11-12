package ownercontrol

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
)

// RotationSnapshot projects the retained local or authenticated keeper snapshot.
func (c *Control) RotationSnapshot(ctx context.Context) (ownerdb.Snapshot, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ownerdb.Snapshot{}, ErrControl
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ownerdb.Snapshot{}, ErrControl
	}
	if c.manager != nil {
		return c.manager.Snapshot()
	}
	if c.client == nil || c.unlock == nil {
		return ownerdb.Snapshot{}, ErrControl
	}
	return c.client.Execute(bounded, ownerpacket.Command{Operation: "snapshot"})
}

// PrepareRotation uses the existing coordinator; attached helpers send only
// the closed metadata request through authenticated owner RPC.
func (c *Control) PrepareRotation(ctx context.Context, revision uint64, serverID, account string) (ownerrotation.Plan, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ownerrotation.Plan{}, ErrControl
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ownerrotation.Plan{}, ErrControl
	}
	if c.manager != nil {
		return c.manager.PrepareRotation(bounded, revision, serverID, account)
	}
	if len(serverID) != 32 || len(account) == 0 || len(account) > 64 {
		return ownerrotation.Plan{}, errors.New("invalid rotation selection")
	}
	request := ownerpacket.Rotation{Action: "prepare", ServerID: serverID, Account: account}
	return c.remoteRotation(bounded, revision, request)
}

// DecideRotation submits one operation/revision/PlanID-bound transition.
func (c *Control) DecideRotation(ctx context.Context, revision, planID uint64, id, action string) (ownerrotation.Plan, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ownerrotation.Plan{}, ErrControl
	}
	switch action {
	case "install", "verify", "commit", "cancel", "recover", "archive":
	default:
		return ownerrotation.Plan{}, errors.New("unsupported rotation action")
	}
	if len(id) != 32 || planID == 0 {
		return ownerrotation.Plan{}, errors.New("invalid rotation identity")
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ownerrotation.Plan{}, ErrControl
	}
	if c.manager != nil {
		if action != "archive" {
			return c.manager.DecideRotation(bounded, revision, planID, id, action)
		}
		before, err := c.manager.Snapshot()
		if err != nil || !archiveSource(before, revision, planID, id) {
			return ownerrotation.Plan{}, errors.New("archive requires the exact healthy completed rotation")
		}
		plan, err := c.manager.DecideRotation(bounded, revision, planID, id, action)
		if err != nil {
			return ownerrotation.Plan{}, err
		}
		if !archiveReceipt(before, plan) {
			return ownerrotation.Plan{}, errors.New("archive receipt lacks healthy durable archived metadata")
		}
		return plan, nil
	}
	var before ownerdb.Snapshot
	if action == "archive" {
		var err error
		before, err = c.client.Execute(bounded, ownerpacket.Command{Operation: "snapshot"})
		if err != nil || !archiveSource(before, revision, planID, id) {
			return ownerrotation.Plan{}, errors.New("archive requires the exact healthy completed rotation")
		}
	}
	request := ownerpacket.Rotation{Action: action, ID: id, PlanID: planID}
	plan, err := c.remoteRotation(bounded, revision, request)
	if err != nil {
		return ownerrotation.Plan{}, err
	}
	if action == "archive" && !archiveReceipt(before, plan) {
		return ownerrotation.Plan{}, errors.New("archive receipt lacks healthy durable archived metadata")
	}
	return plan, nil
}

func archiveSource(snapshot ownerdb.Snapshot, revision, planID uint64, id string) bool {
	info := snapshot.Rotation
	return info != nil && info.ID == id && info.PlanID == planID && info.Phase == "complete" && info.ServerID != "" && info.Account != "" && info.Profile != "" && validArchiveDigest(info.CommitDigest) && snapshot.Status.Err == nil && !snapshot.Status.Busy && !snapshot.Status.Pending && snapshot.Status.Database.Err == nil && !snapshot.Status.Database.Pending && snapshot.Status.Database.Revision == revision && snapshot.Status.Database.SavedRevision == revision && snapshot.CipherDigest != ([32]byte{})
}

func archiveReceipt(before ownerdb.Snapshot, plan ownerrotation.Plan) bool {
	prior := before.Rotation
	next := plan.Info
	return prior != nil && next.ID == prior.ID && next.PlanID == prior.PlanID && next.Phase == "archived" && next.ServerID == prior.ServerID && next.Account == prior.Account && next.Profile == prior.Profile && next.BaseRevision == prior.BaseRevision && next.CommitRevision == prior.CommitRevision && next.CommitDigest == prior.CommitDigest && next.Address == "" && next.User == "" && next.Usage == "" && len(next.OldPublic) == 0 && len(next.NewPublic) == 0 && len(next.HostKeys) == 0 && next.RecoveryPath != "" && len(next.RecoveryPath) <= 4096 && !strings.ContainsAny(next.RecoveryPath, "\x00\r\n\x1b") && validArchiveDigest(next.RecoveryDigest) && next.RecoveryDigest == hex.EncodeToString(before.CipherDigest[:]) && plan.Revision > before.Status.Database.Revision && plan.Digest != ([32]byte{}) && plan.Digest != before.CipherDigest
}

func validArchiveDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}

func (c *Control) remoteRotation(ctx context.Context, revision uint64, rotation ownerpacket.Rotation) (ownerrotation.Plan, error) {
	if c.client == nil || c.manager != nil {
		return ownerrotation.Plan{}, ErrControl
	}
	expected := revision
	snapshot, err := c.client.Execute(ctx, ownerpacket.Command{Operation: "rotation", Revision: &expected, Rotation: &rotation})
	if err != nil {
		return ownerrotation.Plan{}, err
	}
	if snapshot.Rotation == nil || snapshot.Rotation.ID == "" || snapshot.Rotation.PlanID == 0 || snapshot.Rotation.Phase == "" || snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision || snapshot.CipherDigest == ([32]byte{}) {
		return ownerrotation.Plan{}, errors.New("keeper rotation receipt lacks healthy durable metadata")
	}
	if rotation.ID != "" && rotation.Action != "cancel" && (snapshot.Rotation.ID != rotation.ID || snapshot.Rotation.PlanID != rotation.PlanID || snapshot.Rotation.ServerID == "" || snapshot.Rotation.Account == "" || snapshot.Rotation.Profile == "") {
		return ownerrotation.Plan{}, errors.New("keeper rotation receipt did not match the requested journal identity and selected account")
	}
	if rotation.ID != "" && rotation.Action != "cancel" && (rotation.ServerID != "" && snapshot.Rotation.ServerID != rotation.ServerID || rotation.Account != "" && snapshot.Rotation.Account != rotation.Account) {
		return ownerrotation.Plan{}, errors.New("keeper rotation receipt did not match the requested selected account")
	}
	if rotation.ID == "" {
		if snapshot.Rotation.ServerID != rotation.ServerID || snapshot.Rotation.Account != rotation.Account || snapshot.Rotation.Phase != "prepared" || snapshot.Rotation.BaseRevision != revision || snapshot.Status.Database.Revision <= revision {
			return ownerrotation.Plan{}, errors.New("keeper preparation receipt did not match the requested saved selection and advanced revision")
		}
	}
	info := *snapshot.Rotation
	if rotation.Action == "cancel" {
		if info.Phase != "cancelled" || info.ID != rotation.ID || info.PlanID != rotation.PlanID {
			return ownerrotation.Plan{}, errors.New("keeper cancellation receipt did not match the retained journal")
		}
	} else if rotation.Action == "archive" {
		if info.Phase != "archived" || info.ID != rotation.ID || info.PlanID != rotation.PlanID || info.ServerID == "" || info.Account == "" || info.Profile == "" || info.Address != "" || info.User != "" || info.Usage != "" || len(info.OldPublic) != 0 || len(info.NewPublic) != 0 || len(info.HostKeys) != 0 || info.RecoveryPath == "" || len(info.RecoveryPath) > 4096 || strings.ContainsAny(info.RecoveryPath, "\x00\r\n\x1b") || !validArchiveDigest(info.CommitDigest) || !validArchiveDigest(info.RecoveryDigest) || snapshot.Status.Err != nil || snapshot.Status.Busy || snapshot.Status.Pending || snapshot.Status.Database.Err != nil || snapshot.Status.Database.Pending || snapshot.Status.Database.Revision <= revision || snapshot.CipherDigest == ([32]byte{}) {
			return ownerrotation.Plan{}, errors.New("keeper archive receipt did not match healthy retained metadata")
		}
	} else if rotation.ID != "" && (info.ID != rotation.ID || info.PlanID != rotation.PlanID || info.ServerID == "" || info.Account == "" || info.Profile == "") {
		return ownerrotation.Plan{}, errors.New("keeper rotation receipt did not match the requested journal identity")
	}
	return ownerrotation.Plan{Info: info, Revision: snapshot.Status.Database.Revision, Digest: snapshot.CipherDigest}, nil
}
