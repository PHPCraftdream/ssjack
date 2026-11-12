package ownerrotatecli

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func rotationSnapshotReady(snapshot ownerdb.Snapshot) error {
	status := snapshot.Status.Database
	if snapshot.Status.Err != nil || snapshot.Status.Pending || snapshot.Status.Busy || status.Err != nil || status.Pending || status.SavedRevision != status.Revision || snapshot.CipherDigest == ([32]byte{}) {
		return errors.New("key rotation requires a healthy owner coordinator and exact saved ciphertext revision")
	}
	return nil
}

func rotationSelection(snapshot ownerdb.Snapshot, serverName, account string) (string, string, error) {
	var selected *vault.ServerMetadata
	for i := range snapshot.Directory.Servers {
		server := &snapshot.Directory.Servers[i]
		if server.Name == serverName {
			if selected != nil {
				return "", "", errors.New("server selection is ambiguous")
			}
			selected = server
		}
	}
	if selected == nil {
		return "", "", errors.New("selected server does not exist")
	}
	for _, candidate := range selected.Accounts {
		if candidate.Name == account {
			return selected.ID, candidate.Profile, nil
		}
	}
	return "", "", errors.New("selected account does not exist on the selected server")
}

func validateRotationPlan(plan ownerrotation.Plan, serverID, account, profile string, baseRevision uint64) error {
	if plan.Info.ID == "" || plan.Info.PlanID == 0 || plan.Info.ServerID != serverID || plan.Info.Account != account || plan.Info.Profile != profile || plan.Info.Phase != vault.RotationPrepared || plan.Info.BaseRevision != baseRevision || plan.Revision <= baseRevision || plan.Digest == ([32]byte{}) {
		return errors.New("rotation preparation returned incomplete or mismatched metadata")
	}
	return nil
}

func validateRotationTransition(previous, next ownerrotation.Plan, phase string) error {
	if err := validateRotationIdentity(previous.Info, next.Info, phase); err != nil {
		return err
	}
	if next.Revision <= previous.Revision || next.Digest == ([32]byte{}) {
		return errors.New("rotation receipt did not advance the expected durable revision")
	}
	return nil
}

func validateRotationReceipt(previous, next ownerrotation.Plan, phase string, allowSameRevision bool) error {
	if err := validateRotationIdentity(previous.Info, next.Info, phase); err != nil {
		return err
	}
	if allowSameRevision && (next.Revision != previous.Revision || next.Digest != previous.Digest) {
		return errors.New("read-only recovery changed the displayed durable snapshot")
	}
	if !allowSameRevision && (next.Revision <= previous.Revision || next.Digest == previous.Digest) {
		return errors.New("rotation transition did not advance its durable revision and ciphertext")
	}
	if next.Digest == ([32]byte{}) {
		return errors.New("rotation receipt omitted saved ciphertext evidence")
	}
	return nil
}

func validateRotationCancellation(previous, next ownerrotation.Plan) error {
	if next.Info.ID != previous.Info.ID || next.Info.PlanID != previous.Info.PlanID || next.Info.BaseRevision != previous.Info.BaseRevision || next.Info.ServerID != previous.Info.ServerID || next.Info.Account != previous.Info.Account || next.Info.Profile != previous.Info.Profile || next.Info.Phase != vault.RotationCancelled || next.Revision <= previous.Revision || next.Digest == ([32]byte{}) {
		return errors.New("cancellation receipt changed identity or lacks a durable revision")
	}
	return nil
}

func validateRotationIdentity(previous, next vault.RotationInfo, phase string) error {
	if previous.ID != next.ID || previous.PlanID != next.PlanID || previous.BaseRevision != next.BaseRevision || previous.ServerID != next.ServerID || previous.Account != next.Account || previous.Profile != next.Profile || previous.Address != next.Address || previous.User != next.User || previous.Usage != next.Usage || (previous.Phase != "" && previous.Phase != vault.RotationCancelled && next.Phase != phase) || !reflect.DeepEqual(previous.HostKeys, next.HostKeys) || !bytes.Equal(previous.OldPublic, next.OldPublic) || (previous.Phase != vault.RotationCancelled && !bytes.Equal(previous.NewPublic, next.NewPublic)) {
		return errors.New("rotation receipt changed its retained operation or selected SSH scope")
	}
	return nil
}
