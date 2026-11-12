package ownerrotatecli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func runRotationArchive(ctx context.Context, control *ownercontrol.Control, command rotationCommand, readSecret func(string) ([]byte, error)) (int, error) {
	snapshot, err := control.RotationSnapshot(ctx)
	if err != nil {
		return 1, err
	}
	if err := rotationSnapshotReady(snapshot); err != nil {
		return 1, err
	}
	if snapshot.Rotation == nil || snapshot.Rotation.Phase != vault.RotationComplete {
		return 1, errors.New("--archive-completed requires the selected retained rotation to be complete")
	}
	info := *snapshot.Rotation
	serverID, profile, err := rotationSelection(snapshot, command.Server, command.Account)
	if err != nil || info.ServerID != serverID || info.Account != command.Account || info.Profile != profile {
		return 1, errors.New("selected server/account does not match the completed rotation; no action taken")
	}
	plan := ownerrotation.Plan{Info: info, Revision: snapshot.Status.Database.Revision, Digest: snapshot.CipherDigest}
	display, err := makeRotationDisplay(plan)
	if err != nil {
		return 1, err
	}
	confirmation := archiveConfirmation(display)
	printRotationMetadata(os.Stdout, display, confirmation)
	fmt.Fprintln(os.Stdout, "This preserves the exact encrypted completed database as a recovery file. No key retirement or remote action is requested. Run a separate rotate-key command after archive confirmation to prepare another rotation.")
	if err := rotationConsent(readSecret, "Type the exact ARCHIVE confirmation shown above: ", confirmation); err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	archived, err := control.DecideRotation(ctx, plan.Revision, info.PlanID, info.ID, "archive")
	if err != nil {
		return 1, err
	}
	if err := validateRotationArchiveReceipt(plan, archived); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stdout, "Completed rotation archived at revision %d. Encrypted recovery path: %q; ciphertext SHA-256: %s. The journal is preserved as an archive receipt; no key was retired. A later rotation requires a separate invocation.\n", archived.Revision, archived.Info.RecoveryPath, archived.Info.RecoveryDigest)
	return 0, nil
}

func validateRotationArchiveReceipt(previous, next ownerrotation.Plan) error {
	before, after := previous.Info, next.Info
	if before.ID == "" || before.PlanID == 0 || before.Phase != vault.RotationComplete || !validRotationDigest(before.CommitDigest) || previous.Digest == ([32]byte{}) {
		return errors.New("completed rotation lacks valid archive source evidence")
	}
	if after.ID != before.ID || after.PlanID != before.PlanID || after.BaseRevision != before.BaseRevision || after.ServerID != before.ServerID || after.Account != before.Account || after.Profile != before.Profile || after.Phase != vault.RotationArchived || after.CommitRevision != before.CommitRevision || after.CommitDigest != before.CommitDigest {
		return errors.New("archive receipt changed the completed rotation identity or commit evidence")
	}
	if after.Address != "" || after.User != "" || after.Usage != "" || len(after.HostKeys) != 0 || len(after.OldPublic) != 0 || len(after.NewPublic) != 0 {
		return errors.New("archive receipt retained unexpected key material or changed the selected SSH scope")
	}
	if after.RecoveryPath == "" || len(after.RecoveryPath) > 4096 || strings.ContainsAny(after.RecoveryPath, "\x00\r\n\x1b") || !validRotationDigest(after.RecoveryDigest) || after.RecoveryDigest != hex.EncodeToString(previous.Digest[:]) {
		return errors.New("archive receipt omitted valid encrypted recovery path or digest metadata")
	}
	if next.Revision <= previous.Revision || next.Digest == ([32]byte{}) || next.Digest == previous.Digest {
		return errors.New("archive receipt did not advance the exact saved revision")
	}
	return nil
}

func validateArchivedSnapshot(info vault.RotationInfo) error {
	if info.ID == "" || info.PlanID == 0 || info.ServerID == "" || info.Account == "" || info.Profile == "" || info.Phase != vault.RotationArchived || !validRotationDigest(info.CommitDigest) || info.RecoveryPath == "" || strings.ContainsAny(info.RecoveryPath, "\x00\r\n\x1b") || !validRotationDigest(info.RecoveryDigest) || len(info.Address)+len(info.User)+len(info.Usage)+len(info.OldPublic)+len(info.NewPublic)+len(info.HostKeys) != 0 {
		return errors.New("archived rotation snapshot lacks valid identity or preservation proof")
	}
	return nil
}

func validRotationDigest(value string) bool {
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
