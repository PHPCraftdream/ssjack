package ownerrotatecli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func runRotationRecovery(ctx context.Context, control *ownercontrol.Control, command rotationCommand, readSecret func(string) ([]byte, error)) (int, error) {
	snapshot, err := control.RotationSnapshot(ctx)
	if err != nil {
		return 1, err
	}
	if err := rotationSnapshotReady(snapshot); err != nil {
		return 1, err
	}
	if snapshot.Rotation == nil {
		return 1, errors.New("no recoverable key rotation is retained")
	}
	info := *snapshot.Rotation
	serverID, profile, err := rotationSelection(snapshot, command.Server, command.Account)
	if err != nil || info.ServerID != serverID || info.Account != command.Account || info.Profile != profile {
		return 1, errors.New("selected server/account does not match the retained rotation; no action taken")
	}
	if info.Phase == vault.RotationArchived {
		if err := validateArchivedSnapshot(info); err != nil {
			return 1, err
		}
		fmt.Fprintf(os.Stdout, "Archived completed rotation receipt: operation ID %q, plan ID %d, encrypted recovery path %q, ciphertext SHA-256 %s. This retained receipt proves preservation; verification or remote action is not required.\n", info.ID, info.PlanID, info.RecoveryPath, info.RecoveryDigest)
		return 0, nil
	}
	if info.Phase == vault.RotationCancelled {
		return 1, errors.New("no recoverable key rotation is retained")
	}
	if info.Phase == vault.RotationComplete {
		return 1, errors.New("completed rotation requires explicit --archive-completed before another rotation")
	}
	plan := ownerrotation.Plan{Info: info, Revision: snapshot.Status.Database.Revision, Digest: snapshot.CipherDigest}
	display, err := makeRotationDisplay(plan)
	if err != nil {
		return 1, err
	}
	if info.Phase == vault.RotationPrepared && !command.Cancel {
		confirmation := recoveryConfirmation(display)
		printRotationMetadata(os.Stdout, display, confirmation)
		fmt.Fprintln(os.Stdout, "Prepared-plan recovery inspects and claims the encrypted journal without changing its phase. A separate confirmed --recover --cancel-prepared command can cancel it.")
		if err := rotationConsent(readSecret, "Type the exact VERIFY-ONLY confirmation shown above to inspect/claim this prepared plan: ", confirmation); err != nil {
			return 1, err
		}
		claimed, err := control.DecideRotation(ctx, plan.Revision, info.PlanID, info.ID, "recover")
		if err != nil {
			return 1, err
		}
		if err := validateRotationReceipt(plan, claimed, vault.RotationPrepared, true); err != nil {
			return 1, err
		}
		return 1, errors.New("prepared rotation remains retained; no cancellation or remote action was taken")
	}
	if info.Phase != vault.RotationPrepared && command.Cancel {
		return 1, errors.New("--cancel-prepared is allowed only for a prepared no-effect rotation")
	}
	confirmation := recoveryConfirmation(display)
	if command.Cancel {
		confirmation = cancellationConfirmation(display)
	}
	printRotationMetadata(os.Stdout, display, confirmation)
	if command.Cancel {
		fmt.Fprintln(os.Stdout, "Remote effect: none; cancellation is limited to a prepared journal.")
		if err := rotationConsent(readSecret, "Type the exact CANCEL-PREPARED confirmation shown above: ", confirmation); err != nil {
			return 1, err
		}
	} else {
		fmt.Fprintln(os.Stdout, "Recovery mode: verify-only; any uncertain remote add will never be replayed.")
		if err := rotationConsent(readSecret, "Type the exact VERIFY-ONLY confirmation shown above: ", confirmation); err != nil {
			return 1, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	claimed, err := control.DecideRotation(ctx, plan.Revision, info.PlanID, info.ID, "recover")
	if err != nil {
		return 1, err
	}
	if err := validateRotationReceipt(plan, claimed, info.Phase, true); err != nil {
		return 1, err
	}
	if command.Cancel {
		cancelled, err := control.DecideRotation(ctx, claimed.Revision, info.PlanID, info.ID, "cancel")
		if err != nil {
			return 1, err
		}
		if cancelled.Info.ID == "" || cancelled.Info.Phase != vault.RotationCancelled {
			cancelSnapshot, snapshotErr := control.RotationSnapshot(ctx)
			if snapshotErr != nil || cancelSnapshot.Rotation == nil || cancelSnapshot.Rotation.Phase != vault.RotationCancelled || cancelSnapshot.Status.Database.SavedRevision != cancelSnapshot.Status.Database.Revision || cancelSnapshot.CipherDigest == ([32]byte{}) {
				return 1, errors.New("cancelled rotation lacks a readable durable receipt")
			}
			cancelled = ownerrotation.Plan{Info: *cancelSnapshot.Rotation, Revision: cancelSnapshot.Status.Database.Revision, Digest: cancelSnapshot.CipherDigest}
		}
		if err := validateRotationCancellation(claimed, cancelled); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stdout, "Prepared encrypted intent cancelled; no remote effect was attempted. Re-run rotate-key separately to prepare again.")
		return 0, nil
	}
	return continueRotationRecovery(ctx, control, claimed)
}

func continueRotationRecovery(ctx context.Context, control *ownercontrol.Control, plan ownerrotation.Plan) (int, error) {
	switch plan.Info.Phase {
	case vault.RotationAttempting, vault.RotationUnknown, vault.RotationAdded:
		verified, err := control.DecideRotation(ctx, plan.Revision, plan.Info.PlanID, plan.Info.ID, "verify")
		if err != nil {
			return 1, errors.New("verify-only recovery could not verify the new login; do not repeat key addition; inspect server state and retry recovery only after review")
		}
		if err := validateRotationTransition(plan, verified, vault.RotationVerified); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stdout, "New-key login verification: successful; remote addition was not replayed.")
		plan = verified
	case vault.RotationVerified, vault.RotationCommitted:
	case vault.RotationArchived:
		return 1, errors.New("rotation journal is archived; no key verification or remote action is required")
	case vault.RotationPrepared:
		return 1, errors.New("prepared rotation requires explicit --cancel-prepared; no remote action taken")
	default:
		return 1, errors.New("retained rotation phase is not eligible for verify-only recovery")
	}
	if plan.Info.Phase != vault.RotationComplete {
		complete, err := control.DecideRotation(ctx, plan.Revision, plan.Info.PlanID, plan.Info.ID, "commit")
		if err != nil {
			return 1, errors.New("verified rotation remains encrypted and pending commit; rerun owner rotate-key --recover")
		}
		if err := validateRotationTransition(plan, complete, vault.RotationComplete); err != nil {
			return 1, err
		}
		plan = complete
	}
	fmt.Fprintf(os.Stdout, "Encrypted selected-account commit: durable at revision %d. Old remote key remains authorized. This does not prove adoption by every consumer; active sessions/jobs were not restarted or terminated.\n", plan.Revision)
	return 0, nil
}
