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

// runRotationRetire removes the old public key from the remote account after a
// completed rotation. It is a separate, exact-confirmed invocation and changes
// no local state; it must run before --archive-completed discards the old key.
func runRotationRetire(ctx context.Context, control *ownercontrol.Control, command rotationCommand, readSecret func(string) ([]byte, error)) (int, error) {
	snapshot, err := control.RotationSnapshot(ctx)
	if err != nil {
		return 1, err
	}
	if err := rotationSnapshotReady(snapshot); err != nil {
		return 1, err
	}
	if snapshot.Rotation == nil || snapshot.Rotation.Phase != vault.RotationComplete {
		return 1, errors.New("--retire-old requires the selected retained rotation to be complete and not yet archived")
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
	confirmation := retireConfirmation(display)
	printRotationMetadata(os.Stdout, display, confirmation)
	fmt.Fprintln(os.Stdout, "This removes only the old client public key shown above from the selected account's authorized_keys on the server, over a session authenticated by the new key. Every other client that still uses the old key loses access. The previous file is kept beside it as authorized_keys.ssjack-retired. A retry is safe. Run this before --archive-completed, which discards the old public key from the journal.")
	if err := rotationConsent(readSecret, "Type the exact RETIRE-OLD-KEY confirmation shown above: ", confirmation); err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	retired, err := control.DecideRotation(ctx, plan.Revision, info.PlanID, info.ID, "retire")
	if err != nil {
		return 1, err
	}
	if err := validateRotationReceipt(plan, retired, vault.RotationComplete, true); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stdout, "Old remote key retired: %s is no longer authorized for the selected account (or already was not). The new key authenticated this session. Local journal state is unchanged.\n", display.OldFingerprint)
	return 0, nil
}
